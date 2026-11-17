"""A minimal MySQL wire-protocol server, in process, for tests/test_mysql.py.

It lets the tests drive the REAL PyMySQL through the mysql collector: the
connection options, the authentication refusals, the byte decoding and the
error mapping all run against actual packets, with no MySQL installed.

Not a MySQL: it speaks just enough of the classic protocol -- HandshakeV10,
HandshakeResponse41, AuthSwitchRequest, caching_sha2_password's full
authentication over RSA, OK/ERR/EOF packets, COM_QUERY text result sets,
LOAD DATA LOCAL requests and COM_QUIT -- and every reply is scripted by the
test. It records what the client sent (user, database, connection
attributes, every authentication reply, every statement) for the tests to
assert on. One connection at a time, one per collection.
"""

import os
import socket
import struct
import threading
import time

from pymysql.constants import CLIENT, FIELD_TYPE

SERVER_CAPABILITIES = (
    CLIENT.LONG_PASSWORD
    | CLIENT.LONG_FLAG
    | CLIENT.CONNECT_WITH_DB
    | CLIENT.PROTOCOL_41
    | CLIENT.TRANSACTIONS
    | CLIENT.SECURE_CONNECTION
    | CLIENT.MULTI_RESULTS
    | CLIENT.PLUGIN_AUTH
    | CLIENT.CONNECT_ATTRS
    | CLIENT.PLUGIN_AUTH_LENENC_CLIENT_DATA
)

SALT = b"abcdefghijklmnopqrst"  # 20 bytes, sent as 8 + 12

COM_QUIT = 0x01
COM_QUERY = 0x03


def rows(columns, values):
    """A scripted result set: column names, then rows of bytes/str/None."""
    return ("rows", list(columns), [tuple(row) for row in values])


def error(code, message, sqlstate=b"HY000"):
    """A scripted ERR packet."""
    return ("error", code, message, sqlstate)


def hang(seconds):
    """Answer nothing for `seconds`, then close the connection."""
    return ("hang", seconds)


def drop():
    """Close the connection without answering."""
    return ("drop",)


def load_local(filename):
    """Ask the client to send a local file (LOAD DATA LOCAL INFILE)."""
    return ("load_local", filename)


def _lenenc_int(n):
    if n < 251:
        return bytes([n])
    if n < 1 << 16:
        return b"\xfc" + struct.pack("<H", n)
    if n < 1 << 24:
        return b"\xfd" + struct.pack("<I", n)[:3]
    return b"\xfe" + struct.pack("<Q", n)


def _read_lenenc_int(data, i):
    first = data[i]
    if first < 251:
        return first, i + 1
    raw, end = _take(data, i + 1, {0xFC: 2, 0xFD: 3, 0xFE: 8}[first])
    return int.from_bytes(raw, "little"), end


def _take(data, i, n):
    """(n bytes of data from i, the index after them)."""
    end = i + n
    return data[i:end], end


def _lenenc_str(value):
    return _lenenc_int(len(value)) + value


def _as_bytes(value):
    return value if isinstance(value, bytes) else str(value).encode("utf-8")


class _Closed(Exception):
    """The client closed the connection."""


class FakeMySQL:
    """Context manager: a scripted server on 127.0.0.1 or a unix socket.

    plugin: the default authentication plugin named in the greeting.
    switch_to: (plugin, data) for an AuthSwitchRequest after the client's
        first reply, or None.
    full_auth_key: a cryptography RSA private key: answer caching_sha2's fast
        path with "perform full authentication", serve the key's public half
        and decrypt the password the client sends with it.
    auth_error: an error(...) answering the client's first reply.
    greeting_error: an error(...) sent INSTEAD of the greeting.
    greeting_hang: seconds to wait before the greeting.
    results: {sql: rows(...)/error(...)/hang(...)/drop()/load_local(...)};
        a statement not listed is a syntax error (1064). SET statements
        answer OK.
    unix_path: listen on this AF_UNIX path instead of TCP.
    tls_broken: offer TLS in the greeting, then answer a client's TLS request
        with bytes that are no TLS record, so its handshake fails (an old
        server whose TLS versions the client refuses reads the same).
    """

    def __init__(
        self,
        plugin="mysql_native_password",
        switch_to=None,
        full_auth_key=None,
        auth_error=None,
        greeting_error=None,
        greeting_hang=0,
        results=None,
        unix_path=None,
        version="8.4.10-fake",
        tls_broken=False,
    ):
        self.plugin = plugin
        self.switch_to = switch_to
        self.full_auth_key = full_auth_key
        self.auth_error = auth_error
        self.greeting_error = greeting_error
        self.greeting_hang = greeting_hang
        self.results = dict(results or {})
        self.unix_path = unix_path
        self.version = version
        self.tls_broken = tls_broken
        self.tls_requests = 0
        # What the client sent, per connection (the last one's).
        self.connections = 0
        self.user = None
        self.database = None
        self.client_plugin = None
        self.auth_response = None
        self.switch_response = None
        self.rsa_password = None
        self.connect_attrs = {}
        self.queries = []
        self.quit = False
        self.local_file_data = None
        self._listener = None
        self._thread = None
        self._stop = None

    # -- lifecycle -------------------------------------------------------

    def __enter__(self):
        if self.unix_path:
            self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener.bind(self.unix_path)
        else:
            self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        # accept() is not woken by close() from another thread on Linux:
        # poll, so __exit__ stops the server at once.
        self._listener.settimeout(0.05)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(5)
        self._listener.close()
        if self.unix_path and os.path.exists(self.unix_path):
            os.unlink(self.unix_path)

    @property
    def port(self):
        return self._listener.getsockname()[1]

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:  # listener closed: the test is over
                return
            conn.settimeout(None)
            self.connections += 1
            with conn:
                try:
                    self._session(conn)
                except (_Closed, OSError):
                    pass

    # -- packets ---------------------------------------------------------

    @staticmethod
    def _recv_exact(conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise _Closed()
            data += chunk
        return data

    def _read(self, conn):
        header = self._recv_exact(conn, 4)
        length = int.from_bytes(header[:3], "little")
        return header[3], self._recv_exact(conn, length)

    @staticmethod
    def _write(conn, seq, payload):
        conn.sendall(len(payload).to_bytes(3, "little") + bytes([seq]) + payload)

    @staticmethod
    def _ok():
        return b"\x00\x00\x00" + struct.pack("<HH", 2, 0)

    @staticmethod
    def _eof():
        return b"\xfe" + struct.pack("<HH", 0, 2)

    @staticmethod
    def _err(code, message, sqlstate):
        return b"\xff" + struct.pack("<H", code) + b"#" + sqlstate + _as_bytes(message)

    # -- session ---------------------------------------------------------

    def _greeting(self):
        capabilities = SERVER_CAPABILITIES | (CLIENT.SSL if self.tls_broken else 0)
        return (
            b"\x0a"
            + self.version.encode()
            + b"\x00"
            + struct.pack("<I", 7)
            + SALT[:8]
            + b"\x00"
            + struct.pack("<H", capabilities & 0xFFFF)
            + bytes([255])  # utf8mb4_0900_ai_ci
            + struct.pack("<H", 2)
            + struct.pack("<H", capabilities >> 16)
            + bytes([len(SALT) + 1])
            + b"\x00" * 10
            + SALT[8:]
            + b"\x00"
            + self.plugin.encode()
            + b"\x00"
        )

    def _parse_response(self, data):
        flags = struct.unpack("<I", data[:4])[0]
        i = 32
        end = data.index(b"\x00", i)
        self.user = data[i:end].decode()
        i = end + 1
        length, i = _read_lenenc_int(data, i)
        self.auth_response, i = _take(data, i, length)
        if flags & CLIENT.CONNECT_WITH_DB:
            end = data.index(b"\x00", i)
            self.database = data[i:end].decode()
            i = end + 1
        end = data.index(b"\x00", i)
        self.client_plugin = data[i:end].decode()
        i = end + 1
        self.connect_attrs = {}
        total, i = _read_lenenc_int(data, i)
        stop = i + total
        while i < stop:
            key_len, i = _read_lenenc_int(data, i)
            key, i = _take(data, i, key_len)
            value_len, i = _read_lenenc_int(data, i)
            value, i = _take(data, i, value_len)
            self.connect_attrs[key.decode()] = value.decode()

    def _authenticate(self, conn):
        """Run the authentication exchange, ending with OK or an error."""
        seq = 2
        if self.auth_error:
            _, code, message, sqlstate = self.auth_error
            self._write(conn, seq, self._err(code, message, sqlstate))
            raise _Closed()
        if self.full_auth_key is not None:
            self._full_auth(conn)
            return
        if self.switch_to:
            plugin, data = self.switch_to
            self._write(conn, seq, b"\xfe" + plugin.encode() + b"\x00" + data)
            _, self.switch_response = self._read(conn)
            seq += 2
        self._write(conn, seq, self._ok())

    def _full_auth(self, conn):
        """caching_sha2_password: fast auth fails, the password comes RSA-encrypted."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        self._write(conn, 2, b"\x01\x04")  # perform full authentication
        seq, request = self._read(conn)
        assert request == b"\x02", request  # the client asks for the key
        public = self.full_auth_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._write(conn, seq + 1, b"\x01" + public)
        seq, encrypted = self._read(conn)
        xored = self.full_auth_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        plain = bytes(b ^ SALT[i % len(SALT)] for i, b in enumerate(xored))
        self.rsa_password = plain.rstrip(b"\x00")
        self._write(conn, seq + 1, self._ok())

    def _session(self, conn):
        self.queries = []
        self.quit = False
        if self.greeting_hang:
            time.sleep(self.greeting_hang)
            return
        if self.greeting_error:
            _, code, message, sqlstate = self.greeting_error
            self._write(conn, 0, self._err(code, message, sqlstate))
            return
        self._write(conn, 0, self._greeting())
        _, response = self._read(conn)
        if len(response) == 32 and struct.unpack("<I", response[:4])[0] & CLIENT.SSL:
            # An SSL request: the client starts its TLS handshake next.
            self.tls_requests += 1
            conn.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")
            # Close cleanly: never with the ClientHello unread, which would
            # reset the connection (Windows then drops the bytes above and the
            # client sees a reset, not a failed TLS handshake).
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(5)
            while conn.recv(4096):
                pass
            return
        self._parse_response(response)
        self._authenticate(conn)
        while True:
            _, command = self._read(conn)
            if command[0] == COM_QUIT:
                self.quit = True
                return
            sql = command[1:].decode()
            self.queries.append(sql)
            if sql.startswith("SET "):
                self._write(conn, 1, self._ok())
                continue
            reply = self.results.get(
                sql, error(1064, "You have an error in your SQL syntax", b"42000")
            )
            if not self._answer(conn, reply):
                return

    def _answer(self, conn, reply):
        """Send one scripted reply; False when the connection must end."""
        kind = reply[0]
        if kind == "error":
            _, code, message, sqlstate = reply
            self._write(conn, 1, self._err(code, message, sqlstate))
            return True
        if kind == "hang":
            time.sleep(reply[1])
            return False
        if kind == "drop":
            return False
        if kind == "load_local":
            self._write(conn, 1, b"\xfb" + reply[1].encode())
            # A client that honours it sends the file then an empty packet.
            _, self.local_file_data = self._read(conn)
            return False
        _, columns, values = reply
        seq = 1
        self._write(conn, seq, _lenenc_int(len(columns)))
        for name in columns:
            seq += 1
            self._write(conn, seq, self._column(name))
        seq += 1
        self._write(conn, seq, self._eof())
        for row in values:
            seq += 1
            self._write(
                conn,
                seq,
                b"".join(
                    b"\xfb" if value is None else _lenenc_str(_as_bytes(value))
                    for value in row
                ),
            )
        self._write(conn, seq + 1, self._eof())
        return True

    @staticmethod
    def _column(name):
        name = name.encode()
        return (
            _lenenc_str(b"def")
            + _lenenc_str(b"")
            + _lenenc_str(b"")
            + _lenenc_str(b"")
            + _lenenc_str(name)
            + _lenenc_str(name)
            + b"\x0c"
            + struct.pack("<HIBHB", 255, 1024, FIELD_TYPE.VAR_STRING, 0, 0)
            + b"\x00\x00"
        )
