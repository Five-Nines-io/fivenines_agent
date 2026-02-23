# Security

This document describes the security posture of the fivenines-agent: what it protects against,
how it is hardened, and what known design trade-offs exist.

## Threat Model

The agent runs on monitored hosts and sends metrics to the fivenines API. The primary threat
scenarios considered are:

1. **Compromised API backend** — an attacker who controls the API server (supply-chain
   compromise, credential theft, rogue insider) attempts to use the agent as a pivot to
   attack the monitored host or its services.
2. **Network interception** — a network-level attacker attempts to intercept or modify
   traffic between the agent and the API.
3. **Local unprivileged user** — a non-root user on the monitored host attempts to read
   agent credentials or escalate privileges via the agent.

---

## Transport Security

All communication with `api.fivenines.io` is over TLS 1.2+.

- **Certificate validation** is always on. The agent uses `ssl.create_default_context()` with
  the `certifi` CA bundle and validates the server hostname (`synchronizer.py`). A
  network MITM requires a CA compromise or a rogue certificate — passive interception is
  not sufficient.
- **IPv4/IPv6 fallback** is handled manually via a custom DNS resolver, which resolves the
  API hostname, connects to the resolved IP, and wraps the socket with TLS before handing
  it to `http.client`. This avoids relying on the system resolver for security-critical
  connections.
- **Payload compression** — all outbound payloads are gzip-compressed. The Content-Encoding
  header is set accordingly; the server is expected to decompress before processing.

---

## API Response Validation (`config_schema.py`)

Every configuration dict received from the API is passed through `validate_config()` in
`fivenines_agent/config_schema.py` before being stored or used. This is a whitelist-based
sanitization layer: only known keys are retained, and each is independently validated.

**Why this matters:** several metric collectors accept connection parameters (host, port,
password, URL, URI) from the configuration dict and pass them directly to third-party
services. Without validation, a compromised API backend could inject parameters that
redirect those collectors to attacker-controlled infrastructure.

### Enforced constraints

| Collector | Parameters validated | Constraint |
|-----------|---------------------|------------|
| `nginx` | `status_page_url` | Loopback only (`127.0.0.1`, `::1`, `localhost`) |
| `caddy` | `admin_api_url` | Loopback only |
| `postgresql` | `host` | Loopback only |
| `postgresql` | `password` | CRLF characters stripped |
| `proxmox` | `host` | Loopback only |
| `proxmox` | `verify_ssl` | Always forced to `True`; any `False` from API is rejected and logged |
| `docker` | `socket_url` | Must be `None` or a `unix://` path; TCP/SSH URLs rejected |
| `qemu` | `uri` | Allowlisted to `qemu:///system` or `qemu:///session` exactly |
| `redis` | `password` | CRLF characters stripped |
| `redis` | `port` | Must be integer 1–65535 |
| `ports` | `monitored_ports` | Each entry validated as integer 1–65535 |

**Collection interval** is clamped to 30–3600 seconds, preventing the server from
scheduling excessively frequent collection. Request timeout, retry count, and retry
interval are similarly range-bounded.

If a collector's configuration fails validation, that collector is disabled for the current
cycle (its config key is set to `None`). The agent continues collecting all other metrics.
Unknown keys in the API response are silently dropped.

---

## Credential Storage

The per-host authentication token is stored in the `TOKEN` file under the agent's
configuration directory (default `/etc/fivenines_agent/TOKEN` for system installs,
`~/.local/fivenines/config/TOKEN` for user installs).

- **File permissions** are enforced at `0600` (owner read/write only). The install scripts
  set this on initial creation, and `_swap_token()` in `synchronizer.py` uses `os.open()`
  with `O_WRONLY | O_CREAT | O_TRUNC` and mode `0o600` when writing a new token. This
  bypasses the process umask and ensures the file is always owner-only regardless of how
  it is created.
- The token is held in memory and used as a Bearer token in the `Authorization` header of
  every request. It is never logged.

---

## Redis Collector

The Redis collector communicates with the local Redis instance using the **RESP
(REdis Serialization Protocol)** binary-safe encoding. Each command argument is
length-prefixed (`$<n>\r\n<data>\r\n`), so Redis reads exactly `n` bytes as a single opaque
value. A password containing `\r\n` sequences cannot inject additional Redis commands
regardless of its content — this is a structural property of the protocol.

This is a defense-in-depth measure layered on top of the CRLF stripping already
performed by `config_schema.py` at configuration ingestion.

The Redis connection always targets `localhost` — the host is not configurable from
the API.

---

## Known Design Considerations

Two architectural decisions create residual risk that is documented here for transparency.

### Token rotation is unconditional

When the API response contains a `"token"` key, the agent replaces its authentication
credential with the supplied value. This is the intended enrollment flow, but it also means
a compromised backend can silently rotate all agent tokens to attacker-controlled values.

Mitigations currently in place: token swaps are logged at `info` level and written
atomically to disk with `0600` permissions. The TLS layer requires a valid certificate to
reach the API, raising the bar for an attacker to trigger a rotation.

Planned hardening: rate-limiting token swaps to enrollment-only, and optionally
HMAC-binding the new token to the previous one.

### Host context is included in every payload

Each metric payload includes the agent's user context: username, UID, group memberships,
and the path to the configuration directory. This data helps the backend understand
permission scope and display accurate capability information.

A compromised backend that receives this data learns the agent's privilege level, group
memberships (which may indicate escalation paths such as `docker` or `sudo`), and the
exact path to the token file.

Planned hardening: replace raw group names with derived capability flags, and transmit
user context only at enrollment rather than with every payload.

---

## Reporting Vulnerabilities

Please report security issues by email to
[sebastien@fivenines.io](mailto:sebastien@fivenines.io). Do not open a public GitHub
issue for security vulnerabilities.
