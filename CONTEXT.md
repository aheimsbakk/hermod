# Hermod: Development Context

## Current State

All source modules and tests are implemented and passing (208/208, ~71% coverage).
The application is fully functional for its core transfer flows, including ICE-based
NAT traversal with STUN candidate gathering and a three-layer hybrid key exchange
(SPAKE2 + ephemeral X25519 + ML-KEM-768).

Auto-detect send/receive UX (v0.6.5):
- `--file/-f` and `--text/-t` removed from `hermod send`; replaced by a single
  positional `[INPUT]` argument with auto-detection:
  - Existing path → sent as file.
  - Non-path string → sent as text.
  - `-` or piped stdin → read `sys.stdin.buffer`; UTF-8-decodable → text, else binary file.
- `SenderSession` gains `raw_bytes: bytes | None` parameter for binary stdin payloads.
  `_send_raw_bytes` sends them as `kind="file"` with name `"stdin"`, chunked via
  `CHUNK_SIZE`, using the same SecretStream encryption path.
- `hermod receive --destination/-d` is now optional (was `Path(".")`):
  - Omitted + stdout is a terminal → text printed, file saved with original name.
  - Omitted + stdout redirected/piped → entire payload streamed to `sys.stdout.buffer`.
  - Explicit → always save/print regardless of stdout state.
- `ReceiverSession` gains `output_sink: IO[bytes] | None` parameter.
  `_receive_file` delegates to `_stream_file_to_sink` when sink is set (inline
  SHA-256 verification, no disk write). `_receive_text` writes raw bytes to sink
  and returns `TransferResult` without `text_content`.

CLI UX improvements (v0.6.4):
- `--p2p-port/-P` renamed to `--listen/-l` on `send` and `receive`; accepts
  `host:port`, `[ipv6]:port`, or bare `:port` (empty host → `"0.0.0.0"`).
- `_AliasedGroup(TyperGroup)` collapses aliases into one help line (`send or tx`,
  `receive or rx`) by overriding `list_commands` and `get_command`.
- `@app.callback(invoke_without_command=True)` with `ctx.invoked_subcommand is None`
  check prints usage when called with no subcommand (including flag-only invocations
  like `hermod --verbosity error`).
- `ctx.default_map` set in the group callback injects config-sourced defaults into
  all subcommand `--help` outputs (effective value, not `(dynamic)`).
- `--verbosity` CLI default changed to `"error"` (suppressed by default); was `"info"`.
- `SenderSession` and `ReceiverSession` both accept `p2p_host: str = "0.0.0.0"` (new)
  in addition to existing `p2p_port: int = 0`; passed to `PeerListener(host=, port=)`.

Configurable P2P listen port added (v0.6.3):
- `p2p_port: int = 0` field added to `HermodConfig` (default 0 = OS-assigned).
- `HERMOD_P2P_PORT` env var and `p2p_port:` YAML key both supported.
- `SenderSession` and `ReceiverSession` both accept `p2p_port: int = 0`; passed
  straight to `PeerListener(host="0.0.0.0", port=self.p2p_port)`.
- `hermod send --listen/-l <host:port>` and `hermod receive --listen/-l <host:port>`
  CLI flags added (formerly `--p2p-port/-P`).
- CLI flag takes precedence over config value (`p2p_port or cfg.p2p_port`).
- Use case: whichever peer has a forwarded port sets `--listen :<N>` so the srflx
  candidate (public IP + fixed port) is reachable by the other side through NAT.

ICE split-connection fix is complete (v0.6.2):
- **Root cause**: `socket_utils.get_local_addresses()` returned both the primary LAN IP
  *and* loopback (`127.0.0.1`), causing the sender to fire two simultaneous probes to
  the same `0.0.0.0` listener.  Both probes succeeded in the same asyncio event-loop
  tick; `asyncio.wait(FIRST_COMPLETED)` returned both in `done` (a `set`); non-deterministic
  set iteration made each side pick a *different* TCP connection.
- **Fix 1** (`socket_utils.py`): loopback is now appended only when no other address is
  found (offline / pure-container / CI environments).  This limits each peer to one
  candidate per listener, eliminating simultaneous-success races.
- **Fix 2** (`ice.py`): the `for t in done:` loop is replaced by `for t in all_tasks: if t
  not in done: continue` — tasks are visited in insertion order (`accept_task` first, then
  probes sorted by priority).  When multiple tasks complete in the same tick, this
  deterministic ordering ensures both sides agree on the same TCP connection.
- **Probe-delay strategy** (v0.6.1): sender fires probes immediately (controlling role);
  receiver delays probes by 100 ms (`probe_delay=0.1` in `ice_connect`) so the sender's
  probe reaches the receiver's listener first.

Config consolidation is complete (v0.6.0):
- `trusted_servers` (formerly `~/.hermod/trust_store.json`) now lives inside `~/.config/hermod/config.yaml`.
- `host` + `port` fields replaced by a single `listen: str` field (`host:port` / `[ipv6]:port`).
- `parse_listen` / `format_listen` helpers in `core/config.py` handle IPv4 and IPv6.
- `hermod serve` uses `--listen/-l`; `hermod trust` auto-saves the server URL as the default.
- `HERMOD_LISTEN` env var added; `HERMOD_HOST` / `HERMOD_PORT` retained for backward compatibility.

Appendix B security hardening is complete:
- **§1**: HMAC-SHA256 MAC binding on PQ_INIT / PQ_RESPONSE frames (MitM prevention).
- **§2**: XChaCha20-Poly1305 (192-bit nonce) replaces AES-256-GCM for ad-hoc AEAD;
  `derive_resume_key` added for safe session resumption.
- **§3**: `crypto_secretstream` (auto key-ratcheting + TAG_FINAL truncation proof)
  replaces single-key AES-GCM for payload encryption.

## Module Map

| Module | File(s) | Status |
|---|---|---|
| Crypto: AEAD | `src/hermod/crypto/aead.py` | ✅ Complete (XChaCha20-Poly1305, 192-bit nonce) |
| Crypto: MAC | `src/hermod/crypto/mac.py` | ✅ Complete (HMAC-SHA256 compute/verify) |
| Crypto: Stream | `src/hermod/crypto/stream.py` | ✅ Complete (SecretStreamPush/Pull, TAG_FINAL) |
| Crypto: KDF | `src/hermod/crypto/kdf.py` | ✅ Complete (+ derive_resume_key) |
| Crypto: ECDH | `src/hermod/crypto/ecdh.py` | ✅ Complete (EphemeralX25519) |
| Crypto: KEM | `src/hermod/crypto/kem.py` | ✅ Complete (kyber-py ML-KEM-768 active) |
| Crypto: PAKE | `src/hermod/crypto/pake.py` | ✅ Complete |
| Network: Wire | `src/hermod/network/wire.py` | ✅ Complete |
| Network: P2P | `src/hermod/network/p2p.py` | ✅ Complete (SO_REUSEPORT, backlog=5) |
| Network: Socket Utils | `src/hermod/network/socket_utils.py` | ✅ Complete |
| Network: STUN | `src/hermod/network/stun.py` | ✅ Complete (RFC 5389 client) |
| Network: ICE | `src/hermod/network/ice.py` | ✅ Complete (gather + ice_connect) |
| Server: DB | `src/hermod/server/db.py` | ✅ Complete |
| Server: Rate Limiting | `src/hermod/server/rate_limit.py` | ✅ Complete |
| Server: TLS | `src/hermod/server/tls.py` | ✅ Complete |
| Server: Signaling | `src/hermod/server/signaling.py` | ✅ Complete |
| Core: Config | `src/hermod/core/config.py` | ✅ Complete (`listen` field, `parse_listen`/`format_listen`, `trusted_servers`, `p2p_port`) |
| Core: Trust Store | `src/hermod/core/trust.py` | ✅ Complete (persists to `config.yaml` via `trusted_servers`) |
| Core: Streaming | `src/hermod/core/streaming.py` | ✅ Complete |
| Core: Transfer Code | `src/hermod/core/transfer_code.py` | ✅ Complete |
| Core: Session | `src/hermod/core/session.py` | ✅ Complete (ICE, stun_timeout, p2p_port params; `raw_bytes` send path; `output_sink` receive path) |
| CLI: UI | `src/hermod/cli/ui.py` | ✅ Complete |
| CLI: Main | `src/hermod/cli/main.py` | ✅ Complete (argparse; auto-detect send INPUT arg; stdout-streaming receive; `output_sink` wired to `ReceiverSession`) |

## Key Architectural Decisions

### KEM Backend Priority
`get_kem()` in `crypto/kem.py` selects the best available backend at import time:

1. **`MLKEM768`** — liboqs native C library (fastest; requires compiled shared lib)
2. **`MLKEM768KyberPy`** — pure-Python `kyber-py` package (always installable, no build required; **currently active**)
3. **`X25519KEMFallback`** — classical DH; **NOT post-quantum**; only if neither PQ library is installed

`kyber-py>=1.2.0` is a core dependency in `pyproject.toml`.
`liboqs-python` is retained as an optional extra (`[pq]`) for environments with a compiled liboqs build.

Key/ciphertext sizes for ML-KEM-768 (both backends):
- Encapsulation key (public key): 1184 bytes
- Ciphertext: 1088 bytes
- Shared secret: 32 bytes

### Transfer Code Format
`{channel_id}-{word1}-{word2}-{word3}` where:
- `channel_id` = 5-digit numeric string (server-assigned via REGISTER)
- words = 3 random words from the embedded 256-word list (PAKE passphrase)

Example: `47392-rapid-blue-fox`

### Transfer Code Display Timing
`SenderSession` has a `code_callback: Callable[[str], None] | None` attribute.
The CLI sets this before calling `run()` so the transfer code is printed as soon
as the channel is registered, before the progress bar starts.

### Signaling Protocol (MessagePack)
Client → Server: `REGISTER`, `JOIN`, `RELAY`, `ABORT`
Server → Client: `REGISTERED`, `JOINED_OK`, `PEER_CONNECTED`, `RELAY`, `PEER_DISCONNECTED`, `ERROR`

### Wire Frame (P2P)
15-byte fixed prefix: `b"HD"` (magic) + `0x01` (version) + 4-byte hdr_len (uint32 BE)
+ 8-byte payload_len (uint64 BE), followed by MessagePack header + raw encrypted payload.

### Session Flow (8 steps, symmetric ICE)
1. Sender connects to signaling server, sends REGISTER
2. Server returns REGISTERED with `channel_id`; sender builds transfer code
3. Receiver joins with JOIN + code; PAKE (SPAKE2) exchange via RELAY messages
4. Both sides bind a `PeerListener`, gather ICE candidates (host + optional srflx via STUN), encrypt their candidate list with `k_classical[:32]`, and exchange via RELAY
5. Both sides call `ice_connect(listener, peer_candidates)` which races inbound TCP accept vs outbound probes; first connection wins
6. **Sender** sends `PQ_INIT`: `{ pk_kem, salt, pk_ecdh, mac }` (ML-KEM-768 public key + random salt + X25519 public key + HMAC-SHA256 over `pk_kem ‖ pk_ecdh` keyed by `k_classical`)  
   **Receiver** sends `PQ_RESPONSE`: `{ ct, pk_ecdh, mac }` (ML-KEM-768 ciphertext + X25519 public key + HMAC-SHA256 over `ct ‖ pk_ecdh` keyed by `k_classical`)  
   Each side MUST verify the `mac` field before using any received key material. Both compute `k_pq` (ML-KEM decapsulate/encapsulate) and `k_ecdh` (X25519 DH) from the same two frames
7. Both derive `session_key = HKDF(k_classical ‖ k_ecdh ‖ k_pq, salt, "hermod-session-v2")`
8. META (carries `stream_header: bytes` — 24-byte SecretStream init header) → ACK → CHUNK frames → EOF → ACK; receiver verifies SHA-256 and TAG_FINAL truncation guard

### ICE Candidate Exchange Wire Format
Encrypted payload: `{"candidates": [{"type": "host"|"srflx", "ip": "...", "port": N}, ...]}`
Legacy read fallback: `{"ip": "...", "port": N}` → single host candidate.

### STUN Client (`network/stun.py`)
- Implements RFC 5389 Binding Request/Response in pure Python (stdlib only)
- Queries `DEFAULT_STUN_SERVERS` concurrently; returns first valid XOR-MAPPED-ADDRESS
- `get_srflx_candidate(local_port, stun_timeout)` — returns `(ip, port) | None`
- `stun_timeout=0.0` disables STUN entirely (set in all tests for speed)

### ICE Module (`network/ice.py`)
- `IceCandidate(ip, port, candidate_type)` — `priority=100` for host, `200` for srflx
- `gather_candidates(listener, stun_timeout)` — host from `get_local_addresses()` + optional srflx
- `ice_connect(listener, peer_candidates, probe_timeout, total_timeout, probe_delay)` — asyncio task race
  - `probe_delay` (default `0.0`): sleep before each outbound probe; set to `0.1` on the
    ICE *controlled* role (receiver) so the sender's probe arrives first.
  - Done-task iteration is in **`all_tasks` insertion order** (accept first, then probes by
    priority) — not raw set order — to guarantee deterministic connection selection.

### Candidate Gathering (`network/socket_utils.py`)
- `get_local_addresses()` uses a UDP probe to `8.8.8.8` to find the default-route IP.
- Loopback (`127.0.0.1`) is appended **only when no other address is found** (offline /
  pure-container environments).  This prevents two candidates pointing to the same
  `0.0.0.0` listener, which would cause two simultaneous successful probes and a
  non-deterministic split-connection.

### Default Port and Listen Address
Changed from `8765` → `8786`. The `host` and `port` fields on `HermodConfig` were replaced by a
single `listen: str` field (default `"0.0.0.0:8786"`). `HermodConfig.host` and `HermodConfig.port`
are now computed `@property` values derived from `listen` via `parse_listen`.

`parse_listen(s)` handles:
- `"host:port"` → `(host, port)`
- `"[ipv6host]:port"` → `(ipv6host, port)` (brackets stripped for use with `socket.connect`)
- bare `"host"` or `"[ipv6]"` → uses `DEFAULT_PORT = 8786`

`format_listen(host, port)` emits `"[host]:port"` for IPv6 addresses (RFC 3986), `"host:port"` otherwise.

### CLI Aliases and Help Display
`hermod send` → `hermod tx` (same function); `hermod receive` → `hermod rx` (same function).
The `_AliasedGroup(TyperGroup)` class overrides `list_commands` to merge alias names into a
single entry (`"send or tx"`, `"receive or rx"`) and `get_command` to resolve these composite
names back to the real command via a shallow `copy.copy` proxy that carries the display name.
Aliases are registered via `app.command(name="tx")(transmit)` / `app.command(name="rx")(receive)`.
`_ALIAS_MAP = {"tx": "send", "rx": "receive"}` drives the suppression logic.
`ctx.default_map` entries exist for both canonical names AND their aliases so that
`hermod send --help`, `hermod tx --help`, etc. all show the effective configured defaults.

### CLI Framework: stdlib argparse (replaces Typer + Click)
`typer` and `click` removed from `pyproject.toml`. `src/hermod/cli/main.py` uses
`argparse.ArgumentParser` with `add_subparsers`. Aliases (`tx`, `rx`) are registered
via the `aliases=` parameter on `add_parser`. Entry point changed from `app` to `main`.
`typer.Exit` → `sys.exit(N)`. `ctx.default_map` replaced by loading config inside
`_build_parser()` and baking effective defaults directly into `default=` on each argument.

### websockets v16 API
`from websockets.asyncio.server import serve` (not `websockets.server`).
`from websockets.asyncio.client import connect`.
Server handler signature: `async def handler(ws: ServerConnection)`.
`ws.remote_address` is `(host, port)` tuple.
`srv.serve_forever()` blocks; `srv.close()` + `await srv.wait_closed()` for teardown.

### MAC Binding (Appendix B §1)
`compute_mac(key, data)` in `crypto/mac.py` computes HMAC-SHA256 using `cryptography.hazmat.primitives.hmac`.
`verify_mac(key, data, tag)` uses `hmac.compare_digest` for constant-time comparison.

- `PQ_INIT` MAC covers: `pk_kem ‖ pk_ecdh` (keyed by `k_classical[:32]`)
- `PQ_RESPONSE` MAC covers: `ct ‖ pk_ecdh` (keyed by `k_classical[:32]`)
- Receiver raises `ValueError("MAC verification failed …")` on mismatch; session aborts.

### SecretStream Payload Encryption (Appendix B §3)
`SecretStreamPush` / `SecretStreamPull` in `crypto/stream.py` wrap
`nacl.bindings.crypto_secretstream_xchacha20poly1305_*`.

- `push(plaintext, last=False)` — encrypts one chunk; uses `TAG_FINAL` (3) on the last chunk.
- `pull(ciphertext) → (plaintext, is_final: bool)` — decrypts and returns the tag boolean.
- Receiver raises `ValueError("Stream truncated …")` if EOF frame arrives before a `TAG_FINAL` chunk.
- The 24-byte stream header is carried in the `stream_header` field of the META wire frame.

### Resume Sub-Key Derivation (Appendix B §2)
```python
resume_key = derive_resume_key(session_key, resume_counter)
# HKDF-SHA256(ikm=session_key, salt=b"", info=b"hermod-resume-v1:<counter>", len=32)
```
`resume_counter` must be a non-negative integer. The original `session_key` is never passed
directly to a `SecretStream` for a resumed segment; only the derived sub-key is used.

### Ad-hoc AEAD (Appendix B §2)
`AEADCipher` in `crypto/aead.py` uses `nacl.bindings.crypto_aead_xchacha20poly1305_ietf_*`.
Nonce is 24 bytes (192-bit), generated fresh with `os.urandom` per call.
Wire format: `nonce (24 B) ‖ ciphertext+tag`.

### pynacl Dependency
`pynacl>=1.5.0` added to `pyproject.toml` `[project.dependencies]`.
Used by: `crypto/aead.py`, `crypto/stream.py`.
`cryptography` library is retained for HKDF, HMAC, X25519, and X.509.

### Ephemeral X25519 ECDH (`crypto/ecdh.py`)
`EphemeralX25519` wraps `cryptography`'s X25519 with a one-shot guard:
- `public_key_bytes()` → 32-byte raw public key
- `exchange(peer_pk_bytes)` → 32-byte shared secret; raises `RuntimeError` if called twice

The ECDH public keys are piggybacked on the existing `PQ_INIT` / `PQ_RESPONSE` frames
as the `pk_ecdh` field — no additional round-trip required.

### Key Derivation (v2)
```
session_key = HKDF-SHA256(
    ikm  = k_classical ‖ k_ecdh ‖ k_pq,
    salt = random 32 bytes (from PQ_INIT frame),
    info = b"hermod-session-v2",
    len  = 32
)
```
Security property: session key is secure as long as **any one** of the three
input secrets is secure. An attacker must break all three independently.

### Signaling DB (aiosqlite)
In-memory (`:memory:`) for tests. WAL mode for production. TTL sweep removes channels
older than `--ttl` seconds. Per-channel limits: `MAX_MESSAGES_PER_CHANNEL=8`,
`MAX_MESSAGE_SIZE=4096` bytes (anti-spam §8).

### YAML Serialisation for PEM Strings
`save_config` uses a custom `_HermodDumper` (subclass of `yaml.SafeDumper`) with a
`str` representer that writes any string containing `\n` as a YAML literal block
scalar (`style="|"`). This prevents PyYAML's default quoted-scalar style from
inserting a blank line between every base64 line of the PEM certificate/key, keeping
`config.yaml` compact and human-readable. Loading is unaffected (`yaml.safe_load`
parses literal blocks correctly). Two tests in `TestSaveConfig` enforce this:
`test_yaml_no_consecutive_blank_lines` and `test_yaml_pem_round_trips`.

### Configuration Hierarchy
CLI Flags > Env Vars (`HERMOD_SERVER`, `HERMOD_LISTEN`, `HERMOD_DB_PATH`,
`HERMOD_DEST_DIR`, `HERMOD_P2P_PORT`; deprecated: `HERMOD_PORT`, `HERMOD_HOST`) > `~/.config/hermod/config.yaml` > Application Defaults.

`config.yaml` is the **single source of truth** for all settings. It stores:
- Runtime settings (`server`, `listen`, `db_path`, `dest_dir`, `ttl`, `verbosity`, `p2p_port`)
- TLS certificate and private key (`tls_cert`, `tls_key` — PEM strings as `|` block scalars)
- Pinned server certificates (`trusted_servers` — replaces the former `~/.hermod/trust_store.json`)

`TrustStore` reads and writes the `trusted_servers` mapping directly via `load_config`/`save_config`.
`hermod trust <host:port>` fetches the server certificate, pins it, and also saves the server URL
as the `server:` default so subsequent `tx`/`rx` calls work without `--server`.

The file is written with `chmod 0o600` (owner read/write only) because it contains TLS private key material.

### Trust Store Migration
The `~/.hermod/trust_store.json` file is no longer created or read. Any existing pinned
certificates must be re-pinned with `hermod trust <host:port>`.

`TrustStore.__init__` accepts `config_path: Path | None = None` (replaces the former `path` argument).

### File Integrity
Sender pre-computes SHA-256 of the plaintext file and includes it in the META frame.
Receiver writes to `{dest}.hermod_part` and calls `PartFileWriter.finalise(hash)`
which verifies and renames atomically.

## Known Limitations / Future Work

- Transfer resumption (`resume_offset`) is scaffolded in `ChunkedFileReader` /
  `PartFileWriter` but the session layer does not yet negotiate resume offsets
- CLI tests (`cli/main.py`, `cli/ui.py`) not covered by the test suite (0% coverage)
  — would require mocking `asyncio.run`, `sys.stdin`, Rich console
- TLS auto-generation (`server/tls.py`) is untested (36% coverage)
- `socket_utils.py` `get_local_addresses()` platform-specific paths untested (47%)
- Rate limiter edge cases (per-channel, LRU eviction) partially tested (85%)
- `kyber-py` is pure Python and slower than a native C KEM; for high-throughput
  production use, consider building liboqs and installing `liboqs-python` (optional `pq` extra)

## Test Infrastructure

- `pytest-asyncio` with `asyncio_mode = "auto"` — all `async def test_*` run automatically
- `conftest.py` provides: `in_memory_db` (async fixture), `small_file`, `medium_file`
- Server tests spin up real in-process WebSocket servers on port 0
- Session tests run full sender + receiver over a real in-process signaling server
