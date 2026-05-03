# Hermod: Development Context

## Current State

All source modules and tests are implemented and passing (150/150, ~70% coverage).
The application is fully functional for its core transfer flows, including ICE-based
NAT traversal with STUN candidate gathering and a three-layer hybrid key exchange
(SPAKE2 + ephemeral X25519 + ML-KEM-768).

## Module Map

| Module | File(s) | Status |
|---|---|---|
| Crypto: AEAD | `src/hermod/crypto/aead.py` | ✅ Complete |
| Crypto: KDF | `src/hermod/crypto/kdf.py` | ✅ Complete |
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
| Core: Config | `src/hermod/core/config.py` | ✅ Complete (default port 8786) |
| Core: Trust Store | `src/hermod/core/trust.py` | ✅ Complete |
| Core: Streaming | `src/hermod/core/streaming.py` | ✅ Complete |
| Core: Transfer Code | `src/hermod/core/transfer_code.py` | ✅ Complete |
| Core: Session | `src/hermod/core/session.py` | ✅ Complete (ICE, stun_timeout param) |
| CLI: UI | `src/hermod/cli/ui.py` | ✅ Complete |
| CLI: Main | `src/hermod/cli/main.py` | ✅ Complete (send/receive aliases) |

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
6. **Sender** sends `PQ_INIT`: `{ pk_kem, salt, pk_ecdh }` (ML-KEM-768 public key + random salt + X25519 public key)  
   **Receiver** sends `PQ_RESPONSE`: `{ ct, pk_ecdh }` (ML-KEM-768 ciphertext + X25519 public key)  
   Both compute `k_pq` (ML-KEM decapsulate/encapsulate) and `k_ecdh` (X25519 DH) from the same two frames
7. Both derive `session_key = HKDF(k_classical ‖ k_ecdh ‖ k_pq, salt, "hermod-session-v2")`
8. META → ACK → CHUNK frames → EOF → ACK; receiver verifies SHA-256

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
- `ice_connect(listener, peer_candidates, probe_timeout, total_timeout)` — asyncio task race

### Default Port
Changed from `8765` → `8786` in `core/config.py` (both `HermodConfig` dataclass and `load_config` defaults dict), `server/signaling.py` (`start()` and `run_server()` signatures), and `cli/main.py` (`serve` command default).

### CLI Aliases
`hermod send` → `hermod tx` (same function); `hermod receive` → `hermod rx` (same function).
Registered via `app.command(name="send")(transmit)` / `app.command(name="receive")(receive)` after the command definitions.

### websockets v16 API
`from websockets.asyncio.server import serve` (not `websockets.server`).
`from websockets.asyncio.client import connect`.
Server handler signature: `async def handler(ws: ServerConnection)`.
`ws.remote_address` is `(host, port)` tuple.
`srv.serve_forever()` blocks; `srv.close()` + `await srv.wait_closed()` for teardown.

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
CLI Flags > Env Vars (`HERMOD_SERVER`, `HERMOD_PORT`, `HERMOD_HOST`, `HERMOD_DB_PATH`,
`HERMOD_DEST_DIR`) > `~/.config/hermod/config.yaml` > Application Defaults.

`config.yaml` is the **single source of truth** for all settings. The TLS certificate
and private key are stored as PEM strings under the `tls_cert` and `tls_key` keys —
no separate certificate files are written to disk. On first `hermod serve`, the cert
is auto-generated and saved into config.

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
