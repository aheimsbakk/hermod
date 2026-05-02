# Hermod: Development Context

## Current State

All source modules and tests are implemented and passing (129/129, ~70% coverage).
The application is fully functional for its core transfer flows, including ICE-based
NAT traversal with STUN candidate gathering.

## Module Map

| Module | File(s) | Status |
|---|---|---|
| Crypto: AEAD | `src/hermod/crypto/aead.py` | ✅ Complete |
| Crypto: KDF | `src/hermod/crypto/kdf.py` | ✅ Complete |
| Crypto: KEM | `src/hermod/crypto/kem.py` | ✅ Complete (X25519 fallback active) |
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
| Core: Config | `src/hermod/core/config.py` | ✅ Complete (default port 4430) |
| Core: Trust Store | `src/hermod/core/trust.py` | ✅ Complete |
| Core: Streaming | `src/hermod/core/streaming.py` | ✅ Complete |
| Core: Transfer Code | `src/hermod/core/transfer_code.py` | ✅ Complete |
| Core: Session | `src/hermod/core/session.py` | ✅ Complete (ICE, stun_timeout param) |
| CLI: UI | `src/hermod/cli/ui.py` | ✅ Complete |
| CLI: Main | `src/hermod/cli/main.py` | ✅ Complete (send/receive aliases) |

## Key Architectural Decisions

### KEM Fallback
`liboqs-python` is installed but the native C library is unavailable in this environment.
`get_kem()` in `crypto/kem.py` detects this at import time and returns `X25519KEMFallback`.
The fallback is clearly logged as non-PQ. Production deployments must install a full
liboqs build to enable `MLKEM768`.

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
6. Sender sends PQ_INIT (public key + salt); receiver returns PQ_RESPONSE (ciphertext)
7. Both derive `session_key = HKDF(k_classical ‖ k_pq, salt, "hermod-session-v1")`
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
Changed from `8765` → `4430` in `core/config.py` (both `HermodConfig` dataclass and `load_config` defaults dict).

### CLI Aliases
`hermod send` → `hermod tx` (same function); `hermod receive` → `hermod rx` (same function).
Registered via `app.command(name="send")(transmit)` / `app.command(name="receive")(receive)` after the command definitions.

### websockets v16 API
`from websockets.asyncio.server import serve` (not `websockets.server`).
`from websockets.asyncio.client import connect`.
Server handler signature: `async def handler(ws: ServerConnection)`.
`ws.remote_address` is `(host, port)` tuple.
`srv.serve_forever()` blocks; `srv.close()` + `await srv.wait_closed()` for teardown.

### HKDF Key Derivation
- Session key: `HKDF(SHA256, 32, salt=random_32, info=b"hermod-session-v1").derive(k_classical ‖ k_pq)`
- SAS: `HKDF(SHA256, 3, salt=None, info=b"hermod-sas-v1").derive(session_key)` → 6 hex chars

### Signaling DB (aiosqlite)
In-memory (`:memory:`) for tests. WAL mode for production. TTL sweep removes channels
older than `--ttl` seconds. Per-channel limits: `MAX_MESSAGES_PER_CHANNEL=8`,
`MAX_MESSAGE_SIZE=4096` bytes (anti-spam §8).

### Configuration Hierarchy
CLI Flags > Env Vars (`HERMOD_SERVER`, `HERMOD_PORT`, `HERMOD_HOST`, `HERMOD_DB_PATH`,
`HERMOD_DEST_DIR`) > `~/.config/hermod/config.yaml` > Application Defaults.

### File Integrity
Sender pre-computes SHA-256 of the plaintext file and includes it in the META frame.
Receiver writes to `{dest}.hermod_part` and calls `PartFileWriter.finalise(hash)`
which verifies and renames atomically.

## Known Limitations / Future Work

- `liboqs` C library not available in this environment → X25519 fallback only
- Transfer resumption (`resume_offset`) is scaffolded in `ChunkedFileReader` /
  `PartFileWriter` but the session layer does not yet negotiate resume offsets
- CLI tests (`cli/main.py`, `cli/ui.py`) not covered by the test suite (0% coverage)
  — would require mocking `asyncio.run`, `sys.stdin`, Rich console
- TLS auto-generation (`server/tls.py`) is untested (36% coverage)
- `socket_utils.py` `get_local_addresses()` platform-specific paths untested (47%)
- Rate limiter edge cases (per-channel, LRU eviction) partially tested (85%)

## Test Infrastructure

- `pytest-asyncio` with `asyncio_mode = "auto"` — all `async def test_*` run automatically
- `conftest.py` provides: `in_memory_db` (async fixture), `small_file`, `medium_file`
- Server tests spin up real in-process WebSocket servers on port 0
- Session tests run full sender + receiver over a real in-process signaling server
