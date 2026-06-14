# Hermod — Architecture Blueprint

## Component Map

```
cmd/hermod/main.go          — binary entry, cobra root
internal/cli/               — serve, trust, tx, rx commands
internal/cli/cancel.go      — QUIC cancellation error code, peer-cancel detection helper
internal/cli/tty_unix.go    — /dev/tty open helper (Unix)
internal/cli/tty_windows.go — CONIN$ open helper (Windows)
internal/cli/verbosity.go   — --verbose flag parsing, slog/stdlog wiring, log helpers
internal/config/            — YAML config load/save, TLS helpers, cert generation (1-year self-signed ECDSA P-256, IsCA=false), cert expiry warning helper; cert auto-renewal 14 days before expiry in serve command
internal/crypto/            — CPace PAKE (P-256), AES-256-GCM, SAS, identicon, transfer codes
internal/server/            — MemoryStore SignalingStore, WebSocket relay (rejects browser cross-origin connections), HMAC-SHA256 IP-hashing rate limiter with 10-min cleanup ticker, per-channel blob/CPace-failure limits, single-receiver enforcement, TTL GC, /cert endpoint serving DER certificate, UDP reflection endpoint for CGNAT address discovery (two-phase HMAC cookie handshake; no legacy 0x00 probe)
internal/network/           — UDP mux (SO_REUSEADDR/REUSEPORT), hole punching (session-unique nonce derived from CPace key), QUIC transport (DialQUIC, ListenQUIC), signaling client (WithContext goroutine lifecycle managed via done channel), external UDP address discovery via server reflection (CGNAT; cookie protocol only)
pkg/transfer/               — payload metadata, stream classification, SHA-256 integrity
README.md                   — user-facing documentation
docs/protocol.md            — wire protocol specification
docs/api.md                 — internal package API reference
docs/worklogs/              — session worklogs
scripts/                    — bump-version.sh, build-release.sh, check-coverage.sh, extract-changelog-entry.sh, validate-changelog.sh
.github/workflows/          — release.yml (GitHub Actions: cross-build + publish on tag push)
VERSION                     — current version (1.0.3)
```

## Logging

Controlled by `--verbose none|error|warning|info|debug` (default: `none`).
Implemented with `log/slog` via helpers in `verbosity.go`: `logDebug`, `logInfo`, `logWarn`, `logError`.
All output goes to stderr. No log files are written.

| Level   | What it covers |
|---------|---------------|
| error   | Unrecoverable failures — integrity check failed, server exited with error |
| warning | Non-fatal problems — rate-limited request, missing peer, ack not received |
| info    | State changes — server ready, channel allocated/joined, PAKE complete, hole punch success, QUIC connected, transfer complete |
| debug   | Every internal step — config load, cert gen, UDP bind, each relay message, stream open/close, GC start |

Rules:
- `debug` traces every step in all three modes (serve, tx, rx).
- `info` covers the same events a web server access log would surface: connections, requests, results.
- Log messages use plain language: active voice, specific names, no filler.
- Sensitive material (keys, passwords, raw payloads) is never logged at any level.


## Key Data Models

### Config (config.yaml)
```
server_url: wss://localhost:4376   # updated when trust is run or -s is used in tx/rx
listen: :0
tls_configuration:
  prefer_curves: [X25519MLKEM768]  # post-quantum hybrid only; no classical fallback
  cipher_suites: [TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]
server_cert_pem: ""          # serve: auto-generated self-signed PEM; auto-renewed 14 days before expiry with same key
server_key_pem: ""           # serve: auto-generated private key PEM; unchanged on renewal (SPKI pin survives)
trusted_servers:             # map[url]sha256fingerprint
  wss://example.com:4376: "aabb..."
```

### SignalingStore interface
- AllocateChannel(id uint16, ttl time.Duration, remoteAddr string) error — `remoteAddr` enables per-IP cap enforcement; pass `""` to skip
- ChannelExists(id uint16) bool
- StoreBlob(id uint16, sender bool, blob []byte) error
- FetchBlob(id uint16, sender bool) ([]byte, error)
- RecordFailure(id uint16) (int, error)
- DeleteChannel(id uint16) error
- PurgeExpired() error
- Close() error

Implementation: `MemoryStore` (default, in-process). Optional per-IP channel cap (`maxChannelsPerIP`, default 100, configurable via `--max-channels-per-ip` on `hermod serve`). Tracks channel ownership by IP prefix (IPv4 /32, IPv6 /64) and rejects allocations when the limit is hit. Owner count is decremented on `DeleteChannel` or `PurgeExpired`.

### Metadata (JSON, 4-byte length-prefixed, QUIC stream 0)
```json
{"kind":"file","name":"doc.pdf","size":1234,"sha256":""}
```
`sha256` is always empty in the leading metadata — the actual hash is computed during transfer and sent in the trailing hash stream after the payload (M-07).  
`kind`: `"file"` | `"text"` | `"stream"`

### EndpointBundle (JSON, AES-256-GCM encrypted with HybridBlobKey + channel ID as AAD, relayed via signaling)
```json
{"local_endpoints_v4":["192.168.1.5:51234"],"local_endpoints_v6":["[fe80::1]:51234"],"public_endpoint_v4":"1.2.3.4:51234","public_endpoint_v6":"[2001:db8::1]:51234","public_key_fingerprint":"hex","require_verify":false}
```
`public_key_fingerprint` is the SHA-256 hash of the Subject Public Key Info (SPKI) of the peer's ephemeral TLS certificate. SPKI pinning is used rather than certificate DER pinning so that certificate renewal with the same key pair does not break client trust. The server's auto-renewal reuses the existing private key, keeping the SPKI fingerprint unchanged — clients never need to re-pin after automatic renewal.
The channel ID (2-byte big-endian) is used as AES-GCM Additional Authenticated Data to bind the ciphertext to the session.
The encryption key is a **HybridBlobKey** derived from three pillars:
- `kClassical` — CPace (P-256) shared secret
- `ssX25519` — X25519 ECDH shared secret
- `ssMLKEM` — ML-KEM-768 (post-quantum) shared secret

Final key: `SHA-256(kClassical || ssX25519 || ssMLKEM)`

## Interfaces / Key Functions

- `SignalingStore` — storage backend (MemoryStore)
- `net.PacketConn` — UDP socket abstraction for mux
- `*quic.Conn` / `*quic.Listener` — QUIC transport (quic-go); `DialQUIC` returns a `*quic.Conn`, `ListenQUIC` returns a `*quic.Listener`
- `*packetMux` — demultiplexes probe packets and QUIC packets on a single UDP socket
- `HolePunch` — single-phase NAT hole punching to a list of candidates
- `HolePunchDual` — two-phase hole punch (IPv6 first, IPv4 fallback) with 5s/10s timeouts
- `LocalEndpoints(localPort, IPFamily)` — returns local v4/v6 addresses split by family
- `IPFamily` — `IPFamilyAny` (default), `IPFamilyV4` (`-4`), `IPFamilyV6` (`-6`)

## Protocol Flow

1. Sender allocates channel on signaling server → gets channel ID + public IP
2. Receiver joins channel (server validates channel exists) → sender receives `ready`
3. External UDP address discovery: both peers send a cookie-mode probe to the
   signaling server's UDP reflection port. Server responds with HMAC cookie;
   peer echoes cookie to prove address ownership, receives external UDP address.
   Used as `PublicEndpointV4`/`V6` in the bundle (critical for CGNAT where UDP
   port differs from WebSocket TCP port). Falls back to server-reported WebSocket
   IP + local port if the server does not support reflection or discovery times out.
4. Hybrid handshake over signaling relay:
   a. CPace public messages exchanged (P-256, password = transfer code words)
   b. X25519 public keys + ML-KEM-768 encapsulation keys exchanged in same blobs
   c. Sender encapsulates ML-KEM → ciphertext sent alongside encrypted bundle
5. Endpoint bundles encrypted with HybridBlobKey (AES-256-GCM, channel ID as AAD). HybridBlobKey = SHA-256(kClassical || ssX25519 || ssMLKEM)
6. UDP hole punch to peer candidates (two-phase: IPv6 preferred, IPv4 fallback; 5s/10s timeouts; `-4`/`-6` flags enforce single family)
7. QUIC connection (TLS 1.3, sender dials / receiver listens, ephemeral ECDSA P-256 certs, SPKI-pinned mutual TLS — public key fingerprint survives cert renewal with the same key)
8. Stream 0 (SAS coordination, only when verify active): 1-byte confirm/reject exchange; Stream 1 (or 0 without verify): 4-byte-prefixed JSON metadata (sha256 = ""); Stream 2 (or 1 without verify): raw payload bytes streamed while sender computes SHA-256 in parallel; Stream 3 (or 2 without verify): 4-byte-prefixed trailing hash (hex SHA-256 computed during send)
9. Receiver computes SHA-256 in parallel while receiving payload, then verifies against trailing hash stream
10. Receiver sends ack stream; sender waits before closing QUIC connection
