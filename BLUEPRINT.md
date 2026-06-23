# Hermod — Architecture Blueprint

## System Goal

Hermod is a secure, peer-to-peer file and text transfer tool. Two parties exchange data directly over an encrypted QUIC connection without any payload passing through a central server. A lightweight signaling server coordinates the rendezvous — channel allocation, key exchange relay, NAT hole-punching — but actual payload flows over a direct peer-to-peer UDP/QUIC connection.

## Security Properties

- End-to-end encryption via QUIC + TLS 1.3 with mutual SPKI pinning
- Password-authenticated key exchange (CPace PAKE, RFC 9496) — no pre-shared secret beyond the human-readable transfer code
- Post-quantum security by default: hybrid key exchange combining X25519 ECDH + ML-KEM-768 (FIPS 203)
- NAT traversal via UDP hole punching
- Optional out-of-band SAS (Short Authentication String) verification for active MitM detection
- Payload integrity via SHA-256 trailing hash verification
- Channel binding: endpoint bundles use channel ID as AES-GCM additional authenticated data

---

## Logical Components

### 1. CLI Application Layer
Orchestrates the four user-facing operations: send (`tx`), receive (`rx`), run signaling server (`serve`), and pin server certificate (`trust`). Manages flags, config loading, and high-level flow coordination.

Flags:
- Global: `--verbose` (verbosity), `--quiet` (suppress status), `--ipv4` / `--ipv6` (IP family restriction), `--version`
- `tx`: `--server`, `--words` (transfer code length, default 3), `--listen` (UDP bind), `--verify` (SAS enforcement)
- `rx`: `--server`, `--destination` (output path), `--listen` (UDP bind), `--verify` (SAS enforcement)
- `serve`: `--listen`, `--ttl` (channel TTL and WebSocket idle timeout), `--rate-limit`, `--rate-burst`, `--max-blobs-per-channel`, `--max-cpace-failures`, `--max-channels-per-ip`
- `trust`: `--fingerprint` (expected SPKI hash)

### 2. Configuration Manager
Loads, saves, and validates YAML configuration. Manages TLS certificate generation (self-signed ECDSA P-256, non-CA, 1-year validity), certificate auto-renewal (same key, new cert — SPKI fingerprint survives), and server trust pinning (TOFU or explicit fingerprint). Certificate expiry warnings at 90/30/7 day thresholds.

### 3. Cryptographic Engine
Provides all cryptographic primitives:

- **CPace PAKE** (P-256, SSWU hash-to-curve, RFC 9496 / RFC 9380) — password-authenticated key exchange using transfer code words as the shared password. Role-bound domain separation via transcript ordering.
- **Hybrid KEM** — X25519 ECDH + ML-KEM-768 key generation, encapsulation, and decapsulation. Split combiner: `SHA-256(kClassical || ssX25519 || ssMLKEM)`.
- **AES-256-GCM** — symmetric encryption for endpoint bundles, with channel ID as AAD.
- **SAS** — Short Authentication String generation (6 words from EFF Short Wordlist 1) and identicon (8x8 mirrored ASCII art). Session-bound via TLS ExportKeyingMaterial with channel ID context.
- **Transfer codes** — human-readable code generation and parsing (word list from EFF).

### 4. Signaling Client
WebSocket client that connects to the signaling server. Handles channel allocation, joining, blob relay (encrypted key exchange messages), and server TLS fingerprint retrieval. Certificate-pinned connection with configurable IP family restriction. Supports context cancellation (SIGINT/SIGTERM) via deadline injection on the WebSocket connection. Enforces a maximum message size of 64 KiB.

### 5. Signaling Server
WebSocket-based relay server that brokers the rendezvous between sender and receiver. Responsibilities:

- Channel allocation with configurable TTL
- Blob relay (encrypted key material passes through without being readable)
- Per-channel blob count cap (default 10) and CPace failure cap (default 3)
- Per-IP channel allocation limits (IPv4 /32, IPv6 /64)
- CORS protection: rejects browser-origin WebSocket connections
- Background goroutine for expired channel garbage collection (60 s interval)
- Background goroutine for stale rate limiter bucket cleanup (10 min interval)
- Certificate endpoint (`/cert`) for client pinning
- WebSocket idle timeout derived from TTL flag (default 600 s)
- HTTP read/write/idle timeouts (10 s / 30 s / 120 s)

### 6. Signaling Store
Storage backend for channels, blobs, and failure tracking. Current implementation is an in-memory store with TTL-based expiry. Defined as an interface to allow alternative backends. Channels track expiry time, failure count, two blob slots (sender/receiver), and owner IP prefix.

### 7. UDP Reflection Server
A separate UDP socket bound on the same port as the TLS listener. Provides external address discovery for peers behind CGNAT. Uses a two-phase HMAC cookie handshake to prevent reflection amplification attacks.

- HMAC secret key is 32 bytes, generated at startup and rotated every UTC calendar day. Previous key accepted during a 5-minute grace period.
- Rate limited independently (10 req/s, burst 5) on cookie request phase only.
- If UDP bind fails, the reflector is disabled and clients fall back to server-reported WebSocket IP + local port.

### 8. UDP Network Layer
Manages a single UDP socket shared between hole-punch probes and QUIC traffic via a demultiplexer (packet first-byte routing). Provides:

- UDP socket binding with `SO_REUSEADDR` / `SO_REUSEPORT` on Unix. Receive/send buffer set to 2 MiB.
- Local endpoint enumeration (IPv4 and IPv6, split by family, excluding loopback).
- External UDP address discovery via two-phase HMAC cookie-based server reflection (supports CGNAT).
- Hole punching: single-phase and dual-phase (IPv6 preferred with 5 s timeout, IPv4 fallback with remaining context timeout up to 10 s total).
- Probe/ack packets use a session-specific nonce derived from the hybrid blob key (64 bits of entropy per packet).

### 9. QUIC Transport Layer
Establishes peer-to-peer QUIC connections (TLS 1.3) with mutual SPKI-pinned authentication. Ephemeral ECDSA P-256 certificates generated per-session (valid 2 hours). Supports dial (sender) and listen (receiver) modes. Configurable IP family restriction.

- ALPN: `hermod-p2p`
- Idle timeout: 30 seconds
- Keep-alive period: 5 seconds
- SPKI pinning via `VerifyPeerCertificate` callback (constant-time comparison)

### 10. Transfer Module
Public types for payload classification and integrity verification. Handles metadata serialization, SHA-256 hashing (file, bytes, stream), safe destination path construction (path-traversal prevention, dedup suffix), temp file handling (atomic rename after verification), and integrity verification.

### 11. Rate Limiter
Token-bucket rate limiter keyed by IP prefix. Bucket keys are HMAC-SHA256(daily salt, IP prefix) — raw IPs are never stored. Daily salt rotation with stale bucket cleanup (10 min interval). Used to protect signaling server endpoints (cert, WebSocket upgrades, join attempts) and the UDP reflection endpoint.

---

## Key Data Models

### Config (YAML)

```
server_url: wss://localhost:4376
tls_configuration:
  prefer_curves: [X25519MLKEM768]
  cipher_suites: [TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]
server_cert_pem: ""                     # auto-generated on serve
server_key_pem: ""                      # auto-generated on serve
trusted_servers:                         # map[serverURL]sha256fingerprint
  wss://example.com:4376: "aabb..."
```

Note: `listen` is not stored in the config file; it is passed as a CLI flag or environment variable (`HERMOD_LISTEN`).

### Channel (Signaling Store)

Each channel has:
- Channel ID (16-bit unsigned integer)
- TTL / expiry timestamp
- Two blob slots (index 0 = receiver, index 1 = sender)
- Failure counter
- Owner IP prefix (for per-IP cap enforcement)

### Transfer Metadata (JSON)

```
{"kind":"file","name":"doc.pdf","size":1234,"sha256":""}
```

- `kind`: `"file"` | `"text"` | `"stream"`
- `name`: original filename (only for `kind = "file"`)
- `sha256` is always empty in the leading metadata — the actual hash is sent separately after the payload

### Endpoint Bundle (JSON, AES-256-GCM encrypted)

```
{
  "local_endpoints_v4": ["192.168.1.5:51234", "10.0.0.2:51234"],
  "local_endpoints_v6": ["[fe80::1]:51234"],
  "public_endpoint_v4": "1.2.3.4:51234",
  "public_endpoint_v6": "[2001:db8::1]:51234",
  "public_key_fingerprint": "hex",
  "require_verify": false
}
```

Encrypted with a hybrid key derived from three pillars:
- CPace (P-256) shared secret
- X25519 ECDH shared secret
- ML-KEM-768 shared secret

Final key: `SHA-256(kClassical || ssX25519 || ssMLKEM)`

Channel ID is used as AES-GCM Additional Authenticated Data to bind ciphertext to the session.

### Signaling Message (JSON, WebSocket relay)

```
{"type":"allocate|join|handshake|blob|ready|ok|error","channel_id":1234,"payload":"<base64>","error":""}
```

- `payload` is a raw JSON byte array (base64-encoded over the wire)
- `handshake` type is defined but not used in the current flow

### Hybrid KEM Handshake Blobs

Fixed-length binary blobs exchanged over signaling relay. The first blob also carries the CPace public message.

1. **Sender handshake blob** (97 bytes): 65-byte CPace point + 32-byte X25519 public key
2. **Receiver handshake blob** (1281 bytes): 65-byte CPace point + 32-byte X25519 public key + 1184-byte ML-KEM-768 encapsulation key
3. **Sender bundle blob** (1088 + N bytes): 1088-byte ML-KEM-768 ciphertext + AES-256-GCM encrypted endpoint bundle (variable length)
4. **Receiver bundle blob** (N bytes): AES-256-GCM encrypted endpoint bundle (variable length)

---

## System Interfaces

### Signaling Store Interface

```
AllocateChannel(id, ttl, remoteAddr) -> error
ChannelExists(id) -> bool
StoreBlob(id, senderBool, blob) -> error
FetchBlob(id, senderBool) -> (blob, error)
RecordFailure(id) -> (failureCount, error)
DeleteChannel(id) -> error
PurgeExpired() -> (cleanedIDs, error)
Close() -> error
```

### Signaling Server HTTP API

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/ws` | WebSocket upgrade | Signaling message relay (allocate, join, blob forwarding) |
| `/cert` | GET | Returns TLS certificate in PEM format for client pinning |

### UDP Reflection Protocol

Two-phase HMAC cookie handshake for external address discovery:

1. **Cookie request**: Client sends 1-byte probe (`0x10`) → Server responds with 9-byte cookie (`0x10` + 8-byte HMAC-SHA256(secret, sourceIP)[:8])
2. **Cookie echo**: Client echoes 9-byte cookie → Server verifies HMAC, responds with external address (7 bytes for IPv4, 19 bytes for IPv6)

Legacy servers that do not support the cookie handshake respond directly with the external address (first byte `0x04` or `0x06`).

### P2P QUIC Protocol

- ALPN: `hermod-p2p`
- Mutual TLS with ephemeral ECDSA P-256 certificates, SPKI-pinned
- Idle timeout: 30 seconds, keep-alive: 5 seconds
- Stream multiplexing:

| Stream (verify active) | Stream (no verify) | Opened by | Content |
|------------------------|--------------------|-----------|---------|
| 0 — SAS coordination | (skipped) | sender | 1-byte confirm (`0x01`) / reject (`0x00`) |
| 1 — Metadata | 0 — Metadata | sender | 4-byte big-endian length prefix + JSON |
| 2 — Payload | 1 — Payload | sender | Raw bytes; SHA-256 computed in parallel |
| 3 — Trailing hash | 2 — Trailing hash | sender | 4-byte big-endian length prefix + hex SHA-256 (64 chars) |
| 4 — Completion ack | 3 — Completion ack | receiver | Empty stream; sender waits before closing |

- Cancellation: either side closes the QUIC connection with application error code `1` and message `"cancelled:sender"` or `"cancelled:receiver"`.

---

## Protocol Flow

1. **Allocation**: Sender allocates a channel on the signaling server → receives channel ID and external IP (classified by address family)
2. **Join**: Receiver joins the channel (server validates it exists) → sender receives `ready` signal
3. **Address discovery**: Both peers query the signaling server's UDP reflection endpoint to discover their external UDP addresses (critical for CGNAT where UDP port differs from WebSocket TCP port). If discovery fails, peers fall back to the server-reported WebSocket IP combined with the local UDP port.
4. **Hybrid handshake** (relayed through signaling server):
   a. Sender sends blob 1: CPace public message + X25519 public key (97 bytes)
   b. Receiver sends blob 2: CPace public message + X25519 public key + ML-KEM-768 encapsulation key (1281 bytes)
   c. Both sides derive `kClassical` via CPaceFinish
   d. Both sides derive `ssX25519` via X25519 ECDH
   e. Sender encapsulates ML-KEM ciphertext, receiver decapsulates
   f. Both sides derive `hybridKey = SHA-256(kClassical || ssX25519 || ssMLKEM)`
   g. Sender sends blob 3: ML-KEM ciphertext + encrypted endpoint bundle
   h. Receiver sends blob 4: encrypted endpoint bundle
5. **Endpoint bundle decryption**: Each peer decrypts the other's bundle using the hybrid key derived from CPace + X25519 + ML-KEM-768. Verification flag is merged: `verify = local || peer.require_verify`
6. **NAT hole punching**: Peers send UDP probes to each other's candidate endpoints (dual-phase: IPv6 preferred with 5 s timeout, IPv4 fallback with remaining context timeout)
7. **QUIC connection**: Sender dials, receiver listens. Mutual TLS with SPKI pinning using the fingerprint from the endpoint bundle
8. **SAS verification** (optional, when `verify` is active): Short Authentication String comparison via out-of-band channel to detect MitM. SAS is session-bound via TLS ExportKeyingMaterial with channel ID. Cancellation is coordinated: if either side cancels, `0x00` is sent over the SAS stream and both sides receive a cancellation message
9. **Payload transfer**:
   - Metadata (JSON with kind, name, size) sent on first data stream
   - Payload streamed while both sender and receiver compute SHA-256 in parallel via TeeReader
   - Trailing hash (hex SHA-256) sent after payload
   - Receiver verifies integrity against computed hash
   - For file transfers, payload is written to a temp file first; atomically renamed after integrity check passes
10. **Acknowledgment**: Receiver sends completion ack (empty stream); sender waits before closing the QUIC connection

---

## State and Memory Management

### Signaling Server State
- Channels are stored in-memory with TTL-based expiry. Expired channels are purged by a background goroutine running every 10 seconds.
- WebSocket connections have an idle timeout derived from the TTL flag (default 600 s). Idle connections are closed, and stale waiters are purged.
- Rate limiter buckets are keyed by HMAC-SHA256(daily salt, IP prefix). Stale buckets (inactive for 30+ minutes) are evicted every 10 minutes.
- The HMAC secret for the UDP reflection endpoint is rotated every UTC calendar day. The previous key is accepted during a 5-minute grace period.

### Client State
- Ephemeral TLS certificates are generated per-session and never stored. Valid for 2 hours.
- The UDP socket is shared between hole-punch probes and QUIC traffic via a packet demultiplexer. Probing continues after hole-punch succeeds to keep NAT mappings alive until the QUIC connection is established.
- Temp files are created with `O_EXCL` and `0o600` permissions. On any error (including cancellation), the temp file is removed.

### Memory Bounds
- WebSocket message size is capped at 64 KiB on both client and server.
- Rate limiter buckets have a 30-minute staleness threshold for cleanup.
- Channel blob count is capped at 10 per channel.
- CPace failure count is capped at 3 per channel — exceeding this drops the channel and disconnects all peers.
- Per-IP channel allocation is capped at 100 concurrent channels (default).

---

## Logging

Controlled by verbosity levels: `none` | `error` | `warning` | `info` | `debug` (default: `none`).

| Level   | What it covers |
|---------|----------------|
| error   | Unrecoverable failures — integrity check failed, server exited with error |
| warning | Non-fatal problems — rate-limited request, missing peer, ack not received |
| info    | State changes — server ready, channel allocated/joined, PAKE complete, hole punch success, QUIC connected, transfer complete |
| debug   | Every internal step — config load, cert gen, UDP bind, each relay message, stream open/close, GC start |

Rules:
- `debug` traces every step in all three modes (serve, tx, rx).
- `info` covers connection-level events: connections, requests, results.
- Log messages use plain language: active voice, specific names, no filler.
- Sensitive material (keys, passwords, raw payloads) is never logged at any level.
- All output goes to stderr. No log files are written.

---

## Key Architectural Decisions

1. **Zero-trust signaling server**: The signaling server handles only encrypted blobs — no plaintext keys or payloads pass through it. The server cannot read transferred content even if compromised.

2. **Three-pillar hybrid key agreement**: Combining CPace (classical PAKE), X25519 (elliptic curve), and ML-KEM-768 (post-quantum) ensures security against both classical and quantum adversaries. Breaking any two of the three pillars still leaves the third protecting the session.

3. **SPKI pinning over DER pinning**: Pinning the Subject Public Key Info hash rather than the full certificate DER allows certificate renewal with the same key pair — clients never need to re-pin.

4. **HMAC-privatized rate limiting**: Rate limiter keys are HMAC-SHA256 of the IP prefix with a daily-rotating salt. No raw IP addresses are ever stored, logged, or exposed.

5. **Single-UDP-socket architecture**: Hole-punch probes and QUIC traffic share one UDP socket via first-byte demultiplexing, avoiding port prediction complexity and firewall rule multiplication.

6. **Two-phase UDP reflection**: The external address discovery protocol uses an HMAC cookie handshake to prevent amplification attacks — the server never responds to unverified sources.

7. **In-band trailing hash**: SHA-256 integrity is computed during transfer and sent after the payload, avoiding a separate file read pass. Both sender and receiver compute in parallel.

8. **Atomic file writes**: Receivers write to a temp file first and atomically rename after integrity verification. On any error or cancellation, the temp file is removed.

9. **Coordinated SAS cancellation**: During SAS verification, cancellation is propagated via the QUIC coordination stream. Both sides receive a descriptive cancellation message indicating who cancelled.

10. **CGNAT-aware address discovery**: The signaling server runs a separate UDP reflection endpoint on the same port as the TLS listener. Peers discover their external UDP address before the endpoint bundle exchange, ensuring the correct port (not the WebSocket port) is advertised.
