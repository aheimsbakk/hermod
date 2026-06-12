# Protocol specification

This document describes the Hermod wire protocol: how two peers establish a shared secret, exchange network endpoints, and transfer a payload.

## Roles

- **Sender (tx)** — initiates the transfer, allocates a signaling channel
- **Receiver (rx)** — joins the channel using the transfer code
- **Signaling server** — relays handshake messages only; never sees payload data

## Connection flow overview

### Phase 1 — Signaling

```
Sender (tx)             Signaling server        Receiver (rx)
     |                        |                        |
     |--- allocate(id) -----> |                        |
     |<-- ok(public_ipv4/v6)- |                        |
     |                        | <-- join(id) --------- |
     |<-- ready ------------- |                        |
     |                        | --> ok(public_ipv4/v6) |
```

### Phase 2 — CPace PAKE (blobs relayed via server)

```
Sender (tx)             Signaling server        Receiver (rx)
     |                        |                        |
     |--- blob(cpace_msg) --> | --> blob(cpace_msg) -> |
     |<-- blob(cpace_msg) --- | <-- blob(cpace_msg) -- |
```

### Phase 3 — Hybrid KEM + Endpoint exchange (blobs relayed via server)

After CPace derivation, peers perform a **three-pillar hybrid KEM exchange**:
classical CPace (P-256) + classical X25519 ECDH + post-quantum ML-KEM-768.

#### Blob 1 (sender → receiver): CPace + X25519 pub (97 bytes binary)

65-byte CPace point + 32-byte X25519 public key.

#### Blob 2 (receiver → sender): CPace + X25519 pub + ML-KEM enc key (1281 bytes binary)

65-byte CPace point + 32-byte X25519 public key + 1184-byte ML-KEM-768
encapsulation key.

#### Key derivation (both sides)

```
kClassical  = CPaceFinish(peer_cpace, password)    // 32 bytes, P-256
ssX25519    = ECDH(my_priv, peer_x25519_pub)        // 32 bytes, X25519
ssMLKEM     = Encapsulate(peer_mlkem_ek)            // 32 bytes (sender)
           = Decapsulate(my_dk, kem_ct)             // 32 bytes (receiver)

hybridKey   = SHA-256(kClassical || ssX25519 || ssMLKEM)  // 32 bytes
```

#### Blob 3 (sender → receiver): KEM ciphertext + encrypted bundle

1088-byte ML-KEM-768 ciphertext + AES-256-GCM(hybridKey, AAD=channelID,
sender_bundle).

#### Blob 4 (receiver → sender): encrypted bundle

AES-256-GCM(hybridKey, AAD=channelID, receiver_bundle).

Signaling connection is no longer used after this point.

### Phase 4 — UDP hole punch (direct, server not involved)

Both peers probe each other's candidates concurrently in two phases:

- **IPv6 first (preferred)** — 5 s timeout; skips to IPv4 on timeout or if no IPv6 candidates exist. Skipped entirely with `-4`.
- **IPv4 fallback** — uses the remaining context timeout (10 s total). Skipped entirely with `-6`.

The first candidate address from which a valid ack is received wins. That address is used for the QUIC connection.

### Phase 5 — QUIC connection (sender dials, receiver listens)

After hole punching, the sender dials and the receiver listens on the same muxed UDP socket. The receiver starts a QUIC listener before the sender begins dialing (with a 200 ms delay after hole punch to ensure the listener is ready).

- ALPN: `hermod-p2p`
- Both sides present ephemeral ECDSA P-256 self-signed certs (valid 2 h)
- Receiver enforces mutual TLS (`RequireAnyClientCert`) — the sender presents a cert and the receiver verifies its fingerprint
- Each side pins the peer's cert fingerprint from the endpoint bundle
- Idle timeout: 30 s, keep-alive: 5 s

### Phase 6 — Payload transfer (QUIC streams, sender-opened unless noted)

Without `--verify`, stream 0 (SAS) is skipped and all subsequent streams are renumbered by subtracting 1.

| Stream (with verify) | Stream (without verify) | Opened by | Content                                     |
|----------------------|-------------------------|-----------|---------------------------------------------|
| 0 — SAS              | (skipped)               | sender    | 1-byte confirm/reject; only when `--verify` |
| 1 — Metadata         | 0                       | sender    | 4-byte-prefixed JSON: kind, name, size      |
| 2 — Payload          | 1                       | sender    | raw bytes; SHA-256 computed in parallel     |
| 3 — Trailing hash    | 2                       | sender    | 4-byte-prefixed hex SHA-256 of payload      |
| 4 — Completion ack   | 3                       | receiver  | empty stream; sender waits before closing   |

### Security properties

- Signaling server sees only binary blobs (CPace points, X25519 keys, ML-KEM
  ciphertexts, and AES-256-GCM ciphertexts) after `allocate`/`join`
- CPace PAKE derives shared key K_classical from the transfer code without
  exposing it
- Endpoint bundles encrypted with **HybridBlobKey**: three-pillar combining
  CPace (P-256) + X25519 ECDH + ML-KEM-768 via SHA-256 concatenation combiner.
  Security is at least as strong as the strongest pillar — post-quantum secure
  even if P-256 falls to quantum cryptanalysis
- QUIC: TLS 1.3, ephemeral self-signed certs, fingerprint-pinned (no CA)
- Payload integrity: trailing SHA-256 hash stream verified end-to-end
- Payload never touches the signaling server

Each phase is described in detail in the sections below.

## Verification chain

A transfer succeeds only when every layer in the chain passes. Each layer
verifies a different property and a failure in any layer aborts the transfer.

| Layer | What it verifies | How |
|-------|------------------|-----|
| **CPace (P-256)** | Both peers know the same transfer code (password) | `kClassical` derived from password; bound into hybrid key. Wrong password → AES-GCM tag mismatch on endpoint bundle → abort |
| **X25519 ECDH** | Classical key agreement (defense-in-depth) | `ssX25519` derived from ephemeral key exchange; bound into hybrid key alongside CPace and ML-KEM |
| **ML-KEM-768** | Post-quantum key agreement | `ssMLKEM` encapsulated by sender, decapsulated by receiver; bound into hybrid key. Protects endpoint bundles even if P-256/X25519 are broken by quantum computer |
| **HybridBlobKey** | All three pillars combined | `SHA-256(kClassical \|\| ssX25519 \|\| ssMLKEM)`. Security is at least as strong as the strongest pillar |
| **Endpoint bundle** | Peer identity (IPs, cert fingerprint) | AES-256-GCM encrypted with HybridBlobKey + channel ID as AAD. Contains peer's UDP candidates + ephemeral TLS cert fingerprint |
| **UDP hole punch** | Both peers are reachable at their claimed addresses | Probe/ack exchange using nonce derived from `hybridKey` (CPace + X25519 + ML-KEM-768). Hole punch fails if no peer responds |
| **QUIC/TLS 1.3** | Peer certificate matches the bundle | Mutual TLS with fingerprint pinning: each side verifies the peer's ephemeral cert fingerprint against the value received in the encrypted endpoint bundle |
| **SAS (optional)** | No MitM in the QUIC handshake | Human compares 6-word SAS + identicon out-of-band (voice, Signal, etc.) derived from TLS ExportKeyingMaterial |
| **Trailing SHA-256** | Payload integrity | Sender computes hash while streaming; receiver verifies after receipt. Mismatch → file deleted |

## Transfer code

The transfer code encodes the channel ID and the PAKE passphrase.

Format:
```
<channel-id>-<word1>-<word2>-...-<wordN>
```

Example: `47832-apple-banana-cherry`

- The first token is the numeric channel ID — a random `uint16` (0–65535).
- The words are drawn from the full EFF Short Wordlist 1 (1,296 unique entries). They form the shared passphrase for the CPace handshake. Each word is selected using rejection sampling on uniform random `uint16` values to eliminate modulo bias.
- The default word count is 3 (≈31.9 bits of passphrase entropy), overridable with `--words` on `tx`.

The sender generates the code and displays it on stderr. The receiver types it in.

## Signaling protocol

The signaling server exposes two endpoints over TLS:

- `/ws` — WebSocket endpoint for signaling messages (allocate, join, blob relay).
- `/cert` — HTTPS endpoint that returns the server's TLS certificate in PEM format for client pinning (used by `hermod trust`). Both endpoints share the same per-IP rate limiter (`--rate-limit` / `--rate-burst` on `hermod serve`).

All messages are JSON with this envelope:

```json
{
  "type": "<message-type>",
  "channel_id": 1234,
  "payload": <bytes or null>,
  "error": ""
}
```

`payload` is a raw JSON byte array (base64-encoded over the wire by `encoding/json`).

### Message types

| Type | Direction | Description |
|---|---|---|
| `allocate` | client → server | Sender reserves a channel |
| `join` | client → server | Receiver joins an existing channel. Server returns `error` if the channel does not exist. |
| `blob` | client → server | Relay an encrypted blob to the peer |
| `ready` | server → client | Sent to sender when receiver joins |
| `ok` | server → client | Acknowledges `allocate` or `join`; carries `public_ip` and the address-family-specific key `public_ipv4` or `public_ipv6` |
| `error` | server → client | Reports a server-side error |

### Sequence

```
Sender                  Server                  Receiver
  |                       |                        |
  |--- allocate(id) ----→ |                        |
  |← ok(public_ip) -----  |                        |
  |                       |  ←--- join(id) --------|
  |← ready -------------- |                        |
  |                       |  --- ok(public_ip) ---→|
  |                       |                        |
  |--- blob1(CPace+X25519) →|  → blob1 →           |
  |← blob2(CPace+X25519+MLKEMek) |  ← blob2 ←     |
  |                       |                        |
  |--- blob3(KEMct+encBundle) →|  → blob3 →        |
  |← blob4(encBundle) --- |  ←-- blob4 -----------|
```

After the last blob exchange the signaling connection is no longer used.

## CPace handshake

Hermod uses CPace (Balanced Password-Authenticated Key Exchange) to derive a shared key from the passphrase without sending the passphrase over the network.

Implementation: CPace over P-256 using `crypto/elliptic` and `math/big` from the Go standard library.

### Steps

1. Both peers call `CPaceInit(password, channelID, role)` where `role` is `"sender"` or `"receiver"`. This produces a public message (an elliptic curve point on P-256) and a session state.
2. Each peer sends its public message inside a `blob` message.
3. Each peer calls `CPaceFinish(peerPubMsg)` with the other's point. Both peers derive the same 32-byte shared key `K` if and only if they used the same password.
4. If the passwords differ, the derived keys differ and the subsequent AES-GCM decrypt fails, aborting the connection.

The `channelID` and `role` are used as domain separators:

- The hash-to-curve generator uses the `P256_XMD:SHA-256_SSWU_RO_` suite (RFC 9380). The DST encodes `channelID` and the password; the message is the fixed tag `sender:receiver`. Both peers compute the same generator point, and the domain is separated from other protocol instances.
- The ISK (Intermediate Session Key) is derived as `SHA-256(iskX || pubSender || pubReceiver)`, where each peer places its own public message in the slot that matches its role. Both peers produce the same byte sequence and thus the same `K`. This binds the role into the shared secret and prevents cross-role composition attacks per RFC 9496 intent.

## Endpoint exchange

After CPace and the hybrid KEM exchange (X25519 + ML-KEM-768), each peer derives
the **HybridBlobKey**:

```
hybridKey = SHA-256(kClassical || ssX25519 || ssMLKEM)
```

Each peer encrypts its candidate UDP addresses, ephemeral TLS certificate
fingerprint, and verify flag with `hybridKey` using AES-256-GCM, then relays
the ciphertext through the signaling server.

The channel ID (2-byte big-endian) is bound as AES-GCM Additional Authenticated
Data (AAD). This prevents a captured endpoint bundle from being replayed in a
different session.

Plaintext endpoint bundle (JSON before encryption):
```json
{
  "local_endpoints_v4": ["192.168.1.5:51234", "10.0.0.2:51234"],
  "local_endpoints_v6": ["[fe80::1]:51234", "[2001:db8::1]:51234"],
  "public_endpoint_v4": "203.0.113.7:51234",
  "public_endpoint_v6": "2001:db8::1:51234",
  "cert_fingerprint": "a3f9...64 hex chars...",
  "require_verify": false
}
```

Addresses are split by IP family. The recipient reads candidates using
`CandidatesV4()` and `CandidatesV6()` which include the public endpoint
(if present) followed by the local endpoints.

`require_verify` is `true` when this peer was started with `--verify`. After each side decrypts the peer's bundle, it computes:

```
verify = local_verify || peer.require_verify
```

If either side requested verification, both sides perform it. The merged value is used for the rest of the session.

## NAT hole punching

Both peers run a two-phase hole punch: IPv6 candidates first (preferred), then IPv4 (fallback).

The IPv6 phase has a 5-second timeout. If it succeeds, the IPv4 phase is skipped. If it times out or no IPv6 candidates exist, the IPv4 phase runs with the remaining context timeout (default 10 s total).

Use `-4` (`--ipv4`) to skip the IPv6 phase entirely. Use `-6` (`--ipv6`) to skip the IPv4 phase entirely. Both flags are mutually exclusive.

Within each phase, probe packets are sent to all candidate addresses of that family concurrently:

Probe and ack packet format (8 bytes each):
```
byte 0:    0x01        (probe/ack marker)
bytes 1–7: hash[0:7]  (probe) or hash[8:14]  (ack) — 7 bytes of SHA-256(hybridKey + "hermod-holepunch-v1")
```

The hash is session-specific (derived from the HybridBlobKey — CPace + X25519 ECDH + ML-KEM-768). Each side uses bytes [0:7] of the hash as the probe identifier and bytes [8:15] as the ack identifier, giving 64 bits of entropy per packet — practically unguessable by an off-path attacker.

The first probe that receives a reply from the correct peer address wins. That address is used for the QUIC connection.

Both peers run the hole punch concurrently. The typical completion time on symmetric NATs is under 500 ms on a LAN and 1–2 s across the internet.

## QUIC connection

After hole punching, the sender (QUIC client) dials the receiver (QUIC server)
on the hole-punched address. The receiver opens a QUIC listener before the sender
begins dialing — a 200 ms delay after hole punch on the sender side ensures the
listener is ready.

Each peer generates an ephemeral ECDSA P-256 self-signed X.509 certificate for this connection. The certificate fingerprint was exchanged in the endpoint bundle (above). Both peers pin the peer's fingerprint in their TLS `VerifyPeerCertificate` callback, replacing normal CA-chain verification. The receiver's TLS config uses `RequireAnyClientCert` for mutual authentication — the sender presents its certificate and the receiver verifies its fingerprint. ECDSA P-256 is chosen for fast key generation and smaller signatures.

QUIC configuration:
- TLS 1.3 (enforced by quic-go)
- ALPN: `hermod-p2p`
- Idle timeout: 30 seconds
- Keep-alive period: 5 seconds

## Payload transfer

The sender opens QUIC streams in order. When SAS verification is active, stream 0 is the SAS coordination stream. Metadata and payload follow.

### Stream 0 — SAS coordination (only when verify is active)

Each peer independently prompts the user to confirm the SAS values out-of-band. After the user answers, both sides exchange a single byte on this stream:

- `0x01` — confirmed
- `0x00` — rejected

The sender opens the stream, writes its byte, then reads the peer's byte. The receiver accepts the stream, reads the peer's byte, then writes its own. The transfer proceeds only if **both** bytes are `0x01`. If either side rejects, both peers receive an error and the QUIC connection is closed before any payload is sent.

This design means neither side can abort the other before they have had a chance to respond.

### Stream 1 (or 0 without verify) — metadata

A 4-byte big-endian length prefix followed by a JSON object:

```json
{
  "kind": "file",
  "name": "report.pdf",
  "size": 204800,
  "sha256": ""
}
```

`kind` is either `"file"`, `"text"`, or `"stream"`.  
`name` is set only for `kind = "file"`. The receiver strips all directory components from the received name with `filepath.Base` before writing to disk, preventing path traversal attacks.  
`sha256` is always empty (`""`). The actual SHA-256 is computed in parallel during transfer and sent in the trailing hash stream (see below).

### Stream 2 (or 1 without verify) — payload

Raw bytes of the file or text, sent in order. No framing.

The sender wraps the payload source in a `TeeReader` that feeds a running SHA-256 hash while streaming bytes to the QUIC stream. The hash is computed in parallel with the transfer, so no buffering of large inputs is needed.

The receiver also reads the payload stream through a `TeeReader`, computing SHA-256 in parallel while writing to the output destination. After the stream closes, the receiver waits for the trailing hash stream (see below) to verify integrity.

### Stream 3 (or 2 without verify) — trailing hash

Sent by the sender immediately after the payload stream is closed. Format: 4-byte big-endian length prefix followed by the hex-encoded SHA-256 of the payload bytes (64 ASCII characters).

The receiver reads this stream after the payload is fully received and compares the trailing hash against its own computed hash. A mismatch aborts with an error. For file transfers, no file has yet been moved to the final destination at this point; only the rename is suppressed on mismatch.

### Completion ack stream

After the payload is saved and verified, the receiver opens one final QUIC stream and immediately closes it. The sender waits to accept this stream before closing the QUIC connection. This prevents the connection from tearing down before the receiver has finished reading the payload.

## SAS verification (optional)

When `verify` is active (see Endpoint exchange above), after the QUIC handshake each peer calls `tls.ConnectionState.ExportKeyingMaterial("hermod-sas-v1", nil, 32)` to derive 32 bytes of key material bound to the session. These bytes are used to generate:

- A **Short Authentication String (SAS)** — a sequence of English words from a fixed wordlist
- An **identicon** — a symmetric ASCII art image derived from the first 16 bytes, rendered inside a double-line box frame with one space of padding inside each vertical border (`║ … ║`)

Both peers display these values simultaneously. The user compares them out-of-band (voice, Signal, etc.) and confirms or rejects. User input is always read from the controlling terminal (`/dev/tty` on Unix, `CONIN$` on Windows) so the prompt works correctly when stdin is piped. The result is then exchanged over the SAS coordination stream (see Payload transfer above). A rejection by either side closes the QUIC connection before any payload is sent.

The prompt listens for OS signals (SIGINT, SIGTERM) and QUIC connection loss while waiting for input. If the user presses Ctrl+C, or if the peer disconnects during the prompt, the read is interrupted immediately. The cancelling side sends `0x00` over the coordination stream and both sides receive a cancellation error message.

## Transfer cancellation

Either side can cancel a transfer at any time by pressing Ctrl+C (SIGINT) or sending SIGTERM.

When the context is cancelled, the cancelling peer closes the QUIC connection with:

- Application error code: `1`
- Error message: `"cancelled:sender"` (tx) or `"cancelled:receiver"` (rx)

This immediately unblocks the peer's blocked stream read or write. The peer detects the `*quic.ApplicationError` with code `1` and prints a message naming who cancelled. For example:

```
Transfer cancelled by sender.
```

Cancellation also works during SAS verification. If the user presses Ctrl+C while the SAS prompt is waiting for input, the prompt exits, the peer receives `0x00` on the coordination stream, and both sides see a cancellation message (e.g. `"SAS verification cancelled by user"` or `"SAS verification cancelled by both sides"`). The prompt also unblocks automatically if the peer disconnects during verification.

On the receiving side, any partial `.hermod_tmp` file is deleted before exit. No incomplete file is left on disk.

Both sides exit with a non-zero status code after cancellation.

## Security considerations

- The signaling server sees only encrypted blobs after the initial `allocate`/`join`. It cannot recover the CPace key or the endpoint data.
- The signaling server TLS certificate is pinned on the client after running `hermod trust`. Connections to an unknown server are accepted on first use and the fingerprint is saved.
- The server certificate is self-signed, non-CA (`IsCA=false`), valid for 1 year. The server logs warnings at startup as the certificate approaches expiry (≤90 days WARN, ≤30 days ERROR, ≤7 days CRITICAL).
- Channel IDs are 16-bit integers. Collisions are possible in high-traffic deployments. The signaling server rejects a second `allocate` for an in-use channel. A `join` for a non-existent channel is rejected with an error response.
- The server enforces a maximum of **3 failed CPace handshake attempts** per channel. On the third violation all peer connections are closed, the channel is invalidated, and its state is purged.
- The server enforces a maximum of **10 relayed blobs** per channel to prevent relay saturation. Exceeding the limit closes the offending connection.
- Client IP addresses are never stored in plaintext. The rate-limiter bucket key is `HMAC-SHA256(dailySalt, ipPrefix)`. The salt is replaced every UTC calendar day and all buckets are cleared on rotation. Stale buckets are also evicted every 10 minutes to bound memory usage.
- Endpoint bundles are encrypted with `AES-256-GCM(hybridKey, channelID_as_AAD, bundle)`. The key `hybridKey = SHA-256(kClassical || ssX25519 || ssMLKEM)` combines three pillars: CPace (P-256 PAKE), X25519 ECDH, and ML-KEM-768 (post-quantum KEM). A quantum adversary who breaks P-256 to recover `kClassical` still cannot decrypt the bundles without the ML-KEM-768 shared secret.
- The CPace implementation uses the `P256_XMD:SHA-256_SSWU_RO_` suite (RFC 9380) to hash passwords to P-256 curve points. SSWU always produces a valid point in a single, fixed-length computation with no data-dependent loop iterations, eliminating the loop-count timing side channel of the former try-and-increment method.
- Ephemeral QUIC certificates use ECDSA P-256. They are valid for 24 hours and are never stored.
- Payload integrity is verified end-to-end via a trailing hash stream. The sender computes SHA-256 in parallel during transfer and sends the digest after the payload stream closes. The receiver computes SHA-256 in parallel during receipt and verifies against the sender's trailing digest. No pre-buffering of large inputs is required.
