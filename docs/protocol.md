# Protocol specification

This document describes the Hermod wire protocol: how two peers establish a shared secret, exchange network endpoints, and transfer a payload.

## Roles

- **Sender (tx)** — initiates the transfer, allocates a signaling channel
- **Receiver (rx)** — joins the channel using the transfer code
- **Signaling server** — relays handshake messages only; never sees payload data

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

The sender generates the code and displays it. The receiver types it in.

## Signaling protocol

The signaling server exposes a single WebSocket endpoint at `/ws` over TLS.

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
| `join` | client → server | Receiver joins an existing channel |
| `blob` | client → server | Relay an encrypted blob to the peer |
| `ready` | server → client | Sent to sender when receiver joins |
| `ok` | server → client | Acknowledges `allocate` or `join`; carries `public_ip` |
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
  |--- blob(cpace_msg) -→ |  --- blob(cpace_msg) →|
  |← blob(cpace_msg) ---- |  ←-- blob(cpace_msg) -|
  |--- blob(enc_bundle) → |  --- blob(enc_bundle)→|
  |← blob(enc_bundle) --- |  ←-- blob(enc_bundle)-|
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

After CPace, each peer encrypts its candidate UDP addresses, ephemeral TLS certificate fingerprint, and verify flag with `K` using AES-256-GCM, then relays the ciphertext through the signaling server.

Plaintext endpoint bundle (JSON before encryption):
```json
{
  "local_endpoints": ["192.168.1.5:51234", "10.0.0.2:51234"],
  "public_endpoint": "203.0.113.7:51234",
  "cert_fingerprint": "a3f9...64 hex chars...",
  "require_verify": false
}
```

`require_verify` is `true` when this peer was started with `--verify`. After each side decrypts the peer's bundle, it computes:

```
verify = local_verify || peer.require_verify
```

If either side requested verification, both sides perform it. The merged value is used for the rest of the session.

## NAT hole punching

Both peers send UDP probe packets to all candidate addresses of the other peer simultaneously.

Probe packet format:
```
byte 0:    0x01  (probe marker)
bytes 1–N: random payload
```

The first probe that receives a reply from the correct peer address wins. That address is used for the QUIC connection.

Both peers run the hole punch concurrently. The typical completion time on symmetric NATs is under 500 ms on a LAN and 1–2 s across the internet.

## QUIC connection

After hole punching, the receiver acts as the QUIC server and the sender as the client.

Each peer generates an ephemeral RSA-2048 self-signed X.509 certificate for this connection. The certificate fingerprint was exchanged in the endpoint bundle (above). Both peers pin the peer's fingerprint in their TLS `VerifyPeerCertificate` callback, replacing normal CA-chain verification.

QUIC configuration:
- TLS 1.3 (enforced by quic-go)
- ALPN: `hermod-p2p`
- Idle timeout: 30 seconds

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
  "sha256": "e3b0c44298fc1c149afb..."
}
```

`kind` is either `"file"`, `"text"`, or `"stream"`.  
`name` is set only for `kind = "file"`. The receiver strips all directory components from the received name with `filepath.Base` before writing to disk, preventing path traversal attacks.  
`sha256` is the hex-encoded SHA-256 of the payload bytes.

### Stream 2 (or 1 without verify) — payload

Raw bytes of the file or text, sent in order. No framing.

The receiver reads the payload stream through a `TeeReader` that simultaneously writes to the output and feeds a running SHA-256 hash. After the stream closes, the computed hash is compared to `sha256` from the metadata. A mismatch aborts with an error and the partial output is discarded.

### Completion ack stream

After the payload is saved and verified, the receiver opens one final QUIC stream and immediately closes it. The sender waits to accept this stream before closing the QUIC connection. This prevents the connection from tearing down before the receiver has finished reading the payload.

## SAS verification (optional)

When `verify` is active (see Endpoint exchange above), after the QUIC handshake each peer calls `tls.ConnectionState.ExportKeyingMaterial("hermod-sas-v1", nil, 32)` to derive 32 bytes of key material bound to the session. These bytes are used to generate:

- A **Short Authentication String (SAS)** — a sequence of English words from a fixed wordlist
- An **identicon** — a symmetric ASCII art image derived from the first 16 bytes, rendered inside a double-line box frame with one space of padding inside each vertical border (`║ … ║`)

Both peers display these values simultaneously. The user compares them out-of-band (voice, Signal, etc.) and confirms or rejects. User input is always read from the controlling terminal (`/dev/tty` on Unix, `CONIN$` on Windows) so the prompt works correctly when stdin is piped. The result is then exchanged over the SAS coordination stream (see Payload transfer above). A rejection by either side closes the QUIC connection before any payload is sent.

## Transfer cancellation

Either side can cancel a transfer at any time by pressing Ctrl+C (SIGINT) or sending SIGTERM.

When the context is cancelled, the cancelling peer closes the QUIC connection with:

- Application error code: `1`
- Error message: `"cancelled:sender"` (tx) or `"cancelled:receiver"` (rx)

This immediately unblocks the peer's blocked stream read or write. The peer detects the `*quic.ApplicationError` with code `1` and prints a message naming who cancelled. For example:

```
Transfer cancelled by sender.
```

On the receiving side, any partial `.hermod_tmp` file is deleted before exit. No incomplete file is left on disk.

Both sides exit with a non-zero status code after cancellation.

## Security considerations

- The signaling server sees only encrypted blobs after the initial `allocate`/`join`. It cannot recover the CPace key or the endpoint data.
- The signaling server TLS certificate is pinned on the client after running `hermod trust`. Connections to an unknown server are accepted on first use and the fingerprint is saved.
- Channel IDs are 16-bit integers. Collisions are possible in high-traffic deployments. The signaling server rejects a second `allocate` for an in-use channel.
- The server enforces a maximum of **3 failed CPace handshake attempts** per channel. On the third violation all peer connections are closed, the channel is invalidated, and its state is purged.
- The server enforces a maximum of **10 relayed blobs** per channel to prevent relay saturation. Exceeding the limit closes the offending connection.
- Client IP addresses are never stored in plaintext. The rate-limiter bucket key is `HMAC-SHA256(dailySalt, ipPrefix)`. The salt is replaced every UTC calendar day and all buckets are cleared on rotation.
- The CPace implementation uses the `P256_XMD:SHA-256_SSWU_RO_` suite (RFC 9380) to hash passwords to P-256 curve points. SSWU always produces a valid point in a single, fixed-length computation with no data-dependent loop iterations, eliminating the loop-count timing side channel of the former try-and-increment method.
- Ephemeral QUIC certificates use RSA-2048. They are valid for 24 hours and are never stored.
