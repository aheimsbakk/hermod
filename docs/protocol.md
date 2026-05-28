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
<word-count>-<word1>-<word2>-...-<wordN>
```

Example: `3-apple-banana-cherry`

- The first token (`3`) is the number of words, which also encodes the channel ID.
- The words are drawn from a fixed wordlist. They form the shared passphrase for the CPace handshake.
- Channel ID is derived from the word count and a random offset. It fits in a `uint16`.

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

The `channelID` and `role` are mixed into the hash-to-curve input as domain separation, preventing cross-role replay.

## Endpoint exchange

After CPace, each peer encrypts its candidate UDP addresses and ephemeral TLS certificate fingerprint with `K` using AES-256-GCM, then relays the ciphertext through the signaling server.

Plaintext endpoint bundle (JSON before encryption):
```json
{
  "local_endpoints": ["192.168.1.5:51234", "10.0.0.2:51234"],
  "public_endpoint": "203.0.113.7:51234",
  "cert_fingerprint": "a3f9...64 hex chars..."
}
```

The receiver decrypts the sender's bundle and vice versa. A decryption failure aborts the connection.

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
- ALPN: `hermod/1`
- Idle timeout: 30 seconds

## Payload transfer

The sender opens two sequential QUIC streams.

### Stream 0 — metadata

A 4-byte big-endian length prefix followed by a JSON object:

```json
{
  "kind": "file",
  "name": "report.pdf",
  "size": 204800,
  "sha256": "e3b0c44298fc1c149afb..."
}
```

`kind` is either `"file"` or `"text"`.  
`name` is set only for `kind = "file"`.  
`sha256` is the hex-encoded SHA-256 of the payload bytes.

### Stream 1 — payload

Raw bytes of the file or text, sent in order. No framing.

The receiver reads stream 1 through a `TeeReader` that simultaneously writes to the output and feeds a running SHA-256 hash. After the stream closes, the computed hash is compared to `sha256` from the metadata. A mismatch aborts with an error and the partial output is discarded.

## SAS verification (optional)

When both peers pass `--verify`, after the QUIC handshake each peer calls `tls.ConnectionState.ExportKeyingMaterial("hermod-sas-v1", nil, 32)` to derive 32 bytes of key material bound to the session. These bytes are used to generate:

- A **Short Authentication String** — a sequence of English words from a fixed wordlist
- An **identicon** — a small ASCII art image derived from the first 16 bytes

Both peers display these values. The user compares them out-of-band (voice, Signal, etc.) and confirms or rejects. A rejection closes the QUIC connection before any payload is sent.

## Security considerations

- The signaling server sees only encrypted blobs after the initial `allocate`/`join`. It cannot recover the CPace key or the endpoint data.
- The signaling server TLS certificate is pinned on the client after running `hermod trust`. Connections to an unknown server are accepted on first use and the fingerprint is saved.
- Channel IDs are 16-bit integers. Collisions are possible in high-traffic deployments. The signaling server rejects a second `allocate` for an in-use channel.
- The CPace implementation uses the try-and-increment method to hash passwords to P-256 curve points. This is a deterministic constant-time-per-attempt approach.
- Ephemeral QUIC certificates use RSA-2048. They are valid for 24 hours and are never stored.
