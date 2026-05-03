# Protocols and Network Design

This document covers the two communication channels Hermod uses — the signaling channel between clients and the server, and the direct P2P channel between peers — plus the NAT traversal strategy that connects them.

---

## Overview

A Hermod transfer uses two distinct channels:

| Channel | Transport | Purpose |
|---|---|---|
| **Signaling channel** | WebSocket over TLS | Broker the handshake; never carries payload |
| **P2P channel** | Direct TCP | Transfer encrypted payload between peers |

The signaling server acts as an encrypted message relay. It stores opaque blobs and forwards them between peers. It never sees the transfer code passphrase, session keys, filenames, file sizes, or content.

---

## Signaling protocol

The signaling server accepts WebSocket connections and exchanges **MessagePack-encoded** messages with each client.

### Message types

#### Client → Server

| Type | Fields | Description |
|---|---|---|
| `REGISTER` | — | Sender requests a new channel ID |
| `JOIN` | `code: str` | Receiver joins an existing channel by transfer code |
| `RELAY` | `channel_id: int`, `payload: bytes` | Forward an opaque blob to the peer |
| `ABORT` | `channel_id: int` | Tear down the channel immediately |

#### Server → Client

| Type | Fields | Description |
|---|---|---|
| `REGISTERED` | `channel_id: int`, `code: str` | Confirms channel creation; returns the full transfer code |
| `JOINED_OK` | — | Confirms the receiver has joined |
| `PEER_CONNECTED` | — | Notifies the sender that a receiver joined |
| `RELAY` | `payload: bytes` | Delivers a blob from the peer |
| `PEER_DISCONNECTED` | — | Notifies the remaining peer that the other side left |
| `ERROR` | `message: str` | Signals a protocol or server error |

### Anti-spam limits

The server enforces hard limits to prevent abuse:

| Limit | Value |
|---|---|
| Max `RELAY` messages per channel | 8 |
| Max message payload | 4096 bytes |
| Rate limit scope | Per IP address (hashed with a daily rotating salt) and per channel |

Channels that exceed the message count limit are dropped. Rate limiting uses a token-bucket algorithm.

---

## P2P wire protocol

Once the P2P connection is established, peers communicate with a binary framing protocol. Every message is a **frame**: a fixed-size prefix followed by a MessagePack header and a raw binary payload.

### Frame layout

```
┌─────────────────────────────────────────────────────┐
│  Magic (2 bytes)   │ Version (1 byte)               │
├─────────────────────────────────────────────────────┤
│  Header length (4 bytes, uint32 big-endian)         │
├─────────────────────────────────────────────────────┤
│  Payload length (8 bytes, uint64 big-endian)        │
├─────────────────────────────────────────────────────┤
│  Header (variable, MessagePack-encoded dictionary)  │
├─────────────────────────────────────────────────────┤
│  Payload (variable, raw encrypted bytes)            │
└─────────────────────────────────────────────────────┘
```

| Field | Size | Value |
|---|---|---|
| Magic | 2 bytes | `HD` (ASCII `0x48 0x44`) |
| Version | 1 byte | `0x01` |
| Header length | 4 bytes | uint32, big-endian |
| Payload length | 8 bytes | uint64, big-endian |

Total prefix size: **15 bytes**.

The header is a MessagePack dictionary. Every header must contain a `"type"` key. Clients must ignore any unrecognised keys — this is the extension point for future protocol versions.

### Frame types

| Type | Direction | Description |
|---|---|---|
| `PQ_INIT` | Sender → Receiver | ML-KEM public key + X25519 public key + HMAC-SHA256 MAC |
| `PQ_RESPONSE` | Receiver → Sender | ML-KEM ciphertext + X25519 public key + HMAC-SHA256 MAC |
| `META` | Sender → Receiver | File metadata (name, size, SHA-256 hash, SecretStream header) |
| `ACK` | Either | Acknowledgement |
| `CHUNK` | Sender → Receiver | One encrypted data chunk (1 MB default) |
| `EOF` | Sender → Receiver | Signals the end of the data stream |
| `ABORT` | Either | Aborts the transfer and closes the connection |
| `ERROR` | Either | Reports a protocol error |

### META frame extension

The `META` frame header carries an extra field: `stream_header` (24 bytes). This is the libsodium `crypto_secretstream` initialisation header. The receiver must pass it to `SecretStreamPull` before decrypting any `CHUNK` frames.

---

## Session flow

A complete transfer follows eight steps.

### Step 1 — Sender connects and registers

The sender opens a TLS WebSocket to the signaling server and sends `REGISTER`. The server responds with `REGISTERED`, which includes a numeric `channel_id`. The sender builds the transfer code by combining the channel ID with three random words and prints it to the terminal.

### Step 2 — Receiver joins

The receiver opens a TLS WebSocket to the same server and sends `JOIN` with the transfer code. The server routes the receiver to the correct channel and sends `JOINED_OK` to the receiver and `PEER_CONNECTED` to the sender.

### Step 3 — SPAKE2 key exchange

Sender and receiver exchange SPAKE2 messages through the signaling relay. Each message is an opaque blob — the server cannot interpret it. After two round-trips both sides derive `K_classical`. See [`crypto.md`](crypto.md) for details.

### Step 4 — ICE candidate exchange

Both peers:

1. Bind a TCP listener on a local port.
2. Gather ICE candidates (see [NAT traversal](#nat-traversal-and-ice) below).
3. Serialize the candidate list as:
   ```json
   {"candidates": [{"type": "host", "ip": "192.168.1.5", "port": 9000}, ...]}
   ```
4. Encrypt the serialised list with `AEADCipher(K_classical[:32])`.
5. Send the encrypted blob via `RELAY` through the signaling server.

The server sees only an opaque encrypted blob. It cannot read the IP addresses.

### Step 5 — P2P connection (ICE connect)

Both peers call `ice_connect(listener, peer_candidates)`, which races:

- An inbound TCP `accept()` on the local listener.
- Outbound TCP probes to each peer candidate, sorted by priority (server-reflexive first, then host).

The **sender** (ICE controlling role) fires probes immediately.  
The **receiver** (ICE controlled role) delays probes by 100 ms so the sender's probe reaches the receiver's listener first, reducing split-connection races.

When multiple tasks complete in the same asyncio tick, tasks are evaluated in insertion order: `accept_task` first, then probes by priority. This guarantees both peers agree on the same TCP connection.

The signaling WebSocket is closed once the P2P connection is established.

### Step 6 — PQ + ECDH upgrade

Over the new P2P TCP connection:

1. The sender sends `PQ_INIT`: `{pk_kem, salt, pk_ecdh, mac}`.
   - `pk_kem`: ML-KEM-768 encapsulation key (1184 bytes)
   - `salt`: random 32 bytes for HKDF
   - `pk_ecdh`: X25519 public key (32 bytes)
   - `mac`: HMAC-SHA256 over `pk_kem ‖ pk_ecdh`, keyed by `K_classical[:32]`

2. The receiver verifies the MAC, then sends `PQ_RESPONSE`: `{ct, pk_ecdh, mac}`.
   - `ct`: ML-KEM ciphertext (1088 bytes)
   - `pk_ecdh`: receiver's X25519 public key (32 bytes)
   - `mac`: HMAC-SHA256 over `ct ‖ pk_ecdh`, keyed by `K_classical[:32]`

3. The sender verifies the MAC.

Both sides derive `K_pq` (ML-KEM) and `K_ecdh` (X25519) from the same two frames — no extra round-trip.

### Step 7 — Session key derivation

Both peers run HKDF-SHA256:

```
Session_Key = HKDF(
    ikm  = K_classical ‖ K_ecdh ‖ K_pq,
    salt = salt field from PQ_INIT,
    info = "hermod-session-v2",
    len  = 32
)
```

If `--verify` is set, both peers now pause, display a short authentication string (SAS) derived from `Session_Key`, and wait for the user to confirm both strings match before proceeding.

### Step 8 — Data transfer

1. Sender initialises a `SecretStreamPush` from `Session_Key`.
2. Sender sends `META` (file name, size, SHA-256 hash, 24-byte SecretStream stream header).
3. Receiver sends `ACK`.
4. Sender sends `CHUNK` frames (1 MB each), each encrypted by `SecretStreamPush.push()`.
5. The final chunk uses `TAG_FINAL`. Sender sends `EOF`.
6. Receiver sends `ACK`.
7. Receiver decrypts all chunks with `SecretStreamPull.pull()`. The last chunk must carry `TAG_FINAL`, otherwise the receiver raises `ValueError("Stream truncated")`.
8. Receiver computes SHA-256 of the reconstructed plaintext and compares it to the hash in `META`. A mismatch raises an error before the file is written to its final path.

The partial file is written to `{destination}.hermod_part` during transfer and renamed atomically on successful verification.

---

## NAT traversal and ICE

Hermod implements a subset of ICE (Interactive Connectivity Establishment) to connect peers that are behind NAT routers.

### Candidate types

| Type | How gathered | Priority |
|---|---|---|
| `host` | Local interface IP (via UDP probe to `8.8.8.8` to find the default-route IP) | 100 |
| `srflx` (server-reflexive) | STUN query to public STUN servers | 200 |

Loopback (`127.0.0.1`) is included only when no other address is found — for example in offline or pure-container environments. Including loopback alongside a real LAN IP would produce two candidates pointing to the same listener and cause a split-connection race.

### STUN client

The STUN client (`network/stun.py`) implements RFC 5389 Binding Request/Response in pure Python using the standard library only.

- Queries multiple public STUN servers concurrently.
- Returns the first valid `XOR-MAPPED-ADDRESS` response.
- `stun_timeout=0.0` disables STUN entirely (used in tests for speed).

### Connectivity establishment

`ice_connect(listener, peer_candidates, probe_delay)`:

1. Starts a background TCP `accept()` task on the local listener.
2. Fires outbound TCP connection probes to each peer candidate, sorted descending by priority (srflx before host).
3. Uses `asyncio.wait(FIRST_COMPLETED)` to race all tasks.
4. When one or more tasks complete in the same tick, the winner is picked in **insertion order** — `accept_task` first, then probes by priority — not raw set order. This deterministic ordering ensures both peers agree on the same connection.

### Socket configuration

Sockets are configured with `SO_REUSEADDR` and `SO_REUSEPORT` so both peers can bind a listener and make outbound connections on the same local port — the core requirement for NAT hole punching.

---

## Transfer resumption

Partial downloads are saved with a `.hermod_part` extension. The `HELLO` frame includes a `resume_offset` field for negotiating where to restart.

> **Note:** The session layer does not yet negotiate resume offsets. The scaffolding (`ChunkedFileReader`, `PartFileWriter`) is in place but the end-to-end resume flow is not active. This is tracked as a known limitation.

When resumption is active, each resumed segment must use a fresh sub-key derived from the original `Session_Key`. See [`crypto.md — Resume sub-key derivation`](crypto.md#resume-sub-key-derivation) for the key derivation scheme.

---

## Signal handling and graceful shutdown

### Client

On SIGINT or SIGTERM, the client:

1. Sends a `ABORT` P2P frame to the peer.
2. Flushes write buffers.
3. Closes the `.hermod_part` file safely (the partial file is preserved for future resumption).

### Server

On SIGINT or SIGTERM, the server:

1. Stops accepting new WebSocket connections.
2. Sends WebSocket close code `1001 Going Away` to all connected clients.
3. Executes an SQLite WAL checkpoint (`PRAGMA wal_checkpoint(FULL)`).
4. Closes all file handles to prevent database corruption.

---

## Server storage

The signaling server uses SQLite.

| Stored | Not stored |
|---|---|
| `channel_id` (integer) | Transfer code passphrase |
| Opaque encrypted blobs | Payload type or size |
| Creation timestamp | IP addresses of peers |

A background TTL sweep deletes channels older than `--ttl` seconds (default 3600). Deletion uses `ON DELETE CASCADE` so all blobs in a channel are removed together.

In-memory SQLite (`:memory:`) is used for tests. WAL mode is used in production.

---

## IPv6 support

All listen-address fields accept IPv6 notation:

```
[::1]:8786
[2001:db8::1]:9000
```

`parse_listen(s)` strips brackets from IPv6 addresses before passing them to `socket.connect`. `format_listen(host, port)` adds brackets back when the host contains a colon (RFC 3986 URI format).
