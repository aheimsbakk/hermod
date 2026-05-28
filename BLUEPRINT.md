# Hermod — Architecture Blueprint

## Component Map

```
cmd/hermod/main.go          — binary entry, cobra root
internal/cli/               — serve, trust, tx, rx commands
internal/config/            — YAML config load/save, TLS helpers, cert generation
internal/crypto/            — CPace PAKE (P-256), AES-256-GCM, SAS, identicon, transfer codes
internal/server/            — MemoryStore SignalingStore, WebSocket relay, rate limiter, TTL GC
internal/network/           — UDP mux (SO_REUSEADDR/REUSEPORT), hole punching, QUIC dial/listen, signaling client
pkg/transfer/               — payload metadata, stream classification, SHA-256 integrity
docs/                       — README, protocol.md, api.md
```

## Key Data Models

### Config (config.yaml)
```
server_url: wss://localhost:4376
listen: :0
tls_configuration:
  prefer_curves: [X25519MLKEM768, X25519, CurveP256]
  cipher_suites: [TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]
server_cert_pem: ""          # serve: auto-generated self-signed PEM
server_key_pem: ""           # serve: auto-generated private key PEM
trusted_servers:             # map[url]sha256fingerprint
  wss://example.com:4376: "aabb..."
```

### SignalingStore interface
- AllocateChannel(id uint16, ttl time.Duration) error
- StoreBlob(id uint16, sender bool, blob []byte) error
- FetchBlob(id uint16, sender bool) ([]byte, error)
- RecordFailure(id uint16) (attempts int, err error)
- DeleteChannel(id uint16) error
- PurgeExpired() error
- Close() error

Implementation: `MemoryStore` (default, in-process). SQLite removed.

### Metadata (JSON, 4-byte length-prefixed, QUIC stream 0)
```json
{"kind":"file","name":"doc.pdf","size":1234,"sha256":"hex"}
```
`kind`: `"file"` | `"text"`

### EndpointBundle (JSON, AES-256-GCM encrypted, relayed via signaling)
```json
{"local_endpoints":["192.168.1.5:51234"],"public_endpoint":"1.2.3.4:51234","cert_fingerprint":"hex"}
```

## Interfaces

- `SignalingStore` — storage backend (MemoryStore)
- `net.PacketConn` — UDP socket abstraction for mux
- `*quic.Conn` / `*quic.Listener` — QUIC transport (quic-go)
- `*packetMux` — demultiplexes probe packets and QUIC packets on a single UDP socket

## Protocol Flow

1. Sender allocates channel on signaling server → gets channel ID + public IP
2. Receiver joins channel → sender receives `ready`
3. CPace handshake over signaling relay (P-256, password = transfer code words)
4. Endpoint bundles exchanged (AES-256-GCM encrypted with CPace key)
5. UDP hole punch to peer candidates
6. QUIC connection (TLS 1.3, ephemeral RSA-2048 certs, fingerprint-pinned)
7. Stream 0: 4-byte-prefixed JSON metadata; Stream 1: raw payload bytes
8. Receiver verifies SHA-256; optional SAS out-of-band confirmation
