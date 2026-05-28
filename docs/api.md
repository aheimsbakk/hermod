# API reference

Internal package API for contributors and embedders. All packages are under `github.com/hermod/hermod`.

---

## `internal/crypto`

Password-authenticated key exchange, symmetric encryption, and display utilities.

### CPace

```go
func CPaceInit(password string, channelID uint16, role string) (*CPaceSession, []byte, error)
```
Initialises a CPace session. Returns the session state and a public message (elliptic curve point, uncompressed) to send to the peer. `role` must be `"sender"` or `"receiver"` — it is mixed into the hash-to-curve input as domain separation.

```go
func (s *CPaceSession) CPaceFinish(peerPubMsg []byte) ([]byte, error)
```
Completes the handshake using the peer's public message. Returns a 32-byte shared key. Returns an error if `peerPubMsg` is not a valid P-256 point.

### Symmetric encryption

```go
func Seal(key, plaintext []byte) ([]byte, error)
```
Encrypts `plaintext` with AES-256-GCM. Generates a random 12-byte nonce, prepends it to the ciphertext. `key` must be 32 bytes.

```go
func Open(key, ciphertext []byte) ([]byte, error)
```
Decrypts and authenticates ciphertext produced by `Seal`. Returns an error if authentication fails.

### Transfer codes

```go
func GenerateTransferCode(wordCount int) (channelID uint16, code string, err error)
```
Generates a random transfer code. `wordCount` controls the passphrase length (minimum 2). Returns the numeric channel ID and the full code string (e.g. `"3-apple-banana-cherry"`).

```go
func ParseTransferCode(code string) (channelID uint16, words []string, err error)
```
Parses a transfer code. Returns the channel ID and the passphrase words.

### Display

```go
func SASFromBytes(b []byte) []string
```
Derives a Short Authentication String word list from raw bytes.

```go
func SASString(words []string) string
```
Formats words as a space-separated string.

```go
func Identicon(b []byte) string
```
Returns a small ASCII art identicon derived from `b`.

---

## `internal/network`

UDP multiplexing, NAT hole punching, QUIC transport, and signaling client.

### UDP

```go
func BindUDP(addr string) (net.PacketConn, error)
```
Binds a UDP socket. Sets `SO_REUSEADDR` and `SO_REUSEPORT` on Linux/macOS. Use `":0"` for an OS-assigned port.

```go
func LocalUDPAddr(conn net.PacketConn) (*net.UDPAddr, error)
```
Returns the local address of a bound UDP connection.

### Packet mux

```go
func NewPacketMux(conn net.PacketConn) *packetMux
```
Wraps a UDP socket and demultiplexes incoming packets into two channels: one for probe packets (first byte `0x01`) and one for QUIC packets (everything else). The returned `*packetMux` is passed to `HolePunch`, `DialQUIC`, and `ListenQUIC`.

```go
func (m *packetMux) Close()
func (m *packetMux) LocalAddr() net.Addr
```

### Hole punching

```go
type HolePunchResult struct {
    PeerAddr *net.UDPAddr
}

func HolePunch(ctx context.Context, mux *packetMux, candidates []*net.UDPAddr) (*HolePunchResult, error)
```
Sends probe packets to all candidate addresses concurrently until one replies. Returns the first address that responds. Cancelled by `ctx` timeout.

```go
func ParseCandidates(endpoints []string) ([]*net.UDPAddr, error)
```
Parses a slice of `"host:port"` strings into UDP addresses.

### QUIC

```go
func DialQUIC(ctx context.Context, mux *packetMux, peerAddr *net.UDPAddr, baseTLS *tls.Config, peerCertHash string) (*quic.Conn, error)
```
Dials a QUIC connection to `peerAddr` over the muxed UDP socket. Pins the peer certificate to `peerCertHash` (64-char hex SHA-256).

```go
func ListenQUIC(mux *packetMux, cert tls.Certificate, baseTLS *tls.Config, peerCertHash string) (*quic.Listener, error)
```
Listens for incoming QUIC connections over the muxed UDP socket. Uses `cert` as the server certificate. Pins the connecting client's certificate to `peerCertHash`.

```go
func CertFingerprint(certDER []byte) string
```
Returns the SHA-256 fingerprint of a DER-encoded certificate as a 64-character hex string.

### Endpoint bundle

```go
type EndpointBundle struct {
    LocalEndpoints  []string
    PublicEndpoint  string
    CertFingerprint string
    RequireVerify   bool
}

func EncodeEndpointBundle(b EndpointBundle) ([]byte, error)
func DecodeEndpointBundle(data []byte) (EndpointBundle, error)
```
JSON serialisation for the encrypted endpoint exchange. `RequireVerify` is `true` when the local peer was started with `--verify`. After decoding the peer bundle, the caller merges the flags: `verify = local || peer.RequireVerify`.

```go
func LocalEndpoints(localPort int) ([]string, error)
```
Returns all non-loopback local IP addresses formatted as `"host:port"` strings.

### CPace message

```go
type CPaceMsg struct {
    PubMsg []byte
}

func EncodeCPaceMsg(m CPaceMsg) ([]byte, error)
func DecodeCPaceMsg(data []byte) (CPaceMsg, error)
```
JSON serialisation for the CPace public message exchanged via the signaling relay.

### Signaling client

```go
func DialSignaling(serverURL, pinnedFingerprint string) (*SignalingClient, error)
```
Opens a WebSocket connection to the signaling server. If `pinnedFingerprint` is non-empty, the server's certificate must match.

```go
func (c *SignalingClient) Close() error
func (c *SignalingClient) Allocate(channelID uint16) (publicIP string, err error)
func (c *SignalingClient) Join(channelID uint16) (publicIP string, err error)
func (c *SignalingClient) SendBlob(channelID uint16, blob []byte) error
func (c *SignalingClient) RecvBlob() ([]byte, error)
func (c *SignalingClient) WaitReady() error
```

```go
func FetchServerFingerprint(serverURL string) (string, error)
```
Connects without cert pinning and returns the server's certificate fingerprint. Used by `hermod trust`.

---

## `internal/server`

Signaling server and in-memory store.

### Server

```go
func NewServer(store SignalingStore, rl *RateLimiter, channelTTL time.Duration, log *slog.Logger) *Server
```
Creates a new signaling server. `store` holds channel state. `rl` enforces per-IP rate limits. `channelTTL` is how long an allocated channel lives before the server expires it.

```go
func (s *Server) ListenAndServe(ctx context.Context, addr string, tlsCfg *tls.Config) error
```
Starts the HTTPS/WebSocket server. Blocks until `ctx` is cancelled.

### Store

```go
type SignalingStore interface {
    AllocateChannel(id uint16, ttl time.Duration) error
    StoreBlob(id uint16, sender bool, blob []byte) error
    FetchBlob(id uint16, sender bool) ([]byte, error)
    RecordFailure(id uint16) (int, error)
    DeleteChannel(id uint16) error
    PurgeExpired() error
    Close() error
}

func NewMemoryStore() *MemoryStore
```
`MemoryStore` is the default store. It holds all state in memory and is suitable for single-process deployments.

### GC

```go
func RunGC(ctx context.Context, store SignalingStore, interval time.Duration)
```
Starts a background goroutine that calls `store.PurgeExpired()` every `interval`. Stops when `ctx` is cancelled.

### Rate limiter

```go
func NewRateLimiter(rate, burst float64) *RateLimiter
func (rl *RateLimiter) Allow(addr string) bool
```
Token-bucket rate limiter keyed by `/32` IPv4 prefix or `/64` IPv6 prefix. `addr` is a `"host:port"` or bare IP string.

---

## `internal/config`

Config file, TLS certificate, and path helpers.

```go
func Default() *Config
func Load() (*Config, error)
func Save(cfg *Config) error
```
Loads from `~/.config/hermod/config.yaml`. `Default()` returns a zero-value config without reading disk.

```go
func GenerateServerCert(cfg *Config) error
```
Generates a self-signed RSA-2048 certificate and stores the PEM in `cfg`. Does not write to disk — call `Save` after.

```go
func LoadServerTLSCert(cfg *Config) (tls.Certificate, error)
```
Parses the PEM certificate and key stored in `cfg`.

```go
func BuildTLSConfig(cfg *Config) *tls.Config
```
Returns a base `*tls.Config` with TLS 1.3 minimum version and the ALPN protocol `hermod/1`.

```go
func ServerFingerprint(cfg *Config) (string, error)
```
Returns the SHA-256 fingerprint of the server certificate stored in `cfg`.

```go
func Path() string   // full path to config.yaml
func Dir() string    // config directory
func LogPath() string
```

---

## `pkg/transfer`

Payload classification, metadata, and integrity verification.

```go
type Kind string

const (
    KindFile Kind = "file"
    KindText Kind = "text"
)

type Metadata struct {
    Kind   Kind   `json:"kind"`
    Name   string `json:"name,omitempty"`
    Size   int64  `json:"size"`
    SHA256 string `json:"sha256"`
}
```

```go
func ClassifyInput(arg string, isStdinPiped bool) (Kind, string, error)
```
Returns whether `arg` is a file path or a text snippet. Returns `KindText` when `isStdinPiped` is true and `arg` is empty.

```go
func HashFile(path string) (hash string, size int64, err error)
func HashBytes(data []byte) string
```
Compute the hex-encoded SHA-256 of a file or byte slice.

```go
func EncodeMetadata(m *Metadata) ([]byte, error)
func DecodeMetadata(data []byte) (*Metadata, error)
```

```go
func VerifyStream(r io.Reader, w io.Writer, expected string) error
```
Reads from `r`, writes to `w`, and verifies the SHA-256 of all bytes read equals `expected`. Returns an error if the hash does not match. The caller should discard `w`'s output on error.

```go
func SafeDestinationPath(dir, name string) string
```
Returns a safe output path under `dir` for a file named `name`. Strips directory components and appends a numeric suffix if the file already exists.

```go
func TempPath(dest string) string
```
Returns a `.tmp`-suffixed path alongside `dest`, used while writing before the integrity check passes.
