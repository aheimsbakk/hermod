# API reference

Internal package API for contributors and embedders. All packages are under `github.com/hermod/hermod`.

---

## `internal/cli`

CLI command implementations and shared transfer helpers.

### SAS verification

```go
func promptSASVerification(ctx context.Context, tlsState tls.ConnectionState, sasContext []byte) (bool, error)
```
Opens `/dev/tty` (or `CONIN$` on Windows), reads the user's SAS answer, and returns `true` if the user confirms (`y`/`Y`). The read is interruptible via `ctx`: if the context is cancelled (SIGINT, SIGTERM, or peer disconnect), the prompt exits immediately and returns `context.Canceled`.

```go
func promptSASVerificationFrom(ctx context.Context, tlsState tls.ConnectionState, r io.Reader, sasContext []byte) (bool, error)
```
Testable variant of `promptSASVerification` that reads from the given `io.Reader` instead of opening the TTY. The read is interruptible via `ctx` — it uses an internal goroutine with a channel select so the prompt does not hang on context cancellation.

```go
func performSASCoordinated(ctx context.Context, conn *quic.Conn, tlsState tls.ConnectionState, isSender bool, sasContext []byte) error
```
Runs the full SAS coordination protocol: opens `/dev/tty`, displays the SAS and identicon, reads user input, exchanges a 1-byte confirm/reject (`0x01`/`0x00`) over a dedicated QUIC stream with the peer, and returns `nil` only when both sides confirm. Closes the TTY when either `ctx` is cancelled or the QUIC connection drops, so the prompt does not block on disconnect.

```go
func performSASCoordinatedWith(ctx context.Context, conn sasStreamConn, tlsState tls.ConnectionState, isSender bool, reader io.Reader, sasContext []byte) error
```
Testable core of `performSASCoordinated`. If the prompt returns `context.Canceled`, it prints `"SAS verification cancelled by user, notifying peer..."`, sends `0x00` to the peer, and returns a cancellation error. When both sides cancel simultaneously, the error message reads `"SAS verification cancelled by both sides"`.

### Cancellation

```go
const cancelCodeUser quic.ApplicationErrorCode = 1
const cancelMsgSender   = "cancelled:sender"
const cancelMsgReceiver = "cancelled:receiver"
```
Error code and messages used when a user cancels a transfer (Ctrl+C / SIGTERM).

Both `tx` and `rx` watch `ctx.Done()` and call `quicConn.CloseWithError(cancelCodeUser, cancelMsg*)` as soon as the context is cancelled. This unblocks the peer's blocked stream read or write immediately. The SAS prompt also responds to context cancellation, so a Ctrl+C during verification shows a cancellation message and sends the signal to the peer.

```go
func cancelledByPeer(err error) error
```
Returns a user-facing error ("transfer cancelled by sender" or "transfer cancelled by receiver") when `err` wraps a `*quic.ApplicationError` with code `1`. Returns `nil` for any other error or `nil` input.

---

## `internal/crypto`

Password-authenticated key exchange, symmetric encryption, and display utilities.

### CPace

```go
func CPaceInit(password string, channelID uint16, role string) (*CPaceSession, []byte, error)
```
Initialises a CPace session. Returns the session state and a public message (elliptic curve point, uncompressed) to send to the peer. `role` must be `"sender"` or `"receiver"` — it is bound into the DST of the `P256_XMD:SHA-256_SSWU_RO_` hash-to-curve (RFC 9380) as domain separation.

```go
func (s *CPaceSession) CPaceFinish(peerPubMsg []byte) ([]byte, error)
```
Completes the handshake using the peer's public message. Returns a 32-byte shared key. Returns an error if `peerPubMsg` is not a valid P-256 point.

### Hybrid KEM (X25519 + ML-KEM-768)

```go
func GenerateX25519KeyPair() (*ecdh.PrivateKey, []byte, error)
```
Generates an ephemeral X25519 key pair. Returns the private key and the 32-byte public key.

```go
func ECDHX25519(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error)
```
Computes the X25519 ECDH shared secret. Returns 32 bytes.

```go
func NewX25519PubFromBytes(data []byte) (*ecdh.PublicKey, error)
```
Parses a 32-byte X25519 public key.

```go
type MLKEMReceiverKey struct {
    DecapKey *mlkem.DecapsulationKey768
    EncapKey *mlkem.EncapsulationKey768
}

func GenerateMLKEMReceiverKey() (*MLKEMReceiverKey, error)
```
Generates an ML-KEM-768 key pair for the receiver side. The receiver sends `EncapKeyBytes()` to the sender and keeps `DecapKey` for decapsulation.

```go
func (k *MLKEMReceiverKey) EncapKeyBytes() []byte
```
Returns the 1184-byte ML-KEM-768 encapsulation key.

```go
func NewEncapsulationKey768Bytes(data []byte) (*mlkem.EncapsulationKey768, error)
```
Parses a 1184-byte ML-KEM-768 encapsulation key received from a peer.

```go
func EncapsulateMLKEM(ek *mlkem.EncapsulationKey768) (sharedKey, ciphertext []byte)
```
Encapsulates a shared secret using the peer's encapsulation key. Returns the 32-byte shared key and the 1088-byte ciphertext.

```go
func DecapsulateMLKEM(dk *mlkem.DecapsulationKey768, ciphertext []byte) ([]byte, error)
```
Recovers the 32-byte shared secret from a KEM ciphertext.

```go
func DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM []byte) []byte
```
Derives the 32-byte hybrid blob key: `SHA-256(kClassical || ssX25519 || ssMLKEM)`. Combines CPace (P-256) + X25519 ECDH + ML-KEM-768 into a single key. Security is at least as strong as the strongest component.

### Symmetric encryption

```go
func Seal(key, plaintext []byte) ([]byte, error)
```
Encrypts `plaintext` with AES-256-GCM. Generates a random 12-byte nonce, prepends it to the ciphertext. `key` must be 32 bytes.

```go
func SealAAD(key, aad, plaintext []byte) ([]byte, error)
```
Like `Seal` but binds `aad` as additional authenticated data. Used for endpoint bundle encryption with the channel ID as AAD.

```go
func Open(key, ciphertext []byte) ([]byte, error)
```
Decrypts and authenticates ciphertext produced by `Seal`. Returns an error if authentication fails.

```go
func OpenAAD(key, aad, blob []byte) ([]byte, error)
```
Like `Open` but requires the same `aad` used during encryption.

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
Derives a Short Authentication String word list (6 words) from raw bytes (32 bytes).
Words are drawn from the EFF Short Wordlist 1 (1296 entries) using rejection
sampling. The output is deterministic for the same input.

```go
func Identicon(b []byte) (string, error)
```
Returns a small ASCII art identicon derived from `b`. Returns an error if `b` is shorter than 16 bytes (H-03).

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
Wraps a UDP socket and demultiplexes incoming packets into two channels: one for probe packets (first byte `0x01`) and one for QUIC packets (everything else). The returned `*packetMux` is passed to `HolePunch` and `RaceQUIC`.

```go
func (m *packetMux) Close()
func (m *packetMux) LocalAddr() net.Addr
```

### Hole punching

```go
type HolePunchResult struct {
    PeerAddr *net.UDPAddr
}

func HolePunch(ctx context.Context, mux *packetMux, candidates []*net.UDPAddr, probeNonce [32]byte) (*HolePunchResult, error)
```
Sends 8-byte probe packets (marker byte + 7 hash bytes) to all candidate addresses concurrently until one replies. `probeNonce` is a 32-byte SHA-256 hash derived from the hybrid blob key (CPace + X25519 + ML-KEM-768); bytes [0:7] form the probe payload and bytes [8:15] form the ack payload, giving 64 bits of entropy per packet. Returns the first address that responds. Cancelled by `ctx` timeout (default 10 s).

```go
func HolePunchDual(ctx context.Context, mux *packetMux, candidatesV4, candidatesV6 []*net.UDPAddr, probeNonce [32]byte) (*HolePunchResult, error)
```
Two-phase NAT hole punching: IPv6 first (5 s timeout), then IPv4 fallback (remaining ctx timeout). Pass an empty slice for a phase to skip it entirely (used when `-4` or `-6` flag enforces a single protocol).

```go
func ParseCandidates(endpoints []string) ([]*net.UDPAddr, error)
```
Parses a slice of `"host:port"` strings into UDP addresses.

```go
type IPFamily int
const (
    IPFamilyAny IPFamily = iota
    IPFamilyV4
    IPFamilyV6
)
```

```go
func LocalEndpoints(localPort int, family IPFamily) (v4, v6 []string, error)
```
Returns non-loopback local UDP addresses split by address family. `IPFamilyV4` returns only IPv4, `IPFamilyV6` returns only IPv6, `IPFamilyAny` returns both.

```go
func SplitPublicIP(publicIP, port string) (v4, v6 string)
```
Classifies a bare IP string into a `"host:port"` string for the correct address family. Returns `v4` for IPv4 addresses, `v6` for IPv6 addresses. When `publicIP` is empty or not a valid IP, it is treated as a hostname and returned as `v4`.

### QUIC

```go
func RaceQUIC(ctx context.Context, mux *packetMux, peerAddr *net.UDPAddr, baseTLS *tls.Config, cert tls.Certificate, peerCertHash string) (*quic.Conn, error)
```
Races a QUIC dial and accept on the same muxed UDP socket. Returns the first connection that completes the handshake. Sets up mutual TLS (`RequireAnyClientCert`), pins the peer certificate to `peerCertHash`, and uses ALPN `hermod-p2p`. The losing goroutine is cancelled via context. This is the only QUIC connection function — both `tx` and `rx` use it.

```go
func CertFingerprint(certDER []byte) string
```
Returns the SHA-256 fingerprint of a DER-encoded certificate as a 64-character hex string.

### Endpoint bundle

```go
type EndpointBundle struct {
    LocalEndpointsV4 []string
    LocalEndpointsV6 []string
    PublicEndpointV4 string
    PublicEndpointV6 string
    CertFingerprint  string
    RequireVerify    bool
}

func EncodeEndpointBundle(b EndpointBundle) ([]byte, error)
func DecodeEndpointBundle(data []byte) (EndpointBundle, error)

func (b *EndpointBundle) CandidatesV4() []string
func (b *EndpointBundle) CandidatesV6() []string
```
JSON serialisation for the encrypted endpoint exchange. Endpoints are split by address family. `CandidatesV4` / `CandidatesV6` return the public endpoint first, then local endpoints, as a flat string slice. `RequireVerify` is `true` when the local peer was started with `--verify`. After decoding the peer bundle, the caller merges the flags: `verify = local || peer.RequireVerify`.

### Hybrid handshake blob serialisation

Fixed-length binary encoding for the hybrid KEM handshake (CPace + X25519 + ML-KEM-768) exchanged via the signaling relay.

```go
const CPacePointSize       = 65
const X25519PubSize        = 32
const MLKEMEncapKeySize    = 1184
const MLKEMCiphertextSize  = 1088
```

```go
func SenderHandshakeBlob(cpacePub, x25519Pub []byte) []byte
```
Encodes the sender's CPace point (65 bytes) and X25519 public key (32 bytes) into a 97-byte binary blob (blob 1).

```go
func ParseSenderHandshakeBlob(data []byte) (cpacePub, x25519Pub []byte, err error)
```
Extracts CPace point and X25519 public key from a sender handshake blob.

```go
func ReceiverHandshakeBlob(cpacePub, x25519Pub, mlkemEncapKey []byte) []byte
```
Encodes the receiver's CPace point (65 bytes), X25519 public key (32 bytes), and ML-KEM-768 encapsulation key (1184 bytes) into a 1281-byte binary blob (blob 2).

```go
func ParseReceiverHandshakeBlob(data []byte) (cpacePub, x25519Pub, mlkemEncapKey []byte, err error)
```
Extracts CPace point, X25519 public key, and ML-KEM encapsulation key from a receiver handshake blob.

```go
func SenderBundleBlob(kemCt, encBundle []byte) []byte
```
Encodes the ML-KEM ciphertext (1088 bytes) followed by the AES-256-GCM encrypted endpoint bundle (blob 3).

```go
func ParseSenderBundleBlob(data []byte) (kemCt, encBundle []byte, err error)
```
Extracts KEM ciphertext and encrypted bundle from a sender bundle blob.

### Signaling client

```go
func DialSignaling(ctx context.Context, serverURL, pinnedFingerprint string) (*SignalingClient, error)
```
Opens a WebSocket connection to the signaling server. If `pinnedFingerprint` is non-empty, the server's certificate must match. The dial is cancelled when `ctx` is done; `HandshakeTimeout` is 15s.

```go
func DialSignalingWithFamily(ctx context.Context, serverURL, pinnedFingerprint string, family IPFamily) (*SignalingClient, error)
```
Like `DialSignaling` but restricts DNS and TCP to the given IP family (`IPFamilyAny`, `IPFamilyV4`, `IPFamilyV6`).

```go
func (c *SignalingClient) WithContext(ctx context.Context) *SignalingClient
```
Returns a copy of the client whose blocking `RecvBlob` and `WaitReady` calls are cancelled when `ctx` is done. Used by `tx` and `rx` to propagate SIGINT cancellation.

```go
func (c *SignalingClient) Close() error
func (c *SignalingClient) Allocate(channelID uint16) (publicV4, publicV6 string, err error)
func (c *SignalingClient) Join(channelID uint16) (publicV4, publicV6 string, err error)
func (c *SignalingClient) SendBlob(channelID uint16, blob []byte) error
func (c *SignalingClient) RecvBlob() ([]byte, error)
func (c *SignalingClient) WaitReady() error
```

```go
func FetchServerFingerprint(ctx context.Context, serverURL string, pinnedFingerprint string, family IPFamily) (string, error)
```
Fetches the server's TLS certificate via the HTTPS `/cert` endpoint, decodes the PEM block, and returns the SHA-256 fingerprint of the DER certificate. When `pinnedFingerprint` is non-empty, the certificate is verified against this value during the TLS handshake. When empty (TOFU mode), only use over a trusted network (VPN, LAN, or out-of-band fingerprint verification). `family` restricts DNS and TCP to the given IP family (`IPFamilyAny`, `IPFamilyV4`, `IPFamilyV6`). The request is cancelled when `ctx` is done. Used by `hermod trust`.

---

## `internal/server`

Signaling server and in-memory store.

### Server

```go
const DefaultMaxBlobsPerChannel = 10
const DefaultMaxCPaceFailures   = 3

func NewServer(store SignalingStore, certRL, wsRL, joinRL *RateLimiter, ttl time.Duration, maxBlobsPerChannel, maxCPaceFailures int, certDER []byte, logger *slog.Logger) *Server
```
Creates a new signaling server with separate rate limiters: `certRL` for the `/cert` HTTP endpoint, `wsRL` for WebSocket upgrades, and `joinRL` for join attempts (channel enumeration protection). `store` holds channel state. `ttl` is how long an allocated channel lives before the server expires it. `maxBlobsPerChannel` caps the total number of relayed blobs per channel; use `DefaultMaxBlobsPerChannel`. `maxCPaceFailures` caps CPace protocol violations before the channel is dropped and all peers are disconnected; use `DefaultMaxCPaceFailures`. `certDER` is the DER-encoded server certificate served via the `/cert` endpoint (pass nil to disable it).

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
func (rl *RateLimiter) Cleanup(maxAge time.Duration)
```
Token-bucket rate limiter keyed by IP prefix (`/32` IPv4, `/64` IPv6). The server uses separate instances for the `/cert` endpoint, WebSocket upgrades, and join attempts, so abuse of one endpoint does not starve the others. The bucket key is `hex(HMAC-SHA256(salt, prefix))` — raw IP addresses are never stored. A 32-byte cryptographic salt is generated at startup and replaced every UTC calendar day; all buckets are cleared on rotation to prevent cross-day tracking. `addr` is a `"host:port"` or bare IP string. `Cleanup` removes entries not seen within `maxAge`.

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
Generates a self-signed ECDSA P-256 certificate and stores the PEM in `cfg`. Does not write to disk — call `Save` after.

```go
func LoadServerTLSCert(cfg *Config) (tls.Certificate, error)
```
Parses the PEM certificate and key stored in `cfg`.

```go
func BuildTLSConfig(cfg *Config) *tls.Config
```
Returns a `*tls.Config` with TLS 1.3 minimum version and curve/cipher preferences from `cfg`. ALPN (`hermod-p2p`) is set separately by `RaceQUIC` in `internal/network`.

```go
func CertFingerprint(certDER []byte) string
```
Returns the SHA-256 fingerprint of a DER-encoded certificate as a 64-character lowercase hex string.

```go
func PinServer(cfg *Config, serverURL, fingerprint string)
```
Stores `fingerprint` in `cfg.TrustedServers[serverURL]`. Does not write to disk — call `Save` after.

```go
func SetDefaultServer(cfg *Config, serverURL string)
```
Sets `cfg.ServerURL` to `serverURL`. Does not write to disk — call `Save` after. Called automatically by `trust` and by `tx`/`rx` when `-s` is explicitly provided.

```go
func Path() string   // full path to config.yaml
```

---

## `pkg/transfer`

Payload classification, metadata, and integrity verification.

```go
type Kind string

const (
    KindFile   Kind = "file"
    KindText   Kind = "text"
    KindStream Kind = "stream"
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
Returns the payload kind and name for a given input argument. Returns `KindStream` when `arg` is `"-"` or when `arg` is empty and `isStdinPiped` is true. Returns `KindFile` when `arg` is a path to an existing file. Returns `KindText` otherwise.

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
Returns a `.hermod_tmp`-suffixed path alongside `dest`, used while writing before the integrity check passes. The temp file is removed on any write error, including context cancellation.
