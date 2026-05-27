# Hermod: Architecture Blueprint

## 1. System Overview

The application is named after Hermod, the messenger of the gods in Norse mythology, recognized as the primary courier of the Æsir and best known for his journey to the underworld (Hel) to negotiate the return of the god Baldr [Source: Hermod, Store norske leksikon, 2024, https://snl.no/Hermod_-_norr%C3%B8n_mytologi].

Hermod is a secure, peer-to-peer (P2P) file and text transfer application written in Go. The architecture relies on a centralized signaling and NAT punch-through helper server to establish connections, while enforcing strict P2P data transmission. The server facilitates initial rendezvous and cryptographic key exchange but never handles or routes the actual payload. All P2P data transport is executed via the QUIC protocol over UDP [Source: RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport, IETF, 2021, https://datatracker.ietf.org/doc/html/rfc9000].

## 2. Component Architecture

* **Hermod Client (`tx` / `rx`)**: A compiled Go binary executing on the sender and receiver machines. It handles file I/O, cryptographic operations, local UDP network binding, and direct P2P connection establishment via QUIC.
* **Hermod Signaling Server (`serve`)**: A lightweight Go service responsible for the state management of pending transfers. It acts as a mailbox for connection intent, routes encrypted handshake messages between peers, and provides IP discovery (STUN-like functionality) for NAT traversal.
* **Signaling Channel**: A WebSocket connection established over TLS 1.3 between the clients and the server. This channel strictly adheres to the global cryptographic parameters defined in the client and server configurations.
* **P2P Channel**: A direct UDP connection established between clients via NAT hole punching, secured by TLS 1.3 integrated directly into the QUIC layer [Source: RFC 9001 Using TLS to Secure QUIC, IETF, 2021, https://datatracker.ietf.org/doc/html/rfc9001].

## 3. Command Line Interface (CLI)

The CLI resolves configuration based on a strict hierarchy: CLI Flags > Environment Variables > `config.yaml` > Application Defaults.

```bash
# Start the signaling and NAT helper service
hermod serve --listen 0.0.0.0:443 --db /var/lib/hermod/signaling.db --ttl 3600

# Fetch and pin the public certificate of a specific server
hermod trust my-relay.local:8443

# Send a file or text (explicit paths or stdin via auto-detection)
hermod tx /path/to/document.pdf
echo "Secret text" | hermod tx -

# Receive a payload
hermod rx 7-rapid-blue-fox --destination /secure/folder/

```

## 4. Cryptographic Design

The security model assumes the signaling server is untrusted. End-to-end encryption is established via a hybrid approach utilizing classical PAKE and standard TLS 1.3 cipher suites.

* **Transfer Code Allocation**: A cryptographically secure random code is generated (e.g., `7-rapid-blue-fox`). The integer identifies the signaling channel. The string acts as the shared secret for classical authentication.
* **Classical Authentication (PAKE)**: Clients execute a classical SPAKE2 protocol via the signaling server to prevent offline dictionary attacks and yield a shared classical secret ($K_{classical}$) [Source: RFC 9382 The SPAKE2+ Password-Authenticated Key Exchange (PAKE) Protocol, IETF, 2023, https://datatracker.ietf.org/doc/html/rfc9382].
* **Signaling Encryption**: Network endpoint candidates for NAT traversal are encrypted using AES-256-GCM or ChaCha20-Poly1305 keyed by $K_{classical}$ before transiting the relay server.
* **Transport Layer Security (TLS 1.3)**: Upon successful UDP hole punching, a QUIC connection is initialized. The protocol natively performs a TLS 1.3 handshake to derive the session keys and establish forward secrecy [Source: RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3, IETF, 2018, https://datatracker.ietf.org/doc/html/rfc8446]. The application defaults to the hybrid post-quantum key exchange mechanism `X25519MLKEM768` [Source: Go 1.24 Release Notes, The Go Programming Language, 2025, https://go.dev/doc/go1.24].
* **Cipher Configuration and Initialization**: Cryptographic parameters are managed via `config.yaml`. During application startup, the configuration parser verifies the existence of the `tls_configuration` block. If omitted or missing, the application automatically populates the file with the hardcoded secure defaults and flushes the changes to disk. This ensures operational transparency for the user.

```yaml
# Auto-populated default structure in config.yaml upon first execution
tls_configuration:
  prefer_curves:
    - X25519MLKEM768
    - X25519
    - CurveP256
  cipher_suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
```

## 5. Network Protocol and NAT Traversal

Data transmission is constrained to the UDP-based P2P channel to maximize NAT traversal success rates.

* **Endpoint Discovery**: The `serve` component inspects incoming connections to determine public IP addresses (Server-Reflexive addresses).
* **Socket Multiplexing**: The client binds a single local UDP socket using OS-level `SO_REUSEADDR` and `SO_REUSEPORT` flags. This socket handles outbound STUN probes, signaling interactions (if UDP-based), and the final QUIC connection.
* **UDP Hole Punching**: Both peers simultaneously transmit UDP datagrams to each other's public and local endpoints. The stateless nature of UDP allows outward datagrams to establish port mappings in the respective NAT gateways, permitting incoming packets from the peer [Source: RFC 5128 State of Peer-to-Peer (P2P) Communication across Network Address Translators (NATs), IETF, 2008, [https://datatracker.ietf.org/doc/html/rfc5128](https://datatracker.ietf.org/doc/html/rfc5128)].
* **Asymmetric Connectivity**: To resolve connection initialization conflicts over the punched UDP hole, the sender consistently operates as the QUIC client (initiator) and the receiver as the QUIC server (listener).

## 6. Execution Flow

1. **Initialization**: The sender executes `hermod tx <file>`. The client generates a random transfer code and connects to `hermod serve`.
2. **Allocation**: The sender allocates a channel ID on the server.
3. **Connection**: The receiver executes `hermod rx <code>` and connects to the signaling channel.
4. **Handshake**: Sender and receiver complete the SPAKE2 exchange over the relay to derive $K_{classical}$.
5. **Endpoint Exchange**: Clients encrypt their local and public UDP endpoints with $K_{classical}$ and exchange them via the relay.
6. **P2P Establishment**: Clients execute concurrent UDP hole punching.
7. **QUIC Upgrade**: Upon socket availability, the QUIC TLS 1.3 handshake is executed over the direct UDP link.
8. **Data Transfer**: The signaling channel is terminated. Payload metadata and bytes are written to bidirectional QUIC streams. The receiver streams the payload into a temporary file (filename.hermod_tmp).
9. **Verification**: The receiver reads the stream to completion and verifies the cryptographic hash (if applicable). Upon successful validation, the temporary file is renamed to its final specified output name. If the connection drops prematurely or validation fails, the .hermod_tmp file is deleted.

## 7. Server Storage and Zero-Knowledge Properties

The signaling server operates strictly as an ephemeral, blind relay.

* **No Metadata**: The server cannot observe payload types, sizes, or file names.
* **Opaque Storage**: The database stores only channel IDs and encrypted binary blobs.
* **Time-To-Live (TTL)**: A background routine periodically executes `DELETE` statements on channels exceeding the TTL threshold (default 3600s).

## 8. DDoS Protection and Anti-Spam Mechanisms

* **Message Constraints**: Hard limits exist on signaling messages per channel to prevent relay saturation.
* **Rate Limiting**: Implementation of token bucket rate limiting per IP address. Client IPs are hashed with a daily rotating salt in memory to prevent tracking.

## 9. Technology Stack and Tooling

* **Language**: Go 1.22+
* **QUIC Implementation**: `github.com/quic-go/quic-go`
* **CLI Framework**: `github.com/spf13/cobra`
* **Configuration**: `github.com/yaml/go-yaml`
* **Terminal UI**: `github.com/schollz/progressbar/v3` (Thread-safe progress indication)
* **TTY Detection**: `github.com/mattn/go-isatty` (POSIX-compliant terminal detection)
* **Server Database**: `gitlab.com/cznic/sqlite` (CGO-free SQLite implementation)

## 10. Transport Layer Security (TLS) and Trust Model

* **Unified TLS Configuration**: The application enforces a singular `tls.Config` generation mechanism. The cryptographic preferences defined in `config.yaml` (defaulting to the hybrid post-quantum `X25519MLKEM768` exchange) are injected identically into both the HTTP/WebSocket client-server transport and the QUIC P2P transport.
* **Server-Side Auto-Generation**: `hermod serve` automatically generates a self-signed X.509 certificate on first execution. The PEM certificate and private key are persisted as strings directly inside `~/.config/hermod/config.yaml`.
* **Client-Side Trust Store**: Maps server URLs to SHA-256 public certificate fingerprints in the `trusted_servers` section of `config.yaml`.
* **Certificate Pinning Enforcement**: The client bypasses standard CA validation, explicitly verifying that the presented certificate's SHA-256 fingerprint matches the pinned hash.

## 11. P2P Transport Protocol

The application relies entirely on QUIC for framing, multiplexing, ordered delivery, and congestion control.

* **Stream Segregation**: The sender opens a QUIC stream for metadata (filename, size, SHA-256 hash) and a subsequent stream for the raw payload.
* **No Application-Layer Framing**: Files are copied directly from the OS file descriptor (via `io.Reader`) into the QUIC stream (`io.Writer`). Encryption is handled transparently by the QUIC TLS 1.3 layer.

## 12. Software Architecture: Interfaces and Injection

The Go implementation utilizes structural typing and interfaces to maintain modularity.

* **Storage Interface**: A `SignalingStore` interface defines the required methods for the server, allowing the SQLite implementation to be swapped for in-memory stores during testing.
* **Transport Abstraction**: Network operations accept standard `net.Conn` and `net.PacketConn` interfaces.

## 13. Payload Processing and Stream Handling

* **Raw Stream Transport (No Validation)**: The sender executes no UTF-8 heuristic validation, content sniffing, or teletype inspection. Piped data via `stdin` is treated strictly as an opaque byte stream.
* **Type Assignment on Send**: Resolves payload metadata from the positional argument:
    * Argument `-` or piped `os.Stdin` → Transmitted as `kind="stream"`.
    * Existing file path → Transmitted as `kind="file"` with the original filename.
    * Arbitrary string → Transmitted as `kind="text"`.
* **Context-Aware Routing on Receive**:
    * `--destination` explicitly provided → Saves the incoming stream or file to the specified path.
    * No destination, `stdout` is redirected (piped) → Streams all bytes directly to `os.Stdout`, ignoring payload `kind`.
    * No destination, `stdout` is an interactive terminal:
        * Payload `kind="text"` or `kind="stream"` → Prints all payload bytes directly to the terminal via `stdout`. No blocking mechanism is applied.
        * Payload `kind="file"` → Blocks writing to `stdout` to prevent terminal state corruption. Saves the payload locally to disk using the transmitted filename.

## 14. Out-of-Band Verification (MitM Protection)

* **The `--verify` Flag**: Pauses transmission immediately after the QUIC connection is established.
* **Key Material Extraction**: Extracts cryptographic material from the QUIC session using TLS exporter keying material bound to a specific context string.
* **SAS Generation**: Generates a numeric or word-based Short Authentication String (SAS) utilizing the primary segment of the exported key material.
* **Visual Fingerprint (Identicon)**: Generates a symmetric, framed 8x8 terminal grid utilizing 32 bits (4 bytes) of the exported key material to provide a secondary visual verification channel.
    * **Geometry and Aspect Ratio**: The component utilizes an external bounding box measuring 20 characters in width and 10 characters in height. Logical bits are rendered as double-width blocks (e.g., `U+2588 U+2588` for bit 1, and `U+2591 U+2591` for bit 0). This strict 2:1 character ratio ensures the bounding box renders as a perfect visual square within standard terminal environments.
    * **Entropy and Symmetry**: The internal 8x8 block grid employs vertical symmetry. The 32 left-most logical blocks map sequentially to the 32 exported bits, maintaining a cryptographic entropy of $2^{32}$. The right-most 32 blocks mirror the left side to optimize the pattern for rapid human cognitive processing.
    * **Border Elements**: The frame is rendered using standard single-line Unicode box-drawing characters (e.g., `U+2554`, `U+2550`, `U+2551`) with one character of horizontal padding separating the frame from the internal grid.
* **Verification Enforcement**: Requires explicit manual user confirmation of both the SAS sequence and the Visual Fingerprint match across both endpoints before QUIC data streams are unblocked.

## 15. File Streaming and Memory Management

* **Zero-Copy Optimizations**: Memory overhead is minimized by utilizing `io.Copy` to stream data directly from disk to the network interface in optimized chunk sizes dictated by the Go runtime and QUIC buffers.
* **Memory Footprint**: The application does not load complete files into RAM.

## 16. End-to-End File Integrity

* **Pre-computation**: The sender computes a SHA-256 hash of the entire plaintext file, transmitting the sum in the metadata stream.
* **Verification**: The receiver utilizes an `io.TeeReader` to compute the SHA-256 hash concurrently as the payload is written to disk, validating the sum upon stream completion.

## 17. User Interface and Feedback

* **Progress Indicators**: Renders dynamic, thread-safe progress bars, transfer speeds, and ETAs via `progressbar/v3`.
* **Context-Aware Degradation**: Utilizes `go-isatty` to perform strict TTY detection. Suppresses all UI rendering and gracefully degrades to a raw binary stream when standard output is piped or redirected, preventing corruption of the data stream.

## 18. Configuration and Environment Defaults

* **Collision Handling**: Automatically appends incrementing integers to existing filenames to prevent overwriting (e.g., `document(1).pdf`).

## 19. Project Structure

```text
hermod-p2p/
├── go.mod
├── go.sum
├── cmd/
│   └── hermod/
│       └── main.go         
├── internal/
│   ├── cli/                
│   ├── config/             
│   ├── crypto/             
│   ├── network/            
│   └── server/             
└── pkg/
    └── transfer/           

```

## 20. CLI Parameter Reference

**Command: `serve**`

* `--listen` (`-l`): Bind address (`host:port`). Default: `0.0.0.0:8786`.
* `--db` (`-d`): SQLite database path. Default: `~/.config/hermod/signaling.db`.
* `--ttl` (`-T`): TTL in seconds for channels. Default: `3600`.

**Command: `tx` | `send**`

* `[INPUT]`: File path, text string, or `-`.
* `--server` (`-s`): Signaling server URL. Default: `wss://localhost:8786`.
* `--verify` (`-v`): Enforce SAS verification.
* `--listen` (`-l`): Local UDP bind address. Default: `:0` (OS-assigned).

**Command: `rx` | `receive**`

* `[CODE]`: Transfer code.
* `--destination` (`-d`): Output directory/file path.
* `--server` (`-s`): Signaling server URL.
* `--verify` (`-v`): Enforce SAS verification.
* `--listen` (`-l`): Local UDP bind address. Default: `:0`.

## 21. Environment Variables

* `HERMOD_SERVER`: Maps to `--server`.
* `HERMOD_LISTEN`: Maps to `--listen`.
* `HERMOD_DB_PATH`: Maps to `--db`.
* `HERMOD_DEST_DIR`: Maps to `--destination`.

## 22. Persistent Configuration Management

* **Format**: YAML (`config.yaml`).
* **Location**: `~/.config/hermod/config.yaml` or `%APPDATA%\Hermod\config.yaml`.

## 23. Logging and Diagnostics

* **Implementation**: Utilizes Go's structured logging package `log/slog`.
* **Output**: Suppressed from stdout. Output is appended to a rolling log at `~/.local/state/hermod/app.log`.

## 24. Packaging and Distribution

* **Compilation**: Distributed as a statically linked binary.
* **Cross-Compilation**: The absence of CGO dependencies allows deterministic cross-compilation across Windows, macOS, and Linux targets natively via `GOOS` and `GOARCH` flags.

## 25. Signal Handling and Graceful Shutdown

* **Context Cancellation**: OS signals (`SIGINT`, `SIGTERM`) are captured using `os/signal` and propagated down the execution stack via `context.Context`.
* **Cleanup**: Triggers immediate closure of QUIC streams. The receiver unconditionally deletes any incomplete payload files (.hermod_tmp) from the local disk to prevent artifact accumulation. Server closes database handles cleanly to avoid WAL corruption.

## 26. Testing and Quality Assurance

* **Test Coverage Requirement**: The project mandates a minimum of 80% statement coverage. The build process must abort with an error code if the total coverage falls below this threshold. Coverage is calculated utilizing the standard command `go test -coverprofile=coverage.out ./...`.
* **Test Framework**: All testing executes via Go's native `testing` package. No external assertion libraries (e.g., `testify`) are utilized, maintaining standardized Go paradigms and minimizing dependencies.
* **Unit Testing**: Isolated testing of cryptographic state machines, payload classification, and NAT traversal candidate generation. Mock objects are implemented exclusively via interface substitution (e.g., passing a memory-backed `SignalingStore` instead of the SQLite implementation).
* **End-to-End (E2E) Testing**: E2E tests are implemented using `github.com/rogpeppe/go-internal/testscript` for declarative testing of the compiled CLI binaries.
* **E2E Execution Flow**:
    1. The test harness compiles a temporary `hermod` executable.
    2. A `testscript` routine starts `hermod serve` in the background, bound to a local network interface (`localhost`).
    3. The routine executes `hermod tx` with an automatically generated test file.
    4. The routine parses standard output (`stdout`) to extract the generated transfer code.
    5. The routine executes `hermod rx` concurrently.
    6. The test harness evaluates process exit codes and performs a SHA-256 hash comparison of the initial payload and the received payload to verify QUIC transport integrity and file I/O operations.
* **Concurrency Verification**: All tests are executed with the `-race` flag enabled (`go test -race ./...`) for deterministic detection of data races in asynchronous UDP operations and QUIC stream handling.