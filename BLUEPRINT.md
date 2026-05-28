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
hermod serve --listen 0.0.0.0:4376 --db /var/lib/hermod/signaling.db --ttl 600

# Fetch and pin the public certificate of a specific server
hermod trust my-relay.local:4376

# Send a file or text (explicit paths or stdin via auto-detection)
hermod tx /path/to/document.pdf
echo "Secret text" | hermod tx - --words 4

# Receive a payload
hermod rx 65535-rapid-blue-fox --destination /secure/folder/
```

## 4. Cryptographic Design

The security model assumes the signaling server is untrusted. End-to-end encryption is established via a hybrid approach utilizing classical PAKE and standard TLS 1.3 cipher suites, bound together via cryptographic commitment.

* **Transfer Code Allocation**: A cryptographically secure random code is generated (e.g., `65535-rapid-blue-fox`). The integer identifies the signaling channel and is generated as a random 16-bit integer between 0 and 65535. The string acts as the shared secret for classical authentication. The initiating client utilizes a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) to generate the transfer code. The code consists of the integer channel ID and a minimum of three words selected from a localized EFF Short Wordlist. The default length of the word list is 3 words, overridable via the `--words` CLI flag. This guarantees a minimum entropy of ~38 bits for the default configuration, rendering online guessing mathematically infeasible within the session parameters [Source: EFF Dice-Generated Passphrases, Electronic Frontier Foundation, 2016, https://www.eff.org/dice].
* **Classical Authentication (PAKE)**: Clients execute a classical CPace protocol via the signaling server to prevent offline dictionary attacks and yield a shared classical secret ($K_{classical}$) [Source: RFC 9496 The CPace Password-Authenticated Key Exchange (PAKE), IETF, 2023, https://datatracker.ietf.org/doc/html/rfc9496].
* **Signaling Encryption & Certificate Commitment**: Prior to UDP hole punching, clients generate ephemeral X.509 certificates. The SHA-256 fingerprint of the local certificate is bundled with the NAT traversal candidates. This payload is encrypted using AES-256-GCM keyed by $K_{classical}$ and exchanged via the relay.
* **Transport Layer Security (TLS 1.3)**: Upon successful UDP hole punching, a QUIC connection is initialized. The application defaults to the hybrid post-quantum key exchange mechanism `X25519MLKEM768` [Source: Go 1.24 Release Notes, The Go Programming Language, 2025, https://go.dev/doc/go1.24].
* **Machine Authentication (MitM Prevention)**: During the TLS 1.3 handshake, standard PKI verification is bypassed. The `VerifyPeerCertificate` callback strictly validates that the presented peer certificate's SHA-256 hash matches the cryptographic commitment received over the secure signaling channel. A mismatch instantly terminates the connection.

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

## 5. Signaling Server Architecture and State Management

* **State Storage**: The server utilizes an in-memory SQLite database to track active channel IDs, WebSocket file descriptors, and CPace handshake states.
* **Brute-Force Mitigation (Rate Limiting)**: The server implements a Token Bucket algorithm grouped per `/32` for IPv4 addresses and per `/64` for IPv6 network prefixes. The server strictly enforces a maximum of 3 failed CPace handshake attempts per channel ID. Upon the third failed cryptographic validation, the server immediately drops the WebSocket connections, invalidates the channel ID, and purges the associated state from the database.
* **Session Time-To-Live (TTL)**: Channels have an absolute maximum lifespan of 600 seconds (10 minutes) from the time of allocation. A background garbage collection routine sweeps the database every 60 seconds and permanently deletes expired channels to prevent resource exhaustion and narrow the attack window for online guessing.

## 6. Network Protocol and NAT Traversal

Data transmission is constrained to the UDP-based P2P channel to maximize NAT traversal success rates.

* **Endpoint Discovery**: The `serve` component inspects incoming connections to determine public IP addresses (Server-Reflexive addresses).
* **Socket Multiplexing**: The client binds a single local UDP socket using OS-level `SO_REUSEADDR` and `SO_REUSEPORT` flags. This socket is managed by an application-layer packet multiplexer that reads all incoming UDP datagrams. The multiplexer inspects the first byte of each payload to differentiate between QUIC packet headers and custom STUN/NAT probes, routing them to the QUIC library or the local traversal logic respectively.
* **UDP Hole Punching**: Both peers simultaneously transmit UDP datagrams to each other's public and local endpoints. The stateless nature of UDP allows outward datagrams to establish port mappings in the respective NAT gateways, permitting incoming packets from the peer [Source: RFC 5128 State of Peer-to-Peer (P2P) Communication across Network Address Translators (NATs), IETF, 2008, https://datatracker.ietf.org/doc/html/rfc5128].
* **Asymmetric Connectivity**: To resolve connection initialization conflicts over the punched UDP hole, the sender consistently operates as the QUIC client (initiator) and the receiver as the QUIC server (listener).

## 7. Execution Flow

1.  **Initialization**: The sender executes `hermod tx <input>`. The client generates a random transfer code and connects to `hermod serve`.
2.  **Allocation**: The sender allocates a channel ID on the server.
3.  **Connection**: The receiver executes `hermod rx <code>` and connects to the signaling channel.
4.  **Handshake**: Sender and receiver complete the CPace exchange over the relay to derive $K_{classical}$.
5.  **Endpoint and Certificate Exchange**: Clients generate ephemeral X.509 certificates. They bundle their local/public UDP endpoints and their certificate's SHA-256 fingerprint into a payload, encrypt it with $K_{classical}$, and exchange it via the relay.
6.  **P2P Establishment**: Clients execute concurrent UDP hole punching.
7.  **QUIC Upgrade & Authentication**: Upon socket availability, the QUIC TLS 1.3 handshake is executed. Clients mutually authenticate by verifying the peer's certificate hash against the decrypted fingerprint from Step 5.
8.  **Data Transfer**: The signaling channel is terminated. Payload metadata and bytes are written to bidirectional QUIC streams. The receiver streams the payload into a temporary file (`filename.hermod_tmp`).
9.  **Verification**: The receiver reads the stream to completion and verifies the payload cryptographic hash. Upon successful validation, the temporary file is renamed to its final specified output name. If the connection drops prematurely or validation fails, the `.hermod_tmp` file is deleted.

## 8. Server Storage and Zero-Knowledge Properties

The signaling server operates strictly as an ephemeral, blind relay.

* **No Metadata**: The server cannot observe payload types, sizes, or file names.
* **Opaque Storage**: The database stores only channel IDs and encrypted binary blobs.
* **Time-To-Live (TTL)**: A background routine periodically executes `DELETE` statements on channels exceeding the TTL threshold (default 600s).

## 9. DDoS Protection and Anti-Spam Mechanisms

* **Message Constraints**: Hard limits exist on signaling messages per channel to prevent relay saturation.
* **Rate Limiting**: Client IPs are hashed with a daily rotating salt in memory to prevent tracking.

## 10. Technology Stack and Tooling

* **Language**: Go 1.24+ (Required for native FIPS 203 ML-KEM support via `crypto/tls`) [Source: Go 1.24 Release Notes, The Go Programming Language, 2025, https://go.dev/doc/go1.24]
* **Cryptography (PAKE)**: `github.com/cloudflare/circl` (Provides RFC 9496 CPace implementation)
* **QUIC Implementation**: `github.com/quic-go/quic-go`
* **CLI Framework**: `github.com/spf13/cobra`
* **Configuration**: `github.com/yaml/go-yaml`
* **Terminal UI**: `github.com/schollz/progressbar/v3` (Thread-safe progress indication)
* **TTY Detection**: `github.com/mattn/go-isatty` (POSIX-compliant terminal detection)
* **Server Database**: On of:
  * `gitlab.com/cznic/sqlite` (CGO-free SQLite implementation)
  * `github.com/ncruces/go-sqlite3`

## 11. Transport Layer Security (TLS) and Trust Model

* **Unified TLS Configuration**: The application enforces a singular `tls.Config` generation mechanism. The cryptographic preferences defined in `config.yaml` (defaulting to the hybrid post-quantum `X25519MLKEM768` exchange) are injected identically into both the HTTP/WebSocket client-server transport and the QUIC P2P transport.
* **Server-Side Auto-Generation**: `hermod serve` automatically generates a self-signed X.509 certificate on first execution. The PEM certificate and private key are persisted as strings directly inside `~/.config/hermod/config.yaml`.
* **Client-Side Trust Store**: Maps server URLs to SHA-256 public certificate fingerprints in the `trusted_servers` section of `config.yaml`.
* **Certificate Pinning Enforcement**: The client bypasses standard CA validation, explicitly verifying that the presented certificate's SHA-256 fingerprint matches the pinned hash.

## 12. P2P Transport Protocol

The application relies entirely on QUIC for framing, multiplexing, ordered delivery, and congestion control.

* **Stream Segregation**: The sender opens a QUIC stream for metadata (filename, size, SHA-256 hash) and a subsequent stream for the raw payload.
* **No Application-Layer Framing**: Files are copied directly from the OS file descriptor (via `io.Reader`) into the QUIC stream (`io.Writer`). Encryption is handled transparently by the QUIC TLS 1.3 layer.

## 13. Software Architecture: Interfaces and Injection

The Go implementation utilizes structural typing and interfaces to maintain modularity.

* **Storage Interface**: A `SignalingStore` interface defines the required methods for the server, allowing the SQLite implementation to be swapped for in-memory stores during testing.
* **Transport Abstraction**: Network operations accept standard `net.Conn` and `net.PacketConn` interfaces.

## 14. Payload Processing and Stream Handling

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

## 15. Out-of-Band Verification (MitM Protection)

* **The `--verify` Flag**: Pauses transmission immediately after the QUIC connection is established.
* **Key Material Extraction**: Extracts 256 bits (32 bytes) of cryptographic material from the QUIC session using TLS 1.3 Keying Material Exporters bound to a specific context string.
* **SAS Generation**: Converts the extracted key material into a 6-to-8 word Short Authentication String (SAS) sequence using a standardized word list (e.g., PGP Word List) to reduce cognitive errors during manual cross-device comparison.
* **Visual Fingerprint (Identicon)**: Generates a symmetrical visual representation utilizing 128 bits (16 bytes) of the exported key material to provide a secondary visual verification channel.
    * **Geometry and Aspect Ratio**: The component utilizes a physical grid of 8 rows and 16 columns of characters.
    * **Entropy and Symmetry**: The algorithm reads the 128 bits sequentially, mapping each 2-bit segment to a specific Unicode Block Element character (`U+0020` for 00, `U+2580` for 01, `U+2584` for 10, `U+2588` for 11). The 8 left-most columns represent the 128 bits of entropy. The right-most 8 columns exactly mirror the left side to optimize the pattern for rapid human cognitive processing.
    * **Border Elements**: The frame is rendered using standard single-line Unicode box-drawing characters (e.g., `U+2554`, `U+2550`, `U+2551`).
* **Verification Enforcement**: Requires explicit manual user confirmation of both the SAS sequence and the Visual Fingerprint match across both endpoints before QUIC data streams are unblocked.

## 16. File Streaming and Memory Management

* **Zero-Copy Optimizations**: Memory overhead is minimized by utilizing `io.Copy` to stream data directly from disk to the network interface in optimized chunk sizes dictated by the Go runtime and QUIC buffers.
* **Memory Footprint**: The application does not load complete files into RAM.

## 17. End-to-End File Integrity

* **Pre-computation**: The sender computes a SHA-256 hash of the entire plaintext file, transmitting the sum in the metadata stream.
* **Verification**: The receiver utilizes an `io.TeeReader` to compute the SHA-256 hash concurrently as the payload is written to disk, validating the sum upon stream completion.

## 18. User Interface and Feedback

* **Progress Indicators**: Renders dynamic, thread-safe progress bars, transfer speeds, and ETAs via `progressbar/v3`.
* **Context-Aware Degradation**: Utilizes `go-isatty` to perform strict TTY detection. Suppresses all UI rendering and gracefully degrades to a raw binary stream when standard output is piped or redirected, preventing corruption of the data stream.

## 19. Configuration and Environment Defaults

* **Collision Handling**: Automatically appends incrementing integers to existing filenames to prevent overwriting (e.g., `document(1).pdf`).

## 20. Project Structure

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

## 21. CLI Parameter Reference

**Command: `serve`**

* `--listen` (`-l`): Bind address (`host:port`). Default: `0.0.0.0:4376`. Assigning port `0` triggers automatic ephemeral allocation.
* `--db` (`-d`): SQLite database path. Default: `~/.config/hermod/signaling.db`.
* `--ttl` (`-T`): TTL in seconds for channels. Default: `600`.
* `--rate-limit`: Token bucket permitted requests per second per IP prefix. Default: `5`.
* `--rate-burst`: Token bucket maximum burst capacity per IP prefix. Default: `15`.

**Command: `tx` | `send`**

* `[INPUT]`: File path, text string, or `-`.
* `--server` (`-s`): Signaling server URL. Default: `wss://localhost:4376`.
* `--words` (`-w`): Number of words for the transfer code shared secret. Default: `3`.
* `--verify` (`-v`): Enforce SAS verification.
* `--listen` (`-l`): Local UDP bind address. Default: `:0` (OS-assigned).

**Command: `rx` | `receive`**

* `[CODE]`: Transfer code.
* `--destination` (`-d`): Output directory/file path.
* `--server` (`-s`): Signaling server URL. Default: `wss://localhost:4376`.
* `--verify` (`-v`): Enforce SAS verification.
* `--listen` (`-l`): Local UDP bind address. Default: `:0`.

## 22. Environment Variables

* `HERMOD_SERVER`: Maps to `--server`.
* `HERMOD_LISTEN`: Maps to `--listen`.
* `HERMOD_DB_PATH`: Maps to `--db`.
* `HERMOD_DEST_DIR`: Maps to `--destination`.

## 23. Persistent Configuration Management

* **Format**: YAML (`config.yaml`).
* **Location**: `~/.config/hermod/config.yaml` or `%APPDATA%\Hermod\config.yaml`.

## 24. Logging and Diagnostics

* **Implementation**: Utilizes Go's structured logging package `log/slog`.
* **Output**: Suppressed from stdout. Output is appended to a rolling log at `~/.local/state/hermod/app.log`.

## 25. Packaging and Distribution

* **Compilation**: Distributed as a statically linked binary.
* **Cross-Compilation**: The absence of CGO dependencies allows deterministic cross-compilation across Windows, macOS, and Linux targets natively via `GOOS` and `GOARCH` flags.

## 26. Signal Handling and Graceful Shutdown

* **Context Cancellation**: OS signals (`SIGINT`, `SIGTERM`) are captured using `os/signal` and propagated down the execution stack via `context.Context`.
* **Cleanup**: Triggers immediate closure of QUIC streams. The receiver unconditionally deletes any incomplete payload files (.hermod_tmp) from the local disk to prevent artifact accumulation. Server closes database handles cleanly to avoid WAL corruption.

## 27. Testing and Quality Assurance

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