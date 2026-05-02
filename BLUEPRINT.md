# Hermod: Architecture Blueprint

## 1. System Overview

Hermod is a secure, peer-to-peer (P2P) file and text transfer application. The architecture relies on a centralized signaling and NAT punch-through helper server to establish connections, while enforcing strict P2P data transmission. The server facilitates initial rendezvous and cryptographic key exchange but never handles or routes the actual payload.

## 2. Component Architecture

*   **Hermod Client (`tx` / `rx`)**: The local application executing on the sender and receiver machines. It handles file I/O, cryptographic operations, local network binding, and P2P connection establishment.
*   **Hermod Signaling Server (`serve`)**: A lightweight service responsible for state management of pending transfers. It acts as a mailbox for connection intent, routes encrypted handshake messages between peers, and provides IP discovery (STUN-like functionality) for NAT traversal.
*   **Signaling Channel**: A WebSocket or HTTPS long-polling connection between the clients and the server.
*   **P2P Channel**: A direct UDP or TCP connection established between clients via NAT hole punching.

## 3. Command Line Interface (CLI)

The CLI supports overriding the default signaling server to allow user-defined infrastructure, explicit trust management, and configuration resolution based on a strict hierarchy: CLI Flags > Environment Variables > `config.yaml` > Application Defaults.

```bash
# Start the signaling and NAT helper service on port 443 (requires elevated privileges)
hermod serve --port 443 --db /var/lib/hermod/signaling.db --ttl 3600

# Fetch and pin the public certificate of a specific server
hermod trust my-relay.local:8443

# Send a file or text (explicit flags or stdin)
hermod tx --file /path/to/document.pdf
echo "Secret text" | hermod tx --text -

# Receive a file or text
hermod rx 7-rapid-blue-fox --destination /secure/folder/
```

## 4. Cryptographic Design

The security model assumes the signaling server is untrusted and anticipates future "Store Now, Decrypt Later" (SNDL) attacks utilizing quantum computers. Hermod implements a Hybrid Key Exchange mechanism.

*   **Transfer Code Allocation**: A short, cryptographically secure random code is generated (e.g., `7-rapid-blue-fox`). The integer acts as the channel ID. The string acts as the shared secret for classical authentication.
*   **Layer 1: Classical Authentication (PAKE)**: Clients execute a classical PAKE protocol (e.g., CPace or SPAKE2 over Elliptic Curves) via the signaling server. This prevents offline dictionary attacks and yields a classical shared secret ($K_{classical}$).
*   **Signaling Encryption**: ICE candidates for NAT traversal are encrypted using $K_{classical}$ and exchanged via the signaling server.
*   **Layer 2: Post-Quantum Encapsulation (KEM)**: Upon P2P connection establishment, clients perform a secondary key exchange using a NIST-standardized PQ KEM (e.g., ML-KEM-768). The receiver encapsulates a PQ shared secret ($K_{pq}$) and returns the ciphertext. 
*   **Key Derivation (Composite Key)**: Both clients utilize a Key Derivation Function (HKDF-SHA256) to bind the secrets:
    `Session_Key = HKDF(Salt, K_classical || K_pq)`
*   **Symmetric Payload Encryption**: All data transmitted over the P2P connection is encrypted using AES-256-GCM or ChaCha20-Poly1305 keyed with the composite `Session_Key`.

## 5. Network Protocol and NAT Traversal

Data transmission is strictly constrained to the P2P channel.

*   **Endpoint Discovery**: The `serve` component inspects incoming connections to determine public IP addresses.
*   **ICE (Interactive Connectivity Establishment)**: Both peers independently gather candidates: host candidates from local interfaces (`socket_utils.get_local_addresses`) and an optional server-reflexive (srflx) candidate via STUN (`network/stun.py`, RFC 5389). STUN queries three public servers concurrently; the first valid XOR-MAPPED-ADDRESS wins. Passing `stun_timeout=0.0` skips STUN entirely (used in tests).
*   **Encrypted Exchange**: Candidate lists are serialised as `{"candidates": [{"type": "host"|"srflx", "ip": ..., "port": ...}, ...]}`, encrypted with $K_{classical}$ and exchanged via the signaling relay. A legacy fallback decodes the old `{"ip": ..., "port": ...}` single-endpoint format.
*   **Symmetric Connectivity Race**: Both sides bind a `PeerListener` and call `ice_connect()` simultaneously. `ice_connect` races an inbound TCP accept against outbound TCP probes to every peer candidate; the first successful connection wins and all remaining tasks are cancelled.

## 6. Execution Flow

1.  **Initialization**: Sender runs `hermod tx`. The client generates a random code and connects to `hermod serve`.
2.  **Allocation**: Sender allocates a channel ID on the server and waits.
3.  **Connection**: Receiver runs `hermod rx <code>`. The client connects to the corresponding channel on `hermod serve`.
4.  **Handshake**: Sender and receiver execute Layer 1 PAKE over the signaling channel.
5.  **Endpoint Exchange**: Clients encrypt and swap network endpoints.
6.  **P2P Establishment**: Clients perform NAT punch-through.
7.  **PQ Upgrade**: Clients execute Layer 2 ML-KEM over the direct P2P link.
8.  **Data Transfer**: The signaling channel is dropped. The payload is encrypted with the `Session_Key` and transmitted directly.
9.  **Verification**: The receiver decrypts the payload, verifies integrity, saves the data, and closes the connection.

## 7. Server Storage and Zero-Knowledge Properties

The signaling server acts strictly as an ephemeral, blind relay using SQLite.

*   **No Metadata:** The server is never informed about the payload type, size, or names.
*   **Encrypted Payloads:** The database stores only the `channel_id` and opaque binary blobs.
*   **Time-To-Live (TTL):** A background routine sweeps the database. Channels exceeding the `--ttl` threshold (default 3600s) are permanently deleted (`ON DELETE CASCADE`).

## 8. DDoS Protection and Anti-Spam Mechanisms

*   **Message Count Limits:** Hard limits on signaling messages per channel (e.g., max 4-6). Exceeding this drops the channel.
*   **Payload Size Limits:** Signaling messages are hard-limited (e.g., 4096 bytes).
*   **Token Bucket Rate Limiting:** Per IP Address and Per Channel rate limits. Client IPs are hashed with a daily rotating salt.

## 9. Technology Stack and Tooling

*   **Language**: Python 3.12+
*   **Package Manager**: `uv` (Astral).
*   **Testing**: `pytest` and `pytest-cov` (mandating strict test coverage).
*   **CLI Framework**: `Typer`.
*   **Cryptographic Dependencies**: 
    *   `cryptography`: Symmetrical encryption, hashing, X.509.
    *   `spake2`: Classical PAKE.
    *   `liboqs-python`: Post-Quantum KEM.
    *   `msgpack`: Binary serialization.

## 10. Transport Layer Security (TLS) and Trust Model

*   **Server-Side Auto-Generation**: `hermod serve` automatically generates a self-signed X.509 certificate if none exists.
*   **Client-Side Trust Store**: Maps server URLs to SHA-256 public certificate fingerprints in `~/.hermod/trust_store.json`.
*   **Certificate Pinning Enforcement**: The client rejects standard CA validation, explicitly verifying the SHA-256 fingerprint matches the pinned hash.

## 11. P2P Wire Protocol and Extensibility

The P2P connection utilizes a versioned, MessagePack frame-based "Header-Payload" protocol.

*   **Frame Structure**:
    1.  **Magic Bytes (2 bytes)**: Protocol identifier (`HD`).
    2.  **Version (1 byte)**: Protocol version (`0x01`).
    3.  **Header Length (4 bytes)**: MessagePack header size.
    4.  **Payload Length (8 bytes)**: Raw payload size.
    5.  **Header**: MessagePack encoded dictionary.
    6.  **Payload**: Raw encrypted binary data.
*   **Extensibility**: Clients strictly ignore unrecognized keys in the MessagePack header.

## 12. Software Architecture: Cryptographic Abstraction

Hermod employs the Strategy Design Pattern for Layer 1 authentication to isolate unmaintained dependencies.

*   **Interface Definition**: A strict `PAKEEngine` Protocol defines required methods.
*   **Adapter Pattern**: The `spake2` library is completely isolated within a concrete adapter class.

## 13. Payload Detection and Typing

*   **Auto-Detection**: Standard OS-level path resolution determines if input is a file or text.
*   **Explicit Overrides**: Users bypass auto-detection using `--file` (`-f`) or `--text` (`-t`).

## 14. Out-of-Band Verification (MitM Protection)

*   **The `--verify` Flag**: Pauses transmission immediately after `Session_Key` derivation.
*   **SAS Generation**: Derives a short, deterministic human-readable string (e.g., 6-character hex) via HKDF-SHA256 from the `Session_Key`. Requires manual user confirmation.

## 15. File Streaming and Memory Management

*   **Chunk Size:** Files are read and transmitted in fixed-size chunks (e.g., 1MB).
*   **Frame Encapsulation:** Each chunk is individually encrypted via AEAD and wrapped in a P2P frame containing a sequence number.
*   **EOF Signal:** The final frame contains `is_eof: true`.

## 16. End-to-End File Integrity

*   **Pre-computation:** Sender computes a SHA-256 hash of the entire plaintext file, included in the initial metadata frame.
*   **Verification:** Receiver computes the SHA-256 hash of the saved file and compares it to the metadata hash.

## 17. User Interface and Feedback

*   **UI Library:** Utilizes the `rich` Python library.
*   **Progress Indicators:** Displays dynamic progress bars, transfer speeds, and ETAs.

## 18. Network Socket Specifics for NAT Traversal

*   **Socket Multiplexing:** Local sockets used for signaling must be the same used for P2P connection.
*   **OS Flags:** Configured with `SO_REUSEADDR` and `SO_REUSEPORT`.

## 19. Configuration and Environment Defaults

*   **Collision Handling:** Automatically appends counters to existing filenames (e.g., `document(1).pdf`).

## 20. Project Structure and Modular Library Design

Hermod is a modular, reusable library utilizing the standard `src/` layout.

```text
hermod-p2p/
├── pyproject.toml
├── src/
│   └── hermod/
│       ├── __init__.py     # Public API
│       ├── core/           # State machine, streaming logic
│       ├── crypto/         # PAKE adapter, KEM, AEAD
│       ├── network/        # P2P wire protocol, sockets
│       ├── server/         # Signaling, SQLite
│       └── cli/            # Typer, Rich UI
└── tests/
```

## 21. Library Public API

The `__init__.py` exposes high-level, asynchronous classes (e.g., `P2PClient`, `FilePayload`) for third-party integration.

## 22. Command Line Interface (CLI) Reference and Parameters

**Global Options:**
*   `--verbosity`: Logging level (`debug`, `info`, `warning`, `error`, `critical`). Default: `info`.

**Command: `serve`**
| Parameter / Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--port` | `-p` | `443` | Server bind port. |
| `--host` | `-h` | `0.0.0.0` | Bind interface. |
| `--db` | `-d` | `~/.hermod/signaling.db` | SQLite database path. |
| `--ttl` | `-T` | `3600` | TTL in seconds for channels. |

**Command: `tx` | `send`**
| Parameter / Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--file` | `-f` | None | Path to local file. |
| `--text` | `-t` | None | Literal text. Accepts `-` for `stdin`. |
| `--server` | `-s` | `wss://localhost:4430` | Signaling server URL. |
| `--verify` | `-v` | `False` | Enforce SAS verification. |

**Command: `rx` | `receive`**
| Parameter / Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `code` | N/A | Req. | Transfer code. |
| `--destination`| `-d` | `./` | Output directory/file path. |
| `--server` | `-s` | `wss://localhost:4430` | Signaling server URL. |
| `--verify` | `-v` | `False` | Enforce SAS verification. |
| `--yes` | `-y` | `False` | Auto-accept prompts. |

**Command: `trust`**
| Parameter / Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | N/A | Req. | Hostname/IP format (`domain` or `domain:port`). |

## 23. Environment Variables

| Environment Variable | Maps to Flag |
| :--- | :--- |
| `HERMOD_SERVER` | `--server` |
| `HERMOD_PORT` | `--port` |
| `HERMOD_HOST` | `--host` |
| `HERMOD_DB_PATH` | `--db` |
| `HERMOD_DEST_DIR`| `--destination` |

## 24. Persistent Configuration Management

*   **Format:** `YAML` (`config.yaml`).
*   **Location:** `~/.config/hermod/config.yaml` or `%APPDATA%\Hermod\config.yaml`.

## 25. Logging and Diagnostics

*   **Log Levels:** Uses standard `logging.WARNING`, `logging.DEBUG`, etc.
*   **Output:** Suppressed from `stdout` unless `--verbosity debug` is active. Appended to rolling log `~/.local/state/hermod/app.log`. Sensitive data is strictly masked.

## 26. Transfer Resumability (Interruption Recovery)

*   **State Tracking:** Receiver maintains `.hermod_part`.
*   **Resume Handshake:** `PROTOCOL_HELLO` frame includes `resume_offset`. Cryptographic AEAD nonces factor in this offset to prevent reuse vulnerabilities.

## 27. Packaging and Distribution

*   **Distribution:** Distributed as an isolated CLI tool via `uvx hermod-p2p` and `pipx install hermod-p2p`.
*   **Standalone Binaries:** CI/CD pipeline compiles standalone executables via PyInstaller/Nuitka.

## 28. Signal Handling and Graceful Shutdown

*   **Asynchronous Registration:** Custom handlers for SIGINT and SIGTERM via `asyncio`.
*   **Client Exit:** Dispatches `PROTOCOL_ABORT` frame, flushes buffers, and closes `.hermod_part` safely.
*   **Server Exit:** Rejects new connections, sends `1001 Going Away` to existing clients, executes SQLite WAL checkpoint, and closes file handles to prevent corruption.

---

### Appendix A: Cryptographic and Serialization Specifications

*   **SPAKE2**: RFC 9382 (`[https://www.rfc-editor.org/rfc/rfc9382.txt](https://www.rfc-editor.org/rfc/rfc9382.txt)`)
*   **ML-KEM**: NIST FIPS 203 (`[https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)`)
*   **MessagePack**: Format Spec (`[https://github.com/msgpack/msgpack/blob/master/spec.md](https://github.com/msgpack/msgpack/blob/master/spec.md)`)