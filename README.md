# Hermod

Hermod transfers files and text directly between peers over an encrypted QUIC connection. No data passes through the signaling server — it only helps the two peers find each other.

The project is named after Hermod, the messenger god in Norse mythology — the primary courier of the Æsir, best known for riding to Hel to negotiate the return of Baldr.

Hermod was inspired by [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole), a Python tool that transfers files between computers using short, human-readable codes.

## What it does

- End-to-end encrypted transfer using QUIC + TLS 1.3
- Password-authenticated key exchange (CPace over P-256) — no shared secret needed beyond the transfer code
- Works through NAT via UDP hole punching
- Transfers files, text snippets, or stdin
- Self-hosted signaling server included

## Quick start

**Build:**
```bash
go build -o hermod ./cmd/hermod/
# With version embedded:
go build -ldflags "-X github.com/hermod/hermod/internal/cli.Version=$(cat VERSION)" -o hermod ./cmd/hermod/
```

**Start a signaling server** (one machine, reachable by both peers):
```bash
./hermod serve
```

**Pin the server certificate** (run once on each client):
```bash
./hermod trust wss://your-server:4376
```

**Send a file:**
```bash
./hermod tx report.pdf
# Prints a transfer code to stderr, e.g.: 3-apple-banana-cherry
```

**Receive:**
```bash
./hermod rx 3-apple-banana-cherry
```

The file lands in the current directory.

## Usage

### Global flags

These flags apply to every command.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--verbose` | | `none` | Log verbosity: `none`, `error`, `warning`, `info`, `debug` |
| `--quiet` | `-q` | off | Suppress status output. Errors are always shown. |
| `--ipv4` | `-4` | off | Use IPv4 only for all network operations (listen, signaling, hole punching). Cannot be combined with `--ipv6`. |
| `--ipv6` | `-6` | off | Use IPv6 only for all network operations (listen, signaling, hole punching). Cannot be combined with `--ipv4`. |
| `--version` | `-V` | | Print the version and exit. |

### tx — send

```
hermod tx [INPUT] [flags]
```

`INPUT` can be:
- A file path — sends the file
- A quoted string — sends it as text
- Omitted — reads from stdin

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server` | `-s` | `wss://localhost:4376` | Signaling server URL (saved as default when specified) |
| `--words` | `-w` | `3` | Number of words in the transfer code |
| `--listen` | `-l` | `:0` | Local UDP bind address |
| `--verify` | `-v` | off | Require out-of-band SAS verification (symmetric — enforced on both sides) |

Global flags `--verbose`, `--quiet`, `--ipv4`, and `--ipv6` also apply.

**Examples:**
```bash
# Send a file
./hermod tx photo.jpg -s wss://relay.example.com:4376

# Send text
./hermod tx "Meeting at 3pm"

# Send stdin (pipe)
tar czf - ./project | ./hermod tx

# Require SAS verification before transfer completes
./hermod tx secret.zip --verify
```

### rx — receive

```
hermod rx [CODE] [flags]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server` | `-s` | `wss://localhost:4376` | Signaling server URL (saved as default when specified) |
| `--destination` | `-d` | current directory | Output path |
| `--listen` | `-l` | `:0` | Local UDP bind address |
| `--verify` | `-v` | off | Require out-of-band SAS verification (symmetric — enforced on both sides) |

Global flags `--verbose`, `--quiet`, `--ipv4`, and `--ipv6` also apply.

**Examples:**
```bash
# Receive to current directory
./hermod rx 3-apple-banana-cherry -s wss://relay.example.com:4376

# Save to a specific path
./hermod rx 3-apple-banana-cherry -d ~/downloads/
```

### serve — run a signaling server

```
hermod serve [flags]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--listen` | `-l` | `:4376` | Bind address (default is dual-stack — both IPv4 and IPv6) |
| `--ttl` | `-T` | `600` | Channel TTL in seconds |
| `--rate-limit` | | `5` | Requests per second per IP prefix (applies to both the WebSocket `/ws` and the `/cert` endpoint) |
| `--rate-burst` | | `15` | Burst capacity per IP prefix (applies to both the WebSocket `/ws` and the `/cert` endpoint) |
| `--max-blobs-per-channel` | | `10` | Hard cap on relayed blobs per channel |
| `--max-cpace-failures` | | `3` | Max CPace failures before a channel is dropped |

Global flags `--verbose`, `--quiet`, `--ipv4`, and `--ipv6` also apply.

The server generates a self-signed TLS certificate on first run and saves it to the config directory (`~/.config/hermod/` on Linux).

You can also set the bind address via the `HERMOD_LISTEN` environment variable.

### trust — pin a server certificate

```
hermod trust [SERVER_URL] [--fingerprint FINGERPRINT]
```

Connects to the server, fetches its certificate fingerprint, saves it to the local config, and sets the server as the default for future `tx` and `rx` calls.

If you omit the port, `trust` defaults to port 4376 — hermod's standard signaling port.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--fingerprint` | | `""` | Expected SHA-256 fingerprint (hex). When set, the server's TLS certificate is verified against this value during the handshake. |

Global flags `--verbose`, `--quiet`, `--ipv4`, and `--ipv6` also apply.

```bash
# With explicit port:
./hermod trust wss://relay.example.com:4376

# Port 4376 is assumed when omitted:
./hermod trust relay.example.com

# Prints: Pinned wss://relay.example.com:4376
#           fingerprint: a3f9...
#           set as default server
```

**Security note:** The initial connection uses no certificate verification (trust-on-first-use). Run `hermod trust` over a trusted network — for example, a VPN, physical LAN, or a network where the fingerprint can be confirmed out-of-band.

If you already know the server's fingerprint (e.g., shared by the server operator), pass it with `--fingerprint` to verify before pinning:

```bash
./hermod trust wss://relay.example.com:4376 --fingerprint a3f9cc...
```

The command will fail with an error if the server presents a different certificate.

## SAS verification

Pass `--verify` (`-v`) on **either** `tx` or `rx` — or both — to enable out-of-band SAS verification. The flag is symmetric: whichever side requests it causes both sides to perform verification automatically. Neither side can use `-v` without the other being enforced.

After the QUIC handshake, both sides display a short word phrase and an identicon. Compare these out-of-band (voice call, Signal message) with the other person. If they match, type `y` to allow the transfer. This detects active man-in-the-middle attacks.

The prompt always reads from the controlling terminal (`/dev/tty` on Unix, `CONIN$` on Windows). This means `--verify` works correctly even when stdin is piped — for example, `echo secret | hermod tx -v -` will still show the prompt and wait for your `y`/`n` answer.

You can cancel SAS verification at any time by pressing Ctrl+C. The cancellation propagates to the other side, and both peers see a cancellation message (`"SAS verification cancelled by user"`). If both sides cancel simultaneously, both see `"SAS verification cancelled by both sides"`.

## Configuration

Hermod stores its config in:
- Linux/macOS: `~/.config/hermod/config.yaml`
- Windows: `%APPDATA%\Hermod\config.yaml`
- The server certificate PEM is stored in the same file

No environment variables are required for normal use. Supported env vars:

| Variable | Commands | Description |
|---|---|---|
| `HERMOD_SERVER` | `tx`, `rx` | Default signaling server URL |
| `HERMOD_LISTEN` | `tx`, `rx`, `serve` | Default UDP / TCP bind address |
| `HERMOD_DEST_DIR` | `rx` | Default output directory |

## How it works

1. The sender connects to the signaling server and allocates a channel, receiving a numeric channel ID.
2. The transfer code encodes the channel ID plus a random word passphrase.
3. The receiver connects to the signaling server using the code and joins the channel.
4. Both peers run a CPace PAKE handshake over the signaling channel to establish a shared key, authenticated by the passphrase.
5. Each peer encrypts its UDP endpoints with the shared key and sends them through the signaling relay.
6. Both peers punch through NAT using a two-phase holepunch: IPv6 first (5 s), then IPv4 (10 s). Use `-4` or `-6` to enforce a single protocol.
7. A QUIC connection is established directly between the peers, with the server certificate pinned to each side's ephemeral cert.
8. File metadata and payload stream over QUIC. The receiver verifies the SHA-256 hash on arrival.

See [docs/protocol.md](docs/protocol.md) for the full protocol specification.

## Security properties

| Property | Mechanism |
|---|---|
| Confidentiality | TLS 1.3 over QUIC |
| Authentication | CPace PAKE — only someone with the transfer code can connect |
| Integrity | SHA-256 hash verified on the received payload |
| Server cannot read data | Payload never touches the signaling server |
| Active MITM detection | Optional SAS out-of-band verification |

## Development

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=cover.out ./...
go tool cover -html=cover.out

# Bump the version (patch, minor, or major)
scripts/bump-version.sh patch
```

All packages target ≥ 80% test coverage. See [docs/api.md](docs/api.md) for the internal package API reference.
