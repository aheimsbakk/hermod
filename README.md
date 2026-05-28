# Hermod

Hermod transfers files and text directly between peers over an encrypted QUIC connection. No data passes through the signaling server — it only helps the two peers find each other.

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
```

**Start a signaling server** (one machine, reachable by both peers):
```bash
./hermod serve
# Prints the server's certificate fingerprint on first run
```

**Pin the server certificate** (run once on each client):
```bash
./hermod trust wss://your-server:4376
```

**Send a file:**
```bash
./hermod tx report.pdf
# Prints a transfer code, e.g.: 3-apple-banana-cherry
```

**Receive:**
```bash
./hermod rx 3-apple-banana-cherry
```

The file lands in the current directory.

## Usage

### tx — send

```
hermod tx [INPUT] [flags]
```

`INPUT` can be:
- A file path — sends the file
- A quoted string — sends it as text
- Omitted — reads from stdin

| Flag | Default | Description |
|---|---|---|
| `-s`, `--server` | `wss://localhost:4376` | Signaling server URL |
| `-w`, `--words` | `3` | Number of words in the transfer code |
| `-l`, `--listen` | `:0` | Local UDP bind address |
| `-v`, `--verify` | off | Require out-of-band SAS verification |

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

| Flag | Default | Description |
|---|---|---|
| `-s`, `--server` | `wss://localhost:4376` | Signaling server URL |
| `-d`, `--destination` | current directory | Output path |
| `-l`, `--listen` | `:0` | Local UDP bind address |
| `-v`, `--verify` | off | Require out-of-band SAS verification |

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

| Flag | Default | Description |
|---|---|---|
| `-l`, `--listen` | `0.0.0.0:4376` | Bind address |
| `-T`, `--ttl` | `600` | Channel TTL in seconds |
| `--rate-limit` | `5` | Requests per second per IP prefix |
| `--rate-burst` | `15` | Burst capacity per IP prefix |

The server generates a self-signed TLS certificate on first run and saves it to the config directory (`~/.config/hermod/` on Linux).

You can also set the bind address via the `HERMOD_LISTEN` environment variable.

### trust — pin a server certificate

```
hermod trust [SERVER_URL]
```

Connects to the server, fetches its certificate fingerprint, and saves it to the local config. Subsequent connections to that server verify the fingerprint.

```bash
./hermod trust wss://relay.example.com:4376
# Prints: Fingerprint: a3f9... — confirm this matches the server output, then press y
```

## SAS verification

When both sides pass `--verify`, the tool displays a short word phrase and an identicon after the QUIC handshake. Compare these out-of-band (voice call, Signal message) with the other person. If they match, type `y` to allow the transfer. This detects active man-in-the-middle attacks.

## Configuration

Hermod stores its config in:
- Linux/macOS: `~/.config/hermod/config.yaml`
- The server certificate PEM is stored in the same file

No environment variables are required for normal use. The only supported env var is `HERMOD_LISTEN` for the serve command.

## How it works

1. The sender connects to the signaling server and allocates a channel, receiving a numeric channel ID.
2. The transfer code encodes the channel ID plus a random word passphrase.
3. The receiver connects to the signaling server using the code and joins the channel.
4. Both peers run a CPace PAKE handshake over the signaling channel to establish a shared key, authenticated by the passphrase.
5. Each peer encrypts its UDP endpoints with the shared key and sends them through the signaling relay.
6. Both peers punch through NAT by sending probes to each other's addresses.
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
```

All packages target ≥ 80% test coverage. See [docs/api.md](docs/api.md) for the internal package API reference.
