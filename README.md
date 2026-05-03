# Hermod (Pre ALPHA)

Hermod transfers files and text directly between two computers — no cloud storage, no account, no middleman — using post-quantum encryption.

## What it does

- **Sends files and text** over a direct peer-to-peer connection
- **Encrypts everything** with a three-layer hybrid scheme (SPAKE2 + X25519 + ML-KEM-768) that resists both classical and quantum attackers
- **Requires no shared infrastructure** — the signaling server only brokers the initial handshake; it never sees your data
- **Works through NAT** — punches through firewalls and home routers without port forwarding in most cases
- **Pipes cleanly** — reads from stdin and writes to stdout so you can compose it with other tools

---

## Install

**Requires Python 3.12 or later.**

```bash
# Recommended: run directly without installing
uvx hermod-p2p

# Or install persistently
pipx install hermod-p2p
```

To verify the install:

```bash
hermod --version
```

---

## Quick start

### Send a file

On the sender's machine:

```bash
hermod tx report.pdf
```

Hermod prints a transfer code like `47392-rapid-blue-fox`. Share that code with the receiver over any channel (chat, phone, email).

### Receive a file

On the receiver's machine:

```bash
hermod rx 47392-rapid-blue-fox
```

The file lands in the current directory.

---

## Usage

### Send a file

```bash
hermod tx /path/to/document.pdf
```

### Send text

```bash
hermod tx "Hello, world"
```

### Send from stdin

```bash
echo "Secret text" | hermod tx -
cat archive.tar.gz | hermod tx -
```

Binary data sent via stdin is saved as a file named `stdin` on the receiver's side.

### Receive to a specific folder

```bash
hermod rx 47392-rapid-blue-fox --destination ~/Downloads/
```

### Pipe received data to another tool

When stdout is redirected, Hermod streams the raw bytes directly — no file is saved:

```bash
hermod rx 47392-rapid-blue-fox | tar -xz
```

### Verify the connection before transferring

The `--verify` flag derives a short authentication code from the session key. Both sides must confirm they see the same code before the transfer starts. Use this when the transfer code was exchanged over an untrusted channel.

```bash
# Sender
hermod tx report.pdf --verify

# Receiver
hermod rx 47392-rapid-blue-fox --verify
```

---

## Run your own signaling server

The public default server is `wss://localhost:8786`. You can run your own:

```bash
hermod serve --listen 0.0.0.0:8443 --ttl 3600
```

| Flag | Default | Description |
|---|---|---|
| `--listen` / `-l` | `0.0.0.0:8786` | Address and port to bind |
| `--db` / `-d` | `~/.hermod/signaling.db` | SQLite database path |
| `--ttl` / `-T` | `3600` | Seconds before an unused channel is deleted |

On first run `hermod serve` generates a self-signed TLS certificate and stores it in `~/.config/hermod/config.yaml`.

### Trust a custom server

Clients verify servers by certificate fingerprint rather than by a certificate authority. Pin a server's certificate with:

```bash
hermod trust my-relay.example.com:8443
```

This fetches the server's certificate, pins its SHA-256 fingerprint, and saves the server URL as your default — so you do not need `--server` on subsequent transfers.

---

## All command flags

### `hermod tx` / `hermod send`

| Flag | Short | Default | Description |
|---|---|---|---|
| `[INPUT]` | — | — | File path, text string, or `-` for stdin |
| `--server` | `-s` | `wss://localhost:8786` | Signaling server URL |
| `--listen` | `-l` | `:0` (OS-assigned) | Local address for the P2P listener |
| `--verify` | `-v` | off | Require manual SAS confirmation before transfer |
| `--verbosity` | — | `error` | Log level: `debug`, `info`, `warning`, `error`, `critical` |

### `hermod rx` / `hermod receive`

| Flag | Short | Default | Description |
|---|---|---|---|
| `CODE` | — | required | Transfer code printed by the sender |
| `--destination` | `-d` | current dir | Where to save the received file |
| `--server` | `-s` | `wss://localhost:8786` | Signaling server URL |
| `--listen` | `-l` | `:0` (OS-assigned) | Local address for the P2P listener |
| `--verify` | `-v` | off | Require manual SAS confirmation before transfer |
| `--yes` | `-y` | off | Auto-accept all prompts |
| `--verbosity` | — | `error` | Log level |

---

## Configuration

Hermod reads settings from `~/.config/hermod/config.yaml` (Linux/macOS) or `%APPDATA%\Hermod\config.yaml` (Windows).

Settings are resolved in this order — later entries override earlier ones:

1. Application defaults
2. `config.yaml`
3. Environment variables
4. CLI flags

### Environment variables

| Variable | Equivalent flag | Notes |
|---|---|---|
| `HERMOD_SERVER` | `--server` | |
| `HERMOD_LISTEN` | `--listen` | Format: `host:port` or `[ipv6]:port` |
| `HERMOD_DEST_DIR` | `--destination` | Default download folder |
| `HERMOD_DB_PATH` | `--db` | Signaling server database path |
| `HERMOD_P2P_PORT` | `--listen` (port only) | Fixed port for the P2P listener |
| `HERMOD_PORT` | — | Deprecated — use `HERMOD_LISTEN` |
| `HERMOD_HOST` | — | Deprecated — use `HERMOD_LISTEN` |

### Example config file

```yaml
server: wss://my-relay.example.com:8443
dest_dir: ~/Downloads
verbosity: warning
trusted_servers:
  wss://my-relay.example.com:8443:
    fingerprint: "ab:cd:ef:..."
```

> **Security note:** `config.yaml` stores TLS private key material and is written with mode `0600` (owner read/write only). Do not change its permissions.

---

## Logs

Hermod writes logs to `~/.local/state/hermod/app.log`. Logs are suppressed on the terminal by default. To see them:

```bash
hermod tx report.pdf --verbosity debug
```

---

## Security at a glance

Hermod uses three independent layers of key agreement so an attacker must break all three to read your data:

1. **SPAKE2** — a password-authenticated key exchange over the signaling channel, using the transfer code as the shared secret. This stops offline dictionary attacks.
2. **X25519 ECDH** — an ephemeral Diffie-Hellman exchange over the direct P2P link. Classical defense-in-depth.
3. **ML-KEM-768** — a post-quantum Key Encapsulation Mechanism (NIST FIPS 203). Protects against "Store Now, Decrypt Later" attacks by future quantum computers.

All three secrets are combined with HKDF-SHA256 into a single session key. Payload data is encrypted with `crypto_secretstream` (XChaCha20-Poly1305) which ratchets the key automatically and guarantees truncation protection.

The signaling server stores only opaque encrypted blobs. It never sees filenames, sizes, or content. Channels are deleted automatically after the configured TTL.

For a full technical description see:
- [`docs/architecture/crypto.md`](docs/architecture/crypto.md) — cryptographic design
- [`docs/architecture/protocols.md`](docs/architecture/protocols.md) — wire protocol and NAT traversal

---

## Troubleshooting

**"Connection timed out" or transfer hangs**

Hermod races outbound probes and an inbound listener on both sides simultaneously, so only **one** peer needs to be reachable. If both are behind strict NAT without port forwarding, the connection will fail. Fix a port on whichever machine has a forwarded port (or a public IP):

```bash
# On the reachable machine — either sender or receiver
hermod tx report.pdf --listen :9000
hermod rx 47392-rapid-blue-fox --listen :9000
```

Forward port 9000 on that machine's router, then the other peer can connect to it even from behind NAT.

**"Certificate verification failed"**

The server's certificate has changed. Re-pin it:

```bash
hermod trust my-relay.example.com:8443
```

**Transfer was interrupted — will it resume?**

Partial downloads are saved as `.hermod_part` files. Full resume support is planned but not yet active in the session layer. Delete the `.hermod_part` file and start the transfer again.

**"No post-quantum KEM library found"**

The default install uses the pure-Python `kyber-py` backend. If you see this warning, reinstall:

```bash
uv add kyber-py
```

For maximum performance, install the native C backend:

```bash
uv add "hermod-p2p[pq]"
```

This requires a compiled `liboqs` shared library on your system.

---

## Scripts

| Script | Description |
|---|---|
| `scripts/bump-version.sh [patch\|minor\|major]` | Bump the project version in `pyproject.toml` |
| `scripts/validate-worklog.sh` | Validate worklog YAML front-matter before committing |

---

## Development

```bash
# Install with dev dependencies
uv sync --all-groups

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov
```

Tests require Python 3.12+. All async tests run automatically via `pytest-asyncio`.
