# Hermod — Context

## Overview
Secure P2P file/text transfer. Signaling server brokers CPace PAKE and NAT traversal; never sees payload. Data flows over QUIC/TLS 1.3 directly between peers.

## Language & Runtime
Go 1.25.0

## Key Dependencies
| Package | Purpose |
|---|---|
| `crypto/mlkem` (Go 1.25 stdlib) | ML-KEM-768 post-quantum KEM |
| `crypto/ecdh` (Go 1.25 stdlib) | X25519 ECDH for hybrid KEM |
| `github.com/quic-go/quic-go` | QUIC transport |
| `github.com/spf13/cobra` | CLI |
| `gopkg.in/yaml.v3` | Config YAML |
| `github.com/schollz/progressbar/v3` | Progress UI |
| `github.com/mattn/go-isatty` | TTY detection |
| `github.com/gorilla/websocket` | WebSocket signaling |
| `github.com/rogpeppe/go-internal` | E2E testscript |

## CI / Release

On push of a semver tag (`v*.*.*`), GitHub Actions builds for 5 platforms (linux/amd64, linux/arm64, windows/amd64, windows/arm64, darwin/arm64) and creates a GitHub Release with the changelog entry as body and all binaries + SHA256 checksums attached.
Uses: `actions/checkout@v6`, `actions/setup-go@v6`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, and the official `gh` CLI for release creation.
Scripts: `scripts/build-release.sh`, `scripts/extract-changelog-entry.sh`.

## Security Model
- Signaling server untrusted — payloads never routed through it
- CPace PAKE over WebSocket yields K_classical
- Ephemeral X.509 SPKI fingerprint commitment prevents MitM during QUIC handshake. SPKI (Subject Public Key Info) pinning is used instead of certificate DER pinning so that certificate renewal with the same key pair does not require clients to re-pin.
- TLS 1.3 only; X25519MLKEM768 only (FIPS 203 post-quantum hybrid key exchange, no classical fallback)
- **Hybrid KEM blob encryption**: Endpoint bundles encrypted with three-pillar key — CPace (P-256) + X25519 ECDH + ML-KEM-768 (`crypto/mlkem` stdlib). Combined via SHA-256 concatenation combiner. Provides post-quantum security for the signaling relay phase.
- Rate limiting: token bucket per /32 IPv4, /64 IPv6; bucket keys are HMAC-SHA256(daily-rotating salt, prefix) — raw IPs never stored; max 3 CPace failures and 10 blobs per channel
- Server private key stored in `config.yaml` (PEM, file permission 0o600). This is intentional (H-04): a single config file avoids a separate keystore with its own permissions. The key is ephemeral — regenerated on `hermod serve` if missing. The 0o600 permission restricts access to the file owner. Users who need stronger isolation can restrict process access (containers, systemd `LoadCredential`, or a separate key file via bind mount).
- **Auto-renewal**: `hermod serve` automatically renews the certificate 14 days before the current one expires, reusing the same private key. Because the server is pinned via SPKI (public key) fingerprint and the key does not change, the pin remains valid — clients do NOT need to re-run `hermod trust` after an automatic renewal.

## Config Locations
- Linux/macOS: `~/.config/hermod/config.yaml`
- Windows: `%APPDATA%\Hermod\config.yaml` (resolved via `os.UserConfigDir()` since v0.16.1)
