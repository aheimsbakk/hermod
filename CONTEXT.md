# Hermod — Context

## Overview
Secure P2P file/text transfer. Signaling server brokers CPace PAKE and NAT traversal; never sees payload. Data flows over QUIC/TLS 1.3 directly between peers.

## Language & Runtime
Go 1.25.0

## Key Dependencies
| Package | Purpose |
|---|---|
| `github.com/quic-go/quic-go` | QUIC transport |
| `github.com/spf13/cobra` | CLI |
| `gopkg.in/yaml.v3` | Config YAML |
| `github.com/schollz/progressbar/v3` | Progress UI |
| `github.com/mattn/go-isatty` | TTY detection |
| `github.com/gorilla/websocket` | WebSocket signaling |
| `github.com/rogpeppe/go-internal` | E2E testscript |

## Security Model
- Signaling server untrusted — payloads never routed through it
- CPace PAKE over WebSocket yields K_classical
- Ephemeral X.509 fingerprint commitment prevents MitM during QUIC handshake
- TLS 1.3 only; prefer X25519MLKEM768 (post-quantum hybrid)
- Rate limiting: token bucket per /32 IPv4, /64 IPv6; max 3 CPace failures per channel

## Config Locations
- Linux/macOS: `~/.config/hermod/config.yaml`
- Windows: `%APPDATA%\Hermod\config.yaml`
