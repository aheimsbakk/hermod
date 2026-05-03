---
when: 2026-05-03T17:40:02Z
why: Provide user-facing documentation and a technical reference for the cryptographic and protocol design.
what: Add README.md, docs/architecture/crypto.md, and docs/architecture/protocols.md
model: github-copilot/claude-sonnet-4.6
tags: [docs, readme, architecture, crypto, protocols, nat]
---

Created `README.md` with install instructions, usage examples, full CLI reference, configuration and environment variable tables, a security overview, and a troubleshooting section (including a corrected NAT note: only one peer needs a reachable port, and same-LAN transfers work without any port forwarding). Added `docs/architecture/crypto.md` covering the threat model, three-layer hybrid key exchange (SPAKE2, X25519, ML-KEM-768), MAC binding, HKDF derivation, SecretStream payload encryption, ad-hoc AEAD, resume sub-key derivation, TLS certificate pinning, and the cryptographic library matrix. Added `docs/architecture/protocols.md` covering the signaling protocol message types, P2P wire frame layout, all eight session-flow steps, ICE candidate gathering and connectivity establishment, transfer resumption scaffolding, graceful shutdown sequences, and server storage guarantees. Bumped version to 0.8.0.
