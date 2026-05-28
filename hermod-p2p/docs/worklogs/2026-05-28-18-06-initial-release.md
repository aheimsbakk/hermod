---
when: 2026-05-28T18:06:53Z
why: Initial release of Hermod secure P2P file and text transfer tool
what: Implement full Hermod v0.1.0 — signaling server, QUIC transport, CPace PAKE, CLI (serve/tx/rx), and E2E test suite
model: github-copilot/claude-sonnet-4.6
tags: [feat, initial-release, p2p, quic, cpace, cli, e2e]
---

Implemented Hermod v0.1.0 from scratch: WebSocket signaling server with in-memory store and rate limiting, UDP hole-punching, QUIC transport with ephemeral TLS certs, CPace PAKE key exchange over P-256, AES-GCM encrypted transfer, SAS verification, and a Cobra CLI (serve/trust/tx/rx). Added a tx/rx ack stream to prevent QUIC connection teardown races. Full test suite covers config, crypto, server, network, transfer, and E2E protocol + CLI tests; all packages pass with ≥80% coverage.
