---
when: 2026-05-02T23:30:29Z
why: Enable real NAT traversal so peers behind different NATs can connect directly
what: Add ICE/STUN candidate gathering, symmetric ice_connect, send/receive CLI aliases, default port 4430
model: github-copilot/claude-sonnet-4.6
tags: [feature, network, ice, stun, nat-traversal, cli]
---

Added `src/hermod/network/stun.py` (RFC 5389 Binding client, pure stdlib) and `src/hermod/network/ice.py` (`IceCandidate`, `gather_candidates`, `ice_connect`). Both `SenderSession` and `ReceiverSession` in `session.py` now bind their own `PeerListener`, gather host + optional srflx candidates, exchange the full candidate list via the signaling relay, and race inbound accept against outbound TCP probes via `ice_connect`. Default port changed from 8765 to 4430 in `config.py`; `hermod send` / `hermod receive` CLI aliases added in `cli/main.py`. Bumped version to 0.2.0; 29 new tests added (129 total, all passing).
