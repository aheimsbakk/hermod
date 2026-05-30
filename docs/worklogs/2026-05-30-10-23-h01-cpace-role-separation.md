---
when: 2026-05-30T10:23:13Z
why: Security audit H-01 — CPace role parameter was silently dropped, leaving role domain separation unimplemented
what: Bind role into CPace ISK derivation via role-ordered transcript in CPaceFinish
model: github-copilot/claude-sonnet-4.6
tags: [security, crypto, cpace, pake, h01]
---

Added `role` field to `CPaceSession` and updated `CPaceFinish` to derive the ISK as `SHA-256(iskX || pubSender || pubReceiver)`, ensuring both peers hash the same byte sequence while binding role into the shared secret. The generator domain was extended with the fixed combined tag `sender:receiver`. A failing regression test (`TestCPaceRoleSeparation`) was added before the fix and now passes. `docs/protocol.md` updated to accurately describe the ISK transcript. Bumped to v0.7.4.
