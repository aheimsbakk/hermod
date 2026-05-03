---
when: 2026-05-03T15:35:43Z
why: ICE connectivity was non-deterministically splitting sender and receiver onto different TCP connections when both probes succeeded simultaneously
what: fix ICE split-connection bug via single-candidate enforcement and deterministic done-task iteration (v0.6.2)
model: github-copilot/claude-sonnet-4.6
tags: [bugfix, ice, p2p, networking, session]
---

Root cause: `get_local_addresses()` returned both the primary LAN IP and loopback, causing sender to fire two simultaneous probes to the same `0.0.0.0` listener; `asyncio.wait(FIRST_COMPLETED)` returned both in `done` (a set) and non-deterministic set iteration made each side pick a different TCP connection. Fixed in `network/socket_utils.py` by appending loopback only when no other address is found (one candidate → one probe → no race), and in `network/ice.py` by iterating `done` tasks in `all_tasks` insertion order instead of raw set order. Session role assignment (`session.py`: sender=controlling/no delay, receiver=controlled/probe_delay=0.1) and two new ICE tests in `tests/test_ice.py` complete the fix. Bumped to v0.6.2.
