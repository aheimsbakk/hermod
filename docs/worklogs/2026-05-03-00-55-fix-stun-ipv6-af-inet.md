---
when: 2026-05-03T00:55:16Z
why: STUN getaddrinfo without family=AF_INET returned IPv6 sockaddrs that crashed the AF_INET datagram transport
what: fix STUN DNS lookup to constrain results to IPv4 only
model: github-copilot/claude-sonnet-4.6
tags: [fix, stun, network, ipv6, regression]
---

Added `family=socket.AF_INET` to the `getaddrinfo` call in `get_srflx_candidate`
(`src/hermod/network/stun.py`). Without it, dual-stack DNS responses placed IPv6
sockaddrs (4-tuples) ahead of IPv4 ones; passing them to the AF_INET datagram
transport raised `TypeError: AF_INET address must be a pair (host, port)` at
runtime on macOS with Python 3.14. Added regression test
`test_get_srflx_getaddrinfo_passes_af_inet` to `tests/test_stun.py` that mocks
`loop.getaddrinfo` and asserts `family=AF_INET` is always passed. Bumped to v0.3.4.
