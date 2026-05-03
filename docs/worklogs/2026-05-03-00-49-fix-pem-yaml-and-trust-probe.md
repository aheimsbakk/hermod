---
when: 2026-05-03T00:49:58Z
why: PEM strings produced blank lines in config.yaml and trust connections logged false errors on the server
what: fix YAML PEM serialisation and suppress websockets trust-probe noise
model: github-copilot/claude-sonnet-4.6
tags: [fix, config, tls, trust, yaml, logging]
---

Replaced `yaml.safe_dump` in `save_config` with a custom `_HermodDumper` that writes
any multiline string (PEM cert/key) as a YAML literal block scalar (`|`), eliminating
the blank line PyYAML inserted between every base64 line. Added a `_SuppressTrustProbe`
log filter to `run_server` in `signaling.py` that drops the expected EOF `ERROR` websockets
emits when `hermod trust` opens a raw TLS connection to inspect the certificate. Fixed
`trust` command default port (`443` → `load_config().port`). Two new tests assert no
consecutive blank lines and correct PEM round-trip; full trust workflow integration test
added. Bumped to v0.3.3. Files touched: `src/hermod/core/config.py`,
`src/hermod/server/signaling.py`, `src/hermod/cli/main.py`, `tests/test_config.py`,
`tests/test_session.py`, `CONTEXT.md`.
