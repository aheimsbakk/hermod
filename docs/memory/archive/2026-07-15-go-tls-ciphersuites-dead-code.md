---
topic: "Go tls.Config.CipherSuites is dead code for TLS 1.3"
importance: high
category: warning
tags: [tls, cipher-suites, go, dead-code]
created: 2026-07-15T18:51:58Z
model: opencode/deepseek-v4-flash-free
---

Populating `tls.Config.CipherSuites` while `MinVersion` is set to
`tls.VersionTLS13` (or defaults to TLS 1.3) is dead code. Go ignores
`CipherSuites` for TLS 1.3 connections — it is only consulted for TLS 1.2
and below. Go uses its own hardcoded preference order
(`defaultCipherSuitesTLS13` in `defaults.go`) regardless of what is set
in `CipherSuites`. When AES-GCM hardware is unavailable, Go switches to
`defaultCipherSuitesTLS13NoAES` which prioritizes
`TLS_CHACHA20_POLY1305_SHA256` first.

Go provides no mechanism to configure TLS 1.3 cipher suite selection.
