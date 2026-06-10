---
topic: "Allocate tolerates MsgReady before MsgOK"
importance: medium
category: decision
tags: [signaling, allocate, race-condition, networking]
created: 2026-06-09T19:46:55Z
model: opencode/deepseek-v4-flash-free
---

`Allocate()` in `internal/network/signaling.go` must tolerate receiving
`MsgReady` before `MsgOK` because server-side goroutine ordering is
non-deterministic when both `handleAllocate` and `handleJoin` write to
the sender's connection. The fix loops on non-error message types,
accepting both `MsgOK` and `MsgReady` as valid first responses.
