---
topic: "handleJoin must send MsgOK before adding to waiters"
importance: high
category: pattern
tags: [server, race-condition, websocket, signaling, join]
created: 2026-06-09T20:33:55Z
model: deepseek-v4-flash-free
---

`handleJoin` in `internal/server/server.go` must write `MsgOK` to the receiver
WebSocket BEFORE adding the receiver to `s.waiters`. If the receiver is added
first, the sender's relay goroutine (started by `handleAllocate`) can find it,
forward a `MsgBlob`, and that blob arrives on the receiver's connection before
`MsgOK`. The client's `Join()` reads the blob, fails to parse it as an IP
response map, and returns an error — causing the receiver to disconnect and the
relay to close the sender's connection with a 1006 close error.
