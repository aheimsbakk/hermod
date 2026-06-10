---
topic: "WriteJSON must happen inside s.mu to avoid concurrent writes"
importance: high
category: pattern
tags: [server, race-condition, websocket, locking, signaling]
created: 2026-06-09T19:46:55Z
model: opencode/deepseek-v4-flash-free
---

When the server needs to write to a WebSocket connection from different
goroutines (e.g. `handleAllocate` sends `MsgOK`, `handleJoin` sends
`MsgReady`), both writes must happen while holding `s.mu`. Gorilla
websocket panics on concurrent writes to the same connection. Moving
writes outside `s.mu` (to avoid a theoretical deadlock on panic) creates
a real race that crashes the process.
