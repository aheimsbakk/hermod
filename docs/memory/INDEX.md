# Memory Index

| topic | category | importance | tags | expires | file |
|---|---|---|---|---|---|
| Docs must be updated alongside code changes | preference | high | docs, workflow, readme, blueprint | | archive/2026-05-28-docs-with-code-rule.md |
| WriteJSON must happen inside s.mu to avoid concurrent writes | pattern | high | server, race-condition, websocket, locking, signaling | | archive/2026-06-09-writejson-inside-mutex.md |
| Allocate tolerates MsgReady before MsgOK | decision | medium | signaling, allocate, race-condition, networking | | archive/2026-06-09-allocate-tolerates-msgready-msggok-order.md |
| handleJoin must send MsgOK before adding to waiters | pattern | high | server, race-condition, websocket, signaling, join | | archive/2026-06-09-handlejoin-msgok-before-waiters.md |
| SUM-01 channel ID space wait-and-see | decision | medium | channel-id, dos, uint16, deferred | | archive/2026-06-11-sum01-channel-id-wait-and-see.md |
| No audit references in code comments | preference | high | comments, conventions, code-style | | archive/2026-06-11-no-audit-refs-in-comments.md |
