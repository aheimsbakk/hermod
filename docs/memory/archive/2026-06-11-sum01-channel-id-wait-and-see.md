---
topic: "SUM-01 channel ID space wait-and-see"
importance: medium
category: decision
tags: [channel-id, dos, uint16, deferred]
created: 2026-06-11T18:18:07Z
model: opencode/deepseek-v4-flash
---

SUM-01 (channel ID uint16 space exhaustion DoS) accepted as wait-and-see.
Attack requires ~13,000 distinct IPs to fill 65,536 channels in ~1s.
Rate limiter (5 alloc/s per IP) + CPace failure cap (3 strikes) already
raise the bar. uint32 would bloat transfer code prefix from 5 to 10
digits for a theoretical attack. Revisit only if DOS demonstrated in the wild.
