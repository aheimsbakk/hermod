---
topic: "No audit references in code comments"
importance: high
category: preference
tags: [comments, conventions, code-style]
created: 2026-06-11T19:41:03Z
model: opencode/deepseek-v4-flash
---

Code comments must not reference external audit documents, finding codes
(e.g. `(H-01)`, `(M-07)`), or section numbers from audit/gap documents.
Comments should explain the code's intent directly without external
references.
