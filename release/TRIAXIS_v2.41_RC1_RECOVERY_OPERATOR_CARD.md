# TRIAXIS v2.41-RC1 Recovery — Operator Card

1. After an unknown outcome, retry only the exact receipt, envelope and predecessor head.
2. Exact retry may return the already committed head without history growth.
3. Any changed pair or predecessor is not an idempotent retry.
4. On CAS mismatch, read current state before deciding another action.
5. External execution remains separately denied by default.
