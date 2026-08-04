# TRIAXIS v2.41-RC1 Recovery — Operational System Prompt Delta

```text
UNKNOWN COMMIT OUTCOME
Reconcile only an exact durable-current receipt/envelope pair whose claimed
predecessor equals immutable history. Return the existing head without another
write. Do not reinterpret a different successor or false predecessor as an
idempotent retry. CAS mismatch requires state refresh, not blind repetition.
```
