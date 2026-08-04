# TRIAXIS Authority Checkpoint Scope Atomicity Trigger v3.9 Recovery

## Candidate

- Version: `TRIAXIS v2.44-RC1 Recovery`
- Commit: `fe465aabde921b6c0b94d449114cf202cc0b24da`
- Tree: `03a396c877e03be87a56ea2442f9e9a15a37d7f7`

## Question

Are the signed scope row, immutable checkpoint history and current head one
crash-atomic state transition?

## Required invariant

```text
before COMMIT crash
→ scope/history/current all recover to exact prior state

after COMMIT crash or lost response
→ scope/history/current all recover to exact successor
→ exact retry adds no duplicate row
```

A signed scope row without its checkpoint, or a checkpoint without its signed
scope row, is a mixed durable state and must never be observable after reopen.

## Cases

Four positive controls cover normal commit, scoped restore, exact retry and
expiry rejection. Five crash cases inject abrupt process exit after scope
insert, history insert, current update and COMMIT, then inspect the recovered
SQLite state.
