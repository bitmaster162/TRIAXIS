# TRIAXIS v2.43-RC1 — Post-commit Checkpoint Scope Binding Trigger

## Candidate

```text
commit: d231fc7303538a2e3138b6f422eb8da40671a4ee
tree:   24610f441e643a4229a0247e111a79d4d8b1eade
tag:    TRIAXIS-v2.43-RC1-RECOVERED
```

## Result

```text
cases:             9
conformant:        4
non-conformant:    5
positive controls: 4 / 4 PASS
protocol status:   FAIL
rows SHA-256:      031d15b05985e78f71e8588975167264ea54885e8909ca5c76d1c83593d4d317
```

The result was reproduced against a detached exact-tag worktree with byte-identical result files.

## Material gap

v2.43 establishes first-writer ownership only inside one existing database. A fresh database has no ownership record and accepts the same authenticated checkpoint under another namespace. The store also has no scoped ingress that verifies an authority-signed binding among:

- intended namespace digest;
- exact checkpoint digest;
- exact signed trust-envelope digest;
- authority/key identity;
- host-controlled validity time.

Consequently, exact v2.43 ignored wrong-namespace, subject-mismatched, signature-tampered, expired and missing scope envelopes.

## Required patch

Add an explicit scoped commit/restore surface. Verify a canonical Ed25519 scope envelope against host authority roots and current host time before any durable mutation or restoration. Persist the exact scope envelope atomically with the checkpoint so later scoped restore can reproduce the same binding.

## Compatibility boundary

Legacy unscoped APIs may remain for historical validation, but they must be labeled unscoped and must not inherit cross-database scope-safety claims.
