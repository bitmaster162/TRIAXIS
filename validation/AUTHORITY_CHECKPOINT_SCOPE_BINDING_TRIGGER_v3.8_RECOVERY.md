# TRIAXIS Authority Checkpoint Scope Binding Trigger v3.8 Recovery

## Candidate

- Version: `TRIAXIS v2.43-RC1 Recovery`
- Commit: `d231fc7303538a2e3138b6f422eb8da40671a4ee`
- Tree: `24610f441e643a4229a0247e111a79d4d8b1eade`

## Question

Does an authority-signed checkpoint scope survive transport to another database and prevent use under a different namespace?

## Required scoped-ingress invariant

```text
signed namespace digest
+ exact checkpoint digest
+ exact trust-envelope digest
+ authority identity and validity
→ verified before durable commit or restore
```

Database-local first-writer ownership is not sufficient because a fresh database has no prior owner state.

## Canonical blocks

```text
checkpoint_scope_envelope_required
checkpoint_scope_namespace_mismatch
checkpoint_scope_subject_mismatch
invalid_checkpoint_scope_signature
expired_checkpoint_scope_envelope
```

## Compatibility

Legacy unscoped APIs may remain for historical replay, but they must not be described as cross-database scope-safe. The new scoped entry point must fail closed.
