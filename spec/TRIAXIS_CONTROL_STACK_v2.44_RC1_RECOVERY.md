# TRIAXIS Control Stack v2.44-RC1 Recovery — Signed Checkpoint Scope

## Trigger evidence

Exact v2.43-RC1 passed its positive controls but failed five cross-database
scope cases. Database-local first-writer ownership did not preserve the
authority's namespace intent when an authenticated checkpoint was transported
to a fresh SQLite file.

## New invariant

```text
scoped durable commit or restore
→ exact scope envelope is materialized once
→ Ed25519 signature authenticates under one trusted authority root
→ namespace digest matches the store namespace
→ checkpoint digest matches the exact public receipt
→ trust-envelope digest matches the exact signed trust envelope
→ host evaluation time is inside the signed validity interval
→ scope row and checkpoint/history/current rows change in one transaction
```

The signed contract is:

```text
TRIAXIS_CHECKPOINT_SCOPE_ENVELOPE_v1
```

The namespace is represented by:

```text
SHA-256(canonical JSON {
  contract_id: TRIAXIS_CHECKPOINT_NAMESPACE_v1,
  namespace: exact namespace string
})
```

## APIs

```text
commit_scoped(...)
load_guard_scoped(...)
get_scope_binding(...)
```

The retained legacy `commit()` and `load_guard()` APIs remain available for
historical unscoped lineages. Once a namespace contains a signed scope row,
legacy mutation or restore is blocked to prevent a downgrade.

## Durable schema v3

`checkpoint_scope` stores one immutable exact scope envelope per checkpoint.
A scoped successor requires every checkpoint in its existing history prefix to
have its own valid signed scope. A partial implicit upgrade from unscoped to
scoped history is rejected.

## Canonical failures

```text
checkpoint_scope_envelope_required
checkpoint_scope_namespace_mismatch
checkpoint_scope_subject_mismatch
invalid_checkpoint_scope_signature
expired_checkpoint_scope_envelope
checkpoint_scope_binding_conflict
checkpoint_scope_history_incomplete
checkpoint_scope_time_mismatch
```

## Security effect

A genuine checkpoint copied into a new database cannot be accepted under a
different namespace merely because that fresh database has no local owner row.
The intended namespace now travels with the checkpoint as authenticated data.

## Scope and limitations

This version provides signed namespace intent and local atomic persistence. It
does not provide global uniqueness, distributed consensus, whole-database
anti-rollback, trusted external time, hostile-administrator resistance or
independent certification. Authority roots and the host evaluation tick remain
external trust inputs.
