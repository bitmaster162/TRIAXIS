# TRIAXIS Authority Checkpoint Namespace Confinement Trigger v3.6 Recovery

## Candidate

- Version: `TRIAXIS v2.41-RC2 Recovery`
- Commit: `113fc24457cdd70b6db5bb792509d09c4e039b36`
- Tree: `0932cd6982cdace65728790004f9833f68ac6648`

## Question

Can one authenticated checkpoint identity be replayed or copied into a different logical namespace inside the same durable SQLite store?

## Required invariant

```text
one checkpoint_sha256 / envelope_sha256 identity
→ exactly one durable namespace owner in one database
```

The invariant applies to normal commit, concurrent first-writer races, reads of current state, immutable history, and migration of an existing schema. Namespace partitioning without checkpoint ownership is insufficient because the same authenticated state can otherwise represent two tenants/projects.

## Canonical block

```text
status: BLOCK
error: checkpoint_store_namespace_replay
```

## Scope

This protocol establishes confinement inside one SQLite database. It does not claim cross-database anti-replay, whole-database anti-rollback, hostile-administrator resistance, or distributed consensus.
