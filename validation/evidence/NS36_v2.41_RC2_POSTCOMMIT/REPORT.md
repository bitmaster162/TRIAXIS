# TRIAXIS v2.41-RC2 — Post-commit Namespace Confinement Trigger

## Candidate

```text
commit: 113fc24457cdd70b6db5bb792509d09c4e039b36
tree:   0932cd6982cdace65728790004f9833f68ac6648
tag:    TRIAXIS-v2.41-RC2-RECOVERED
```

## Result

```text
cases:             9
conformant:        4
non-conformant:    5
positive controls: 4 / 4 PASS
protocol status:   FAIL
rows SHA-256:      300df1bedd9e28804a82ac14aaf15921a229a34b3bc53c628bc3be291fe695ef
```

The result was reproduced against a detached exact-tag worktree. `RESULTS.jsonl` and `SUMMARY.json` were byte-identical to the first run.

## Material defect

`SQLiteCheckpointStore` partitions rows by namespace but does not assign one durable owner to an authenticated checkpoint identity. The same valid checkpoint receipt and signed envelope can therefore be committed to two logical namespaces inside one database.

Observed failure modes:

1. Sequential replay A → B is accepted.
2. Concurrent first writers for A and B both succeed.
3. Raw copies of current/history rows are accepted when read through B.
4. A legacy schema already containing duplicate cross-namespace checkpoint identities opens without detecting ambiguity.

## Scope

This evidence proves a same-database namespace-confinement defect. It does not establish cross-database replay, hostile-administrator resistance, distributed consensus, or whole-database anti-rollback.

## Required patch

Introduce database-wide ownership for checkpoint and envelope identities. The first successful namespace claim must be atomic with history/current commitment. Reads and migration must reject an identity owned by another namespace. Exact same-namespace retry must remain idempotent.
