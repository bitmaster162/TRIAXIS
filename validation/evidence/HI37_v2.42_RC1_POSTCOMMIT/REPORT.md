# TRIAXIS v2.42-RC1 — Post-commit History Integrity Trigger

## Candidate

```text
commit: a85bd5cfd9268922f0cf1f9ef3bebff51dc490a4
tree:   796704b37cc4c6bf5b448146701eb4c055bdc4a9
tag:    TRIAXIS-v2.42-RC1-RECOVERED
```

## Result

```text
cases:             9
conformant:        4
non-conformant:    5
positive controls: 4 / 4 PASS
protocol status:   FAIL
rows SHA-256:      18eb8da279e2939e6bcd70717f43c59c5d369de3281bcdf68195bcc7e22b003e
```

The output was reproduced against a detached exact-tag worktree. Result and summary files were byte-identical.

## Material defect

`load_guard()` authenticates the current receipt/envelope under an external head anchor but does not establish that the namespace's durable history is complete and contiguous. Exact v2.42 accepted current state in all of these conditions:

1. Genesis history row deleted.
2. Middle history row deleted.
3. Current-tip history row deleted.
4. Current pointer rolled back while a later valid history row remained.
5. A valid but foreign middle checkpoint replaced the original parent chain.

The current authenticated checkpoint may still be genuine, but the database's claimed immutable audit trail is no longer trustworthy.

## Required patch

Before exposing or restoring non-empty namespace state, validate:

- exact sequences `1..current.sequence` with no gaps;
- history tip equals current exact pair;
- each successor parent equals the previous envelope digest;
- sequence and evaluation time are monotonic;
- authority root identity remains continuous;
- no history row exists after current.

## Scope

This evidence concerns internal database-history consistency. It does not prove whole-database anti-rollback when the database and external expected-head anchor are both replaced together.
