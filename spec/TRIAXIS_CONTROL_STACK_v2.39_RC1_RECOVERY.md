# TRIAXIS Control Stack v2.39-RC1 Recovery — Authenticated Checkpoint Restore

## Status

```text
SPECIFICATION STATUS: Release Candidate under same-lineage validation
IMPLEMENTATION STATUS: Partially implemented
PRODUCTION-QUALIFIED: NO
EXTERNAL EXECUTION PERMISSION: NOT IMPLIED
```

## Trigger

Exact v2.38 passed 74/74 historical tests and all four v3.2 positive controls,
but failed all six restart cases because it exposed no authenticated restore
boundary.

## New invariant

```text
RESTORE CHECKPOINT
= valid v3 receipt
+ exact signed envelope authenticated under configured roots
+ exact field-for-field receipt/envelope correspondence
+ host-controlled expected checkpoint digest
```

The receipt digest alone is not authority and is not a latest-head proof.
`expected_checkpoint_sha256` must be stored and supplied by an external durable
host boundary. If the host anchor names a newer head, an older individually valid
receipt/envelope pair is rejected.

## State transition

`ProvenanceTrustStateGuard.from_checkpoint(...)` performs every check before
publishing in-memory state. After successful restore, the ordinary sequence,
parent, time, root-continuity, subject-binding and atomic-commit rules apply
unchanged.

## Non-claims

No durable database, remote consensus, cross-process CAS, hardware key custody,
trusted clock, independent certification or production operations proof is added.
