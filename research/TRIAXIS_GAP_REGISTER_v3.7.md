# TRIAXIS Gap Register v3.7

## Closed

- arbitrary operational registry injection at the v3.7 path;
- local reinstall of older signed registry snapshot;
- conflicting same-sequence fork;
- parent-digest substitution;
- sequence-gap update;
- loss of current head across normal process restart.

## P0 remaining

1. Whole-SQLite rollback detection through an external monotonic anchor.
2. Root-key rotation and threshold root governance.
3. Remote revocation freshness and trusted time.
4. KMS/HSM custody and operator recovery ceremony.
5. Multi-host registry consensus and fencing.
6. Physical execution receipt signatures.
7. Independent implementation and hostile-admin testing.
