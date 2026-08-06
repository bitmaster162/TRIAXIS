# TRIAXIS v3.14-RC1 Operator Card

## Permit only when

- the exact floor-quorum config digest is provisioned out of band;
- a fresh challenge was issued in the current verifier epoch;
- the configured witness threshold agrees on one floor;
- witnesses are distinct by identity, log, key and declared trust domain;
- the floor binds the exact Policy Head Quorum config digest;
- the exact floor version/digest exists in local verified policy history;
- current policy is not below the floor.

## Block on

- missing threshold;
- stale or replayed response;
- witness equivocation;
- config substitution;
- history gap, parent mismatch or fork;
- local policy below the witnessed floor.

## Boundary

Do not interpret declared trust-domain diversity as physical multi-admin conformance.
