# TRIAXIS v3.31 Availability-Closed Completion and Immutable-Anchor Closure Protocol

## Protocol ID

`TRIAXIS_AVAILABILITY_CLOSED_COMPLETION_AND_IMMUTABLE_ANCHOR_CLOSURE_v3.31`

## Frozen modules

- `tests.test_v3_31_availability_closed_and_immutable_anchor`
- `tests.test_v3_31_availability_closed_and_immutable_anchor_schemas`

## Required coverage

The closure must exercise:

- exact operator-pinned availability policy bound to the completion-quorum
  configuration;
- one fresh response from every configured completion witness;
- missing, stale, duplicate, substituted or equivocal membership blocking;
- full-set semantic agreement and separation of `ABSENT` from `NO_EFFECT`;
- blocking-member veto for `RESERVED`, `UNKNOWN` and `COMPLETED`;
- sealed and signed availability witness verification;
- content-addressed provider-outcome storage with write-once creation;
- exact replay idempotency and conflicting-content rejection;
- signed object receipt, append-only event chain, signed head and state root;
- `UNKNOWN` reconciliation and `NO_EFFECT` generation transition;
- fresh single-use immutable-anchor effect status;
- verifier checkpoint rollback and same-sequence fork detection;
- cumulative execution-ledger, head quorum, provider, full completion
  availability, logical anchor and immutable-anchor preflight;
- current immutable anchor blocking rolled-back permissive layers;
- authenticated mutation endpoint and public health secret minimization;
- JSON Schema validation for every new normative contract.

Every case must PASS. The closure records one sorted row per unittest and seals
the row array with canonical SHA-256. Evidence remains advisory:
`authority_granted=false`, `production_qualified=false`,
`physical_worm_established=false`, `hardware_monotonicity=false`.
