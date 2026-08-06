# TRIAXIS v3.30 Completion-Witness Quorum and WORM-Anchor Closure Protocol

## Protocol ID

`TRIAXIS_COMPLETION_WITNESS_QUORUM_AND_WORM_ANCHOR_CLOSURE_v3.30`

## Frozen modules

- `tests.test_v3_30_completion_witness_quorum_and_worm_anchor`
- `tests.test_v3_30_completion_witness_quorum_and_worm_anchor_schemas`

## Required coverage

The closure must exercise:

- exact operator-pinned completion-witness quorum configuration;
- 2-of-3 acceptance using distinct witness, authority, signer, key and trust-domain identities;
- stale response handling, duplicate response rejection and signer equivocation blocking;
- semantic agreement on one state/generation/provider request/evidence statement;
- blocking-minority veto for `RESERVED`, `UNKNOWN` and `COMPLETED`;
- signed aggregate quorum witness revalidated against the exact pinned config;
- append-only signed provider-outcome events in the logical completion anchor;
- exact event replay idempotency and payload-substitution rejection;
- `UNKNOWN` reconciliation, `NO_EFFECT` generation transition and `COMPLETED` retry block;
- full signed anchor chain, signed head and state-root binding;
- fresh single-use challenge-bound anchor status;
- composed execution-ledger, execution-head quorum, provider, completion quorum and anchor preflight;
- current completion anchor blocking provider and threshold witness rollback;
- authenticated anchor mutation endpoint and public health secret minimization;
- JSON Schema validation for every new normative contract.

Every case must PASS. The closure records a sorted row for each unittest and
seals the row array with canonical SHA-256. The evidence is advisory only:
`authority_granted=false`, `production_qualified=false`,
`physical_worm_established=false`.
