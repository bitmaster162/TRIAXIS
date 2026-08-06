# TRIAXIS v3.29 Execution-Head Quorum and Completion-Witness Closure Protocol

## Protocol ID

`TRIAXIS_EXECUTION_HEAD_QUORUM_AND_COMPLETION_WITNESS_CLOSURE_v3.29`

## Frozen modules

- `tests.test_v3_29_execution_head_quorum_and_completion_witness`
- `tests.test_v3_29_execution_head_quorum_and_completion_witness_schemas`

## Required coverage

The closure must exercise:

- exact operator-pinned quorum configuration;
- 2-of-3 current-head acceptance;
- stale/unavailable/split-view behavior;
- duplicate identity/key rejection and signer equivocation;
- local-ledger rollback detection;
- signed quorum-witness handoff revalidated against the pinned configuration;
- completion-witness reservation and replay blocking;
- provider outcome receipt integrity and identity binding;
- `UNKNOWN` reconciliation and `NO_EFFECT` regeneration;
- complete signed completion-witness chain, signed head and state-root binding;
- fresh single-use completion-witness status;
- provider rollback while completion witness remains current;
- composed ledger/quorum/provider/witness preflight;
- authenticated mutation endpoints and public secret minimization;
- JSON Schema validation for every new normative contract.

Every case must PASS. The closure output records a sorted row for each unittest
case and seals the row array with canonical SHA-256. This closure does not grant
action authority and does not establish physical independence or production
exactly-once behavior.
