# TRIAXIS v3.28 Execution Head and Provider Closure Protocol

## Subject

The exact v3.28 product tree implementing:

- an independently persisted monotonic execution-ledger head authority;
- fresh challenge-bound head verification;
- rollback/fork rejection against the remembered ledger event chain;
- provider-side idempotency keyed by stable `effect_id` and exact payload digest;
- explicit `IN_FLIGHT`, `UNKNOWN`, `COMPLETED`, and `NO_EFFECT` reconciliation;
- HTTP authentication and schema conformance.

## Frozen closure

Run:

```bash
PYTHONPATH=src:. python validation/execution_ledger_head/run_v328_execution_head_and_provider_closure.py
```

The closure consists of the frozen tests in:

- `tests.test_v3_28_execution_head_and_provider`;
- `tests.test_v3_28_execution_head_and_provider_schemas`.

A PASS requires every case to pass and writes a deterministic row digest to
`evidence/TRIAXIS_v3.28_EXECUTION_HEAD_AND_PROVIDER_CLOSURE.json`.

## Claim boundary

A PASS does not establish production exactly-once execution. It proves only the
reference contracts under the tested state-domain assumptions. Coordinated
rollback or compromise of the execution ledger, external head authority, and
provider idempotency store remains outside the closure and must be tested after
the product commit.
