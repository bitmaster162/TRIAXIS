# TRIAXIS v2.3-RC1 — Release Notes

## Decision

```text
ANALYSIS_STATUS: PASS_WITH_CONDITIONS
DECISION_STATUS: SELECT_WITH_CONDITIONS
SPECIFICATION_STATUS: RELEASE_CANDIDATE
IMPLEMENTATION_STATUS: UNIMPLEMENTED
VALIDATION_SCOPE: DEVELOPMENT + REGRESSION CONFORMANCE v0.2
```

## Changes from v2.2-RC1

1. Added Task Graph and per-node E/X routing.
2. Added completion semantics and exact partial task status.
3. Added authority modes, recurring lifecycle, principal authentication and target digest binding.
4. Added Data Gate and project-specific Budget Gate.
5. Added pre-commit TOCTOU revalidation.
6. Added idempotency, UNKNOWN_OUTCOME and reconciliation before retry.
7. Added commit order, irreversible frontier and per-node compensation.
8. Added dynamic revalidation during long-running/recurring execution.

## State delta

```text
ACCEPTED:
— task/action atomization;
— node-scoped authority and capability;
— one-shot/time-bound/standing/recurring authority modes;
— version-bound approval;
— idempotency and reconciliation;
— partial failure ledger;
— data and budget gates;
— dynamic revalidation.

REJECTED:
— one risk vector for an entire mixed task;
— blind retry after timeout;
— recurring execution from an ordinary run-bound receipt;
— approval detached from object version;
— aggregate success that hides partial commit;
— external data movement without destination control;
— material tool spend without an explicit budget.

OPEN:
— independent blind validation;
— machine-readable schema;
— runtime fault injection;
— multi-principal authorization policies;
— Git baseline for implementation.

STOP_STATE:
NO FURTHER SPEC PATCH WITHOUT NEW EVIDENCE OR NEW FAILURE.
```
