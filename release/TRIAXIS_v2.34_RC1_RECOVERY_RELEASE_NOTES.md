# TRIAXIS v2.34-RC1 Recovery — Release Notes

## Closed defect class

v2.34 prevents a valid signed trust envelope from consuming or poisoning the
monotonic authority checkpoint when the associated Analysis Bundle is rejected.

## Added

- `TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v3`;
- exact one-time bundle materialization;
- state-neutral analysis preparation;
- commit only after Bundle v5 validation returns `PASS`;
- `invalid_analysis_bundle_materialization`;
- frozen v2.7 atomicity closure tests.

## Changed

- envelope authenticity and host-time checks remain before analysis;
- Bundle v5 structural, semantic, subject/context and provenance checks now run
  before checkpoint mutation;
- final `guard.accept` repeats all mutable chain/state checks under lock;
- every rejected analysis preserves the exact pre-call checkpoint;
- v1 and v2 session identifiers remain exported for historical identification.

## Preserved

- valid genesis commits sequence 1;
- valid successor commits sequence 2;
- malformed envelope and host-time mismatch remain state-neutral;
- generic authority ingress remains blocked;
- explicit low-level Bundle v5 reproduction remains available;
- root continuity and explicit authority transition requirements remain active;
- external action permission remains separate and denied by default.

## Validation target

```text
TRIAXIS_AUTHORITY_ANALYSIS_ATOMICITY_TRIGGER_v2.7_RECOVERY:
9 / 9 PASS
positive controls: 4 / 4 PASS
rows SHA-256:
05c12354d1142896875be5435b4c2e6a8b9ef5be436b138e8e998660c4241b82

UNIT + HISTORICAL:
117 / 117 PASS
```

## Open production blockers

Durable transactional storage, cross-process CAS, distributed state,
independent certification, live tool execution and Production qualification
remain out of scope.
