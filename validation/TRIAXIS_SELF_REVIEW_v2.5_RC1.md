# TRIAXIS v2.5-RC1 — Self-Review and Patch Verification

```text
RUN_ID: TRIAXIS-v2.5-SELF-2026-08-03
META_DEPTH: 2
PARENT_VERSION: v2.4-RC1
PARENT_COMMIT: 259d9201efa7e6c5e190d389820c07686546e07a
H2_CASE_SHA256: 06b57865e50a5b8437e643b1532a534c5956ca60d3b5104faf675e9888391cf9
H2_V2.4_RESULT_SHA256: 7e3f4e984705cf267844c4dc69e44648ce1ea9faf6e2c4d7290b5143a661b082
H2_V2.4_RESULT: PASS 23 / FAIL 1
```

## Finding

The v2.4 Independence Gate accepted `independent_basis_present=true` without establishing whether the nominally separate evidence shared an upstream source or failure domain.

## Devil

A provenance graph can become ceremonial metadata. Merely filling different source IDs does not establish independence. The gate must identify actual collection paths, datasets, transformations and common failure domains.

## Angel

The patch is narrow: it does not demand many sources. It prevents duplicated or syndicated evidence from being counted multiple times and preserves bounded use of partially independent evidence.

## Falsifier

Replay H2 and require `BLOCKED_BY_CORRELATED_EVIDENCE` for the observed case while preserving all H1/H2 prior passes.

## Decision

```text
ANALYSIS_STATUS: PASS_WITH_CONDITIONS
DECISION_STATUS: SELECT_WITH_CONDITIONS
SPECIFICATION: TRIAXIS v2.5-RC1
IMPLEMENTATION: PARTIALLY_IMPLEMENTED — DETERMINISTIC GATES ONLY
NEXT VALIDATION: fresh H3 after v2.5 commit
```

## Regression receipt

```text
H1: PASS 24 / FAIL 0
H1 RESULT SHA256: 0d878762e1d50f4ce05e3ee74acadced659ef20aaa6da8dafdda75b4a6210340
H2: PASS 24 / FAIL 0
H2 RESULT SHA256: 2ba31885995d2e84508ac62c56a1077090c2d32b8868e894efc6e189e5f1ba66
UNIT TESTS: PASS 6 / FAIL 0
STATUS: regression only; fresh H3 pending.
```
