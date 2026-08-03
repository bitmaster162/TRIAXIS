# TRIAXIS v2.8-RC1 — Self-Review and Input-Contract Patch Verification

```text
RUN_ID: TRIAXIS-v2.8-SELF-2026-08-03
META_DEPTH: 2
PARENT_VERSION: v2.7-RC2
PARENT_COMMIT: 1322da8f8ba495d0fa4b159066ca7145d5e3b367
INPUT_FRAMEWORK_COMMIT: 073bd9b7679c31b4374274998155c74e346f1fa7
Q1_CASE_SHA256: aa42ca757a38ad8f3372d28ef4ea1c770bbafd5657fb650e398596037b7ad15e
V2.7_Q1_RESULT_SHA256: 84ca4c8d543f0ce7fba56b0855bd8dcc2c4d57741af166cbd8cc5cefa4a50644
V2.7_Q1_RESULT: PASS 0 / FAIL 28
```

## Self-Audit

The failure was architectural, not a collection of 28 unrelated downstream defects. Structured input reached governance logic without a closed schema, strict types or fail-closed completeness check.

## Devil

A validator can create new false blocks or merely move ambiguity into an `extensions` escape hatch. Therefore:

- only top-level known fields affect normative gates;
- `extensions` cannot modify gate semantics without a new contract version;
- valid frozen scenarios must preserve v2.7 status and primary reason;
- extraction completeness remains an explicit unknown rather than a claimed solved problem.

## Angel

The patch converts malformed data from an implicit interpretation problem into an explicit terminal receipt. It prevents truthy strings, missing safety fields and typos from being mistaken for verified governance evidence without changing valid decision behavior.

## Falsifier

Required patch result:

```text
UNIT TESTS: entire 39-template fault bank fails closed
Q1 REGRESSION: 28/28
H1–H4 REGRESSION: 96/96
P1/P2 REGRESSION: 64/64
VALID INPUTS: preserve v2.7 status + primary reason
FRESH VALIDATION: Q2 generated only after v2.8 commit
```

## Regression receipt

```text
H1: PASS 24/24; result 93cdc7ed29b382bf256e0cb5798cb4ef1bfa52c2d221e4f675b43f54c150967b
H2: PASS 24/24; result 5f7116ee2a09ceb155a7fc8d4530cba142bd4dde51d0989acc3379f08d1008b7
H3: PASS 24/24; result 7e23b44b79a31afc2a6fcf405b80548c78405d9034cea580d325397bdcf8553c
H4: PASS 24/24; result 074795cc8c19c2b57c02058d51837cf0c40683639da5532105819d5879b0c763
P1: PASS 32/32; result 1a608a23c12733524ec345913960f662fc71bc79ffbddbfc04dcd57b935e46bb
P2: PASS 32/32; result 02d3a1c8f1ceb3f0be3354f2a309c3b740e300139ceb369c33af85ac1eabdbee
Q1: PASS 28/28; result fc4c644ac4414decf2bc8ee328b256629798a06ac3bcdbd16977140eb90fce62
UNIT TESTS: PASS 24 / FAIL 0
```

```text
ANALYSIS_STATUS: PASS_WITH_CONDITIONS
DECISION_STATUS: SELECT_WITH_CONDITIONS
SPECIFICATION: TRIAXIS v2.8-RC1
IMPLEMENTATION: PARTIALLY_IMPLEMENTED — DETERMINISTIC GATES ONLY
NEXT_VALIDATION: fresh commit-bound Q2
```
