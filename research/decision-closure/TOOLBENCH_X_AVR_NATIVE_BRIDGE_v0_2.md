# ToolBench-X AVR Native Bridge v0.2

Status: **research only / native X2 not yet run**.

## Purpose

Run AVR as an `X2` arm inside the upstream ToolBench-X evaluator while preserving the benchmark's task loading, exception tools, native exact-match scorer, failure seed, and base model.

Arms remain:

- `X0`: exception tools, no hint.
- `X1`: ToolBench-X targeted recovery hint (`deferred_on_first_error`) positive control.
- `X2`: AVR runtime diagnosis, **no benchmark recovery hint and no oracle hazard label**.

## Frozen native survival gate

Before any X2 result is observed:

- `X2 - X0 >= +5 pp` exact match;
- X2 recovers at least 25% of X1 positive-control gain;
- regressions <= 25% of newly recovered tasks;
- no material tool-call budget inflation.

Same across arms: task subset, exception tools, `FAIL_SEED`, model/provider settings and max rounds.

## v0.1 -> v0.2 hardening from external ToolBench-X examples

ToolBench-X Figure 7 exposed three gaps in AVR bridge v0.1:

1. **Semantic empty success payload**: a parser can return `success=true` with `row_count=0 / rows=[]` even when the request explicitly contains a positive input cardinality. v0.1 did not flag this because there was no explicit error.
2. **Generic RuntimeError**: ToolBench-X uses `RuntimeError` as an execution-failure surface; v0.1 only matched narrower timeout/connection classes.
3. **List-valued cross-source conflict**: v0.1 deliberately ignored lists to avoid false positives, but ToolBench-X coupon-intersection recovery requires reconciling different candidate sets across sources.

v0.2 adds:

- prompt-aware semantic-empty detection when the request establishes positive task cardinality;
- explicit `RuntimeError` execution classification;
- explicit `InvocationError` classification;
- prompt-gated reconciliation for list/set outputs when the task requests common/intersection/all-source semantics;
- the same one-retry-then-fallback constraint for execution failures;
- finish blocking while action-relevant evidence remains unresolved.

## External example conformance

Non-blind architecture conformance against six representative ToolBench-X recovery examples:

- Sequential Output Drift, target `R006`: block finish on empty parser payload and continue downstream validation/fallback.
- Sequential Specification Drift, target `3 valid rows`: bounded retry/fallback while preserving downstream validator chain.
- Parallel Execution Failure, target `619 kcal`: do not finalize from a surviving partial branch after `RuntimeError` failures.
- Parallel Cross-Source Conflict, target `SAVE10`: reconcile candidate sets rather than return one source's local coupon.
- Mixture Execution Failure, target `360.00 USD`: fallback to surviving integrated evidence path after connection failures.
- Mixture Invocation Error, target `31 g`: repair argument structure rather than repeat the malformed invocation.

The external examples were visible before this check, so this is **not** a blind benchmark result. Its value is gap discovery and mechanism coverage.

## Local bridge validation

The v0.2 package passes 13 source-conformance unit tests covering all five ToolBench-X hazard families plus the Figure 7 edge cases.

Native X2 remains `NOT_RUN` because the active runtime has no model-provider API key/configuration. HF publishes the real dataset assets (`tasks.zip`, `tools.zip`, `tools_exception.zip`), but binary transfer into the current execution container is blocked by the active tool/runtime boundary.

## Current interpretation

This does not add evidence that more internal reasoning helps. It sharpens the candidate amplifier as:

`state/context -> semantic evidence completeness -> hazard diagnosis -> bounded retry/fallback/cross-check -> verified commitment -> stop`

`DEVIL_DEFAULT=OFF` remains unchanged.