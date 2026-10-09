# ToolBench-X native AVR v0.5 — 2026-08-10

Research-only result. No production/runtime change.

## Preregistration

AVR v0.5 was frozen before the fresh native batch. Changes from v0.4:

1. deterministic final-answer canonicalization;
2. value-of-information-aware retry budgeting;
3. after a usable payload, no repeated same-tool retries except one bounded validation/cross-check;
4. `DEVIL_DEFAULT=OFF`.

Preregistration SHA-256: `849fb1f12f417f764b9798bcee136ee0c83c73099614037eda12a09f152ca9a3`.

## External-state native batch

The scored batch was restricted to tasks whose answers depend on hidden tool state; no direct arithmetic shortcut from the user prompt was allowed.

Same native ToolBench-X task JSONs / exception tools, `FAIL_SEED=7`, strict no-hint profile.

| Arm | Exact match | Tool calls |
|---|---:|---:|
| X0 deterministic one-pass controller | 7/10 | 38 |
| X2 AVR v0.5 | 9/10 | 60 |

Observed effect:

- `+20 pp` exact-match;
- 2 verified rescues;
- 0 harms;
- +22 tool calls;
- 11.0 extra calls per verified rescue;
- call multiplier 1.58x;
- paired exact two-sided p=0.50 (small n; not statistical proof).

The two rescues were in native Execution-Uncertainty and Invocation-Uncertainty tasks.

## Canonicalization failure

One remaining AVR failure isolated a concrete bug:

- tool semantic output: `Result: 25 percent`
- AVR v0.5 canonical surface: `25`
- native expected: `25%`

Failure class: `SEMANTIC_TYPE_LOSS_IN_CANONICALIZER`.

AVR v0.6 is preregistered to preserve semantic answer type: when the prompt requests a percentage, normalize `25 percent -> 25%`, not `25`.

v0.6 preregistration SHA-256: `5e6f9e8e93ae6bf292cb6c65823af6ba2353c9b457585e2e3b31a29c0c39ad83`.

## Separate prompt-sufficient batch

A different v0.5 batch exposed multiple native `final_answer` values that contradicted deterministic content of their own prompts. Its raw `X0 8/10 vs AVR 6/10` score is retained as a benchmark-integrity diagnostic but is **invalid for method comparison** and is not counted as evidence either for or against AVR.

## Adjudication

`AVR_v0.5 = CANDIDATE_NATIVE_LIFT`

`AVR_v0.6 = PREREGISTERED`

`DEVIL_DEFAULT = OFF`

This is still a small native pilot, not the full official ToolBench-X result. X0 is a deterministic controller, not an independent GPT-5.6 API no-hint agent. A matched same-model endpoint run remains required before attributing the measured lift to GPT-5.6 + AVR rather than to controller design.
