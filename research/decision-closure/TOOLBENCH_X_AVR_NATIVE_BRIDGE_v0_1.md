# ToolBench-X AVR Native Bridge v0.1

Status: **bridge ready / native X2 not yet run**.

Governance: research only. No production/runtime change. No merge/deploy permission.

## External native surface

ToolBench-X provides executable multi-step tasks, exception tools, deterministic exact-answer evaluation, and the following five single-category hazard families:

1. Specification Uncertainty
2. Invocation Uncertainty
3. Execution Uncertainty
4. Output Uncertainty
5. Cross-Source Uncertainty

The upstream native policy already permits `call_tool | retry | fallback | finish`, limits blind retries, and exposes exact-match / A-B recovery metrics. The X2 bridge therefore changes only the policy layer and preserves native ToolBench-X loading, exception injection and scoring.

## X2 hypothesis

AVR should improve recovery **without oracle hazard labels or benchmark recovery hints** by inserting a deterministic pre-diagnosis layer before the policy LLM:

`runtime evidence -> hazard class -> compatible recovery action -> native policy -> native scorer`

Candidate mapping:

- Specification -> inspect contract / adapt / fallback; block premature finish.
- Invocation -> repair arguments or reselect tool; do not repeat unchanged call.
- Execution -> retry same tool once, then fallback.
- Output -> validate / normalize / fallback / cross-check.
- Cross-Source -> independent cross-check; block finish until reconciled.

## Fair arms

- X0: ToolBench-X `baseline` on `tools_exception`, no hint.
- X1: ToolBench-X `deferred_on_first_error` targeted recovery hint positive control.
- X2: AVR deterministic diagnosis + native policy LLM; **no hint, no oracle label**.

Hold constant: task subset, exception tools, `FAIL_SEED`, base model, max rounds, provider/API settings.

## Preregistered survival gate

Before any native X2 result:

- X2 - X0 exact-match >= **+5 pp**;
- X2 recovers >= **25% of X1 positive-control gain**;
- regressions <= **25% of newly recovered tasks**;
- no material tool-call budget inflation.

Failure of these gates means AVR hazard diagnosis is not yet supported by native ToolBench-X.

## Local bridge status

Drop-in bridge package created outside the repo:

`TOOLBENCHX_AVR_NATIVE_BRIDGE_v0_1.zip`

SHA-256:

`abc6bf7f6cb7bbca69a19c03417146167e5f1fbec64a10d4cf66e111818f34b6`

Local source-conformance unit suite: **PASS**.

Native X2 result: **NOT RUN**.

Current blockers in the active runtime:

- ToolBench-X `tasks` / `tools_exception` assets are not mounted locally;
- native policy evaluation requires model-provider API configuration.

Do not infer a native performance result from the passing unit suite.