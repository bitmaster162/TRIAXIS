# ToolBench-X Native Pilot — 2026-08-10

Research only. No production/runtime changes.

## Dataset receipt

User-supplied native ToolBench-X dataset was unpacked successfully:
- 523 task files
- 1,106 baseline tool files
- 2,213 exception-tool files
- native `exception_hints_catalog.json`

The dataset itself is not copied into this repository.

## Batch 1 — AVR v0.3

Fresh native tasks, `FAIL_SEED=7`.

- X0 one-pass no-hint controller: **8/10**
- X2 AVR v0.3 strict no-hint: **8/10**
- X1 guided positive control: **9/10**

Adjudication: `AVR_v0.3 = NO_NATIVE_LIFT_DEMONSTRATED`.

The one-retry recovery budget was too restrictive for some ToolBench-X entry failures. Official recovery metadata for the missed entry-failure cases allowed several same-call retries before giving up or switching paths.

## AVR recovery v0.4 preregistration

Frozen before Batch 2.

Changes:
- For idempotent/read-only calls that fail before any usable business payload with `TimeoutError`, `ConnectionError`, `OSError`, or a bare `KeyError`, allow up to **3 retries** of the same call (4 total attempts).
- For post-result schema/type/unit drift, keep at most one retry, then deterministic normalization or independent cross-check.
- Never expand the retry budget for side-effecting calls without idempotency assurance.
- `DEVIL_DEFAULT = OFF`.

## Batch 2 — fresh prospective AVR v0.4

- X0 one-pass no-hint controller: **6/10**, 42 tool calls
- X2 AVR v0.4: **8/10**, 93 tool calls
- delta: **+20 pp**
- verified rescues: **2**
- harms: **0**
- tool-call multiplier: **2.21x**
- extra calls per verified rescue: **25.5**
- paired exact two-sided p on two discordant cases: **0.50**

This is a candidate native lift signal, not a general performance claim.

## Remaining failures

1. One `Execution_Uncertainty` task exhausted the bounded recovery path.
2. One `Cross-Source_Uncertainty` task reached the correct semantic value but failed native exact match because the final surface was wrapped: `USD 128540.75` vs canonical `128540.75`.

The second failure isolates a missing mechanism: **final-answer canonicalization before commit**.

## Claim boundary

- Task JSONs, exception-tool code, fault schedules, and expected answers are native ToolBench-X data.
- This is **not** the official full ToolBench-X benchmark.
- Only 20 fresh native tasks were used across two different AVR protocol versions.
- X0 is a deterministic one-pass tool-chain controller, not an independently sampled GPT-5.6 Sol no-hint agent.
- Batch 2 was prospective with AVR v0.4 frozen before the fresh batch.
- Batch 1 and Batch 2 must not be pooled as a single fixed-protocol confirmatory experiment.

## Current decision

```text
AVR_v0.3 = NO_NATIVE_LIFT_DEMONSTRATED
AVR_v0.4 = CANDIDATE_NATIVE_LIFT_WITH_HIGH_CALL_COST
DEVIL_DEFAULT = OFF
```

Next gate:
1. add deterministic final-answer canonicalization;
2. add value-of-information / cost-aware retry allocation;
3. run a true matched model-provider `no_hint vs guided_hint vs AVR` baseline when a provider API runtime is available.
