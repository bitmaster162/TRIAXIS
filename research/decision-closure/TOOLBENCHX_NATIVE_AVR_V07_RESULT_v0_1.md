# ToolBench-X Native AVR v0.7 — Result v0.1

Research-only receipt. No production/runtime changes.

## Fresh external-state batch

- X0 one-pass: **2/10**, 25 tool calls.
- AVR v0.7: **5/10**, 74 tool calls.
- Delta: **+30 pp**.
- Verified rescues: **4**.
- Harms: **1**.
- Extra calls per rescue: **12.25**.
- Exact paired p: **0.375**.

## Critical causal adjudication

The new v0.7 mechanism was `one extra retry only after observed failure-stage depth progresses`.

It fired **0 times** on the general batch. Therefore none of the observed +30 pp can be attributed to the new progress-sensitive retry rule.

A preregistered mechanism-targeted activation audit then searched fresh native modules without reading expected answers or exception hints:

- initial 120-module probe: 1 apparent activation;
- expanded 500-module probe under the same seed/criteria: **0 reproducible activations**.

Decision:

`PROGRESS_SENSITIVE_RETRY = REMOVE_FROM_CANDIDATE_CORE`

The trigger is too sparse/runtime-sensitive to justify promotion.

## Retained architecture

`decision state -> capability route -> instrument validity -> bounded recovery -> semantic-type-preserving canonicalization -> verified commitment -> stop/reopen`

`DEVIL_DEFAULT = OFF`

## Harm note

One Specification-Uncertainty case was correct under X0 and timed out under the AVR process budget. The primary score retains it as a harm. Diagnostic call traces show both arms followed the same first four tool calls; the differential timeout is consistent with runtime/transport variance and cannot be caused by the progress-sensitive extra retry because that rule never activated.

## Claim boundary

- Native ToolBench-X task JSONs and exception tool modules were used.
- This is a 10-task pilot, not the full official benchmark.
- X0 is still a deterministic one-pass controller, not an independent same-model LLM no-hint baseline.
- The +30 pp is a system/controller result, not evidence that v0.7's new retry rule improved the model.
- Next decisive gate: matched same-model native ToolBench-X no-hint vs AVR using an external model-provider runtime.

Governance: `PRODUCTION_CHANGE=false`, `AUTO_MERGE=false`, `MERGE_PERMISSION=DENY`.
