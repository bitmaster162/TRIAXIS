# ToolBench-X Native AVR v0.7 — 2026-08-10

Research-only receipt. No production/runtime/main changes.

## Harness correction

Before this batch, the public ToolBench-X runner was audited. `ModelDrivenToolAgent` installs a default exception config and applies strict/guided profile wrapping only when the generated module exposes the exact `set_injection_config` interface. AVR v0.7 therefore used a corrected official-equivalent local activation harness.

Because earlier local pilots used a broader setter strategy, v0.3-v0.6 call-cost figures are historical and are not pooled with v0.7.

## Prospective freeze

- 10 native ToolBench-X tasks
- 2 per hazard family: Specification, Invocation, Execution, Output, Cross-Source Uncertainty
- `FAIL_SEED=7`
- equal 30-second wall-clock limit per case in X0 and AVR
- subset frozen before native `final_answer` reveal
- output freeze frozen before native `final_answer` reveal
- no official recovery hints supplied to AVR

## Result

| Arm | Native exact match | Tool calls |
|---|---:|---:|
| X0 one-pass controller | 5/10 | 37 |
| AVR v0.7 | 8/10 | 70 |

- delta: **+30 pp**
- verified rescues: **3**
- harms: **0**
- extra calls: **33**
- extra calls / verified rescue: **11.0**
- tool-call multiplier: **1.89x**
- exact paired two-sided p: **0.25**
- harness timeouts: **0 / 0**

Small-n candidate signal only. X0 remains a deterministic controller, not an independent matched GPT-5.6 no-hint model run.

## Mechanism-isolated rescues

1. **Bounded retry / recovery**
   - X0: null
   - AVR: `924.17`
   - native expected: `924.17`

2. **Final-answer label canonicalization**
   - X0: `Answer: 06037`
   - AVR: `06037`
   - native expected: `06037`

3. **Evidence-chain completeness**
   - X0 emitted intermediate `2025-10-03` while downstream evidence was incomplete.
   - AVR continued until terminal venue evidence: `Paramount Theatre`.
   - native expected: `Paramount Theatre`.

This is the first clean native candidate pass for the v0.7 evidence-chain completeness gate and for simple label-stripping canonicalization.

## Remaining failures

- One Specification case spent 16 AVR calls on repeated `TypeError` and still held. This falsifies repeated same-argument retry on non-transient type/schema errors.
- One Execution case spent 12 AVR calls; a middle tool recovered but first/terminal evidence did not. HOLD was appropriate, but recovery cost remained high.

## Next preregistered falsifier: AVR v0.8

Keep v0.7 correctness gates and corrected harness. Add:

- error-class-aware retryability;
- no repeated unchanged call on `TypeError`/schema mismatch;
- chain-wide retry budget for sequential workflows;
- at most two additional high-VOI retries across a sequential chain after the universal one-retry layer;
- evidence-chain completeness unchanged;
- canonicalizer unchanged;
- `DEVIL_DEFAULT = OFF`.

Success criterion: match or beat X0 with low harm and reduce extra calls per verified rescue below v0.7's 11.0 when rescues occur.

## Governance

`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
`DEVIL_DEFAULT=OFF`
