# ToolBench-X Native AVR v0.6 — Prospective Result

## Fresh external-state batch

| Arm | Exact match | Tool calls |
|---|---:|---:|
| X0 one-pass | **3/10** | **19** |
| AVR v0.6 | **8/10** | **100** |

- Accuracy delta: **+50 pp**
- Verified rescues: **5**
- Harms: **0**
- Extra calls per verified rescue: **16.2**
- Exact paired p-value: **0.0625**

This is the strongest native candidate signal so far. It is still a 10-item pilot and does not establish a general model-level claim.

## Protocol integrity

- Native ToolBench-X task JSONs and exception modules were used with `FAIL_SEED=7`.
- Three prompt-sufficient draws were excluded before execution/oracle reveal and replaced with tasks requiring hidden tool state.
- Native expected answers and official recovery hints remained hidden until X0/AVR outputs were frozen.
- X0 remains a deterministic one-pass controller, not an independent GPT-5.6 API no-hint baseline.

## Rescues

AVR v0.6 rescued five X0 failures across:
- Specification Uncertainty: 2
- Cross-Source Uncertainty: 2
- Output Uncertainty: 1

No X0-correct item was harmed.

## Cost

Calls increased from **19 to 100**. The observed rescue cost was **16.2 extra calls per verified rescue**. This is worse than the prior v0.5 batch's 11.0, so the next optimization target remains recovery efficiency rather than higher fixed retry counts.

## Canonicalization

The semantic-type-preserving v0.6 canonicalizer caused no observed harm and preserved percentage surface correctly on the tested percentage task. This batch did not contain a clean formatting-only rescue, so causal credit for canonicalization is not established.

## Remaining failures and next mechanism

Two failures remained:

1. **Execution Uncertainty**: failure stage progressed from repeated `before_tool_logic` errors to a deeper `before_return` failure before the fixed budget stopped.
2. **Invocation Uncertainty**: the invoice path showed deeper `before_wrapper_transform` failures mixed with entry failures before the fixed budget stopped.

Official hint metadata was opened only after scoring. It confirms recoverable paths remain. This motivates AVR v0.7's preregistered **progress-sensitive retry**:

> allow one extra retry only when observed execution advances to a later failpoint stage, no usable payload exists, the call is safe/idempotent, and no cheaper independent evidence path is available.

Do not retry merely because a fixed count expired.

## Adjudication

```text
AVR_v0.6 = STRONGEST_NATIVE_CANDIDATE_SIGNAL_SO_FAR
            X0 3/10 -> AVR 8/10
            +50 pp
            5 rescues / 0 harms
            p = 0.0625
            high tool-call cost

AVR_v0.7 = PREREGISTERED
            progress-sensitive retry
            canonicalizer unchanged

DEVIL_DEFAULT = OFF
```

No production/runtime/main changes. Research branch only.
