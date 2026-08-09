# Tool Trust Routing-12 — Mechanism Isolation Result v0.1

## Frozen result

| Arm | Accuracy | Tool calls | Secondary calls |
|---|---:|---:|---:|
| V0 Raw PRIMARY | 66.7% | 12 | 0 |
| V1 EBRC validate | 100.0% | 24 | 4 |
| V2 Active gate | 100.0% | 16 | 4 |
| V3 + Trialectic | 100.0% | 16 | 4 |

## Causal signal

- Raw external tool use alone was insufficient: four task-local PRIMARY endpoints returned wrong exact results.
- A known-good control detected every faulty endpoint before commitment.
- Instrument validation + independent fallback improved accuracy by **+33.3 percentage points** over raw tool trust.
- Active routing preserved 100% accuracy while reducing tool calls from 24 to 16 (**-33.3%**).
- Trialectic countermodel logic produced **0 pp additional accuracy** and **0 tool-call reduction** over the active gate.

## Interpretation

The current strongest candidate core is not `more debate`.

`STATE / EVIDENCE -> INSTRUMENT CHECK -> SELECTIVE TOOL -> VERIFIED COMMITMENT -> STOP`

The adversarial layer remains optional until it demonstrates measurable lift on a surface where validated evidence and tool control do not already settle the action.

## Claim boundary

This is a synthetic, author-contaminated mechanism-isolation test. It is useful for causal debugging of the architecture, not for an external general-performance claim.

Governance: research only; no production/runtime changes; no merge/automerge permission.