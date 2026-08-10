# ToolBench-X Native AVR v0.11 — Prospective Result

## Result

| Arm | Verified exact | Complete | Wrong complete | Calls |
|---|---:|---:|---:|---:|
| M0 | **6/10** | 6/10 | 0 | **40** |
| R2 v0.11 | **7/10** | 8/10 | 1 | **52** |

- verified delta: **+10 pp**
- verified rescues: **1**
- verified harms: **0**
- extra calls: **12**
- extra calls per rescue: **12.0**
- paired p: **1.00**

**Protocol survival gate: FAIL** because the preregistered cost ceiling was <=7 calls/rescue.

## Dependency-aware target was not exercised

Frozen trace audit:

- correlated sentinel activations: **3**
- dependency-prerequisite activations: **0**
- parallel-targeted activations: **0**

Therefore v0.11 provides **no causal evidence** for the new dependency-aware targeting rule.

## New defect: double aggregation

One parallel Invocation case became complete but wrong:

```text
component counts: 21, 19, 23
terminal tool final_value: 84
controller final: 147
native expected: 84
```

The terminal tool had already computed the requested aggregate. The generic composer then added that aggregate to its own components.

Failure class: `DOUBLE_AGGREGATION_OF_TERMINAL_VALUE`.

## Adjudication

```text
v0.11 protocol              = SURVIVAL FAIL ON COST
verified accuracy signal    = +10 pp, small n
dependency-aware targeting  = NOT TESTED
terminal authority          = MISSING
DEVIL_DEFAULT               = OFF
```

AVR v0.12 is preregistered to test only a **terminal-authority / semantic-composition gate**. It must add zero tool calls and must never aggregate an explicit terminal value with its upstream components.

## Artifact receipts

- `TOOLBENCHX_NATIVE_AVR_V11_RESULT.zip` SHA-256: `b427ba15d1f235a421f2da8d810ad3c82377330f61cb3006002bdc44c1962704`
- AVR v0.11 preregistration SHA-256: `f063fb13a366e00f4a244466c22de7d2c9ecf287eb8cc8a4a284155d761ad151`
- AVR v0.12 preregistration SHA-256: `12d98a3a9ef5d39358d35d19f973172f19bca5b79b2365b51c380a5f6bcc425c`

Research only; no production/runtime changes.
