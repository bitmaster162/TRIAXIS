# ToolBench-X Native AVR v0.8 — Prospective Result

## Raw native exact-match

| Arm | Exact | Calls |
|---|---:|---:|
| X0 one-pass | **4/10** | **41** |
| AVR v0.8 | **3/10** | **57** |

**Raw exact result: AVR lost.**

- delta: **-10 pp**
- raw rescues: **1**
- raw harms: **2**
- paired exact p: **1.00**

## Evidence-valid exact-match

A post-freeze audit exposed a metric split. Several X0 exact answers were produced while
required upstream evidence had failed. The official ToolBench-X recovery hints for those same
tasks explicitly say not to finish in that state.

Conservative project metric:

`VERIFIED_EXACT = native exact-match + complete evidence chain`

| Arm | Verified exact |
|---|---:|
| X0 | **1/10** |
| AVR v0.8 | **3/10** |

- delta: **+20 pp**
- verified gains: **2**
- verified harms: **0**
- paired p: **0.50**
- extra calls per verified gain: **8.0**

This is **not an official ToolBench-X score**. It is an integrity diagnostic.

## Why two raw-exact “harms” are not ordinary harms

For both affected tasks the X0 terminal string happened to equal native `final_answer`, but
upstream tools were UNBOUND/failed.

The official post-hoc hint metadata says:
- the upstream sequence is mandatory;
- downstream finish is forbidden when those upstream fields/tools failed.

Therefore these cases are classified as:

`LUCKY_EXACT_NOT_VERIFIED`

AVR correctly held rather than committing unsupported evidence.

## What actually failed in v0.8

The dominant bottleneck is now **argument binding**, not retry policy.

The generic deterministic runner often sees an explicit ID in the prompt but cannot map it to
the first required tool parameter, producing `UNBOUND`. The official benchmark uses an LLM
agent for argument construction, so this controller limitation is material.

## Adjudication

```text
RAW_EXACT:
X0 4/10 -> AVR v0.8 3/10
FAIL

VERIFIED_EXACT:
X0 1/10 -> AVR v0.8 3/10
+20 pp
2 verified gains / 0 verified harms
8 extra calls per verified gain
CANDIDATE PASS

ERROR-AWARE RETRY:
directionally useful; extra calls 41 -> 57 rather than v0.7's 37 -> 70,
but cross-batch cost comparison is descriptive only.

NEXT BOTTLENECK:
PROMPT -> REQUIRED ARGUMENT BINDING
```

AVR v0.9 is preregistered before any new batch. It changes only the prompt-bound invocation
layer and keeps evidence completeness, retry policy, canonicalization, harness and seed fixed.

## Governance

Research only. No production/runtime changes. `DEVIL_DEFAULT=OFF`. No merge/deploy authorization.