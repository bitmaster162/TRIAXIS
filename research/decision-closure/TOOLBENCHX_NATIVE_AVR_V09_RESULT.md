# ToolBench-X Native AVR v0.9 — Causal Binding Ablation

## Result

| Arm | Raw exact | Verified exact | Calls |
|---|---:|---:|---:|
| X0 one-pass | **5/10** | **3/10** | **41** |
| X0B + prompt binding | **7/10** | **7/10** | **41** |
| AVR v0.9 | **7/10** | **7/10** | **53** |

## Causal attribution

### Prompt binding

- raw exact: **5/10 -> 7/10 (+20 pp)**
- verified exact: **3/10 -> 7/10 (+40 pp)**
- extra calls: **0**
- raw gains/harms: **2 / 0**
- verified gains/harms: **4 / 0**
- verified paired p: **0.125**

### Recovery above binding

- X0B: **7/10 raw, 7/10 verified**
- AVR: **7/10 raw, 7/10 verified**
- incremental lift: **0 pp**
- extra calls: **+12**

So the entire observed lift on this batch came from **binding the task state correctly before tool execution**.

## Architecture consequence

The current minimal candidate core should move toward:

```text
PROMPT / STATE BINDING
        ↓
ONE PASS
        ↓
EVIDENCE COMPLETENESS
        ↓
CANONICAL COMMIT
        ↓
STOP
```

Recovery is no longer justified as an always-available layer. It must earn admission.

Two unresolved tasks showed near-chain-wide `TimeoutError` patterns. Retrying the tools one by one
spent 12 extra calls and produced no additional correct answer.

This motivates AVR v0.10:

```text
CORRELATED TRANSIENT FAILURES
        ↓
ONE SENTINEL RETRY
        ├─ FAIL SAME WAY → CIRCUIT BREAKER → HOLD
        └─ PASS → targeted continuation
```

## Adjudication

```text
PROMPT_BINDING = NATIVE CAUSAL CANDIDATE PASS
RECOVERY_INCREMENT = 0 ON THIS BATCH
RECOVERY_DEFAULT = SHOULD BE GATED
DEVIL_DEFAULT = OFF
```

The remaining major limitation is unchanged: these are deterministic controller arms, not
matched GPT-5.6 API agents.

## Governance

Research only. No production/runtime changes. No merge/deploy authorization.