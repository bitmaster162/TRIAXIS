# ToolBench-X Native AVR v0.10 — Prospective Result

## Preregistered comparison

| Arm | Raw exact | Verified exact | Calls |
|---|---:|---:|---:|
| M0 binding core | **4/10** | **4/10** | **37** |
| R1 + correlated-failure gate | **5/10** | **5/10** | **44** |

- Verified delta: **+10 pp**
- Verified rescues: **1**
- Verified harms: **0**
- Extra calls: **7**
- Extra calls per verified rescue: **7.0**
- Circuit-breaker activations: **3**
- Exact paired p: **1.00**

**AVR v0.10 passed its preregistered survival gate.**

The one verified rescue was an Invocation-Uncertainty workflow that became complete after a single targeted retry and downstream continuation.

## Circuit-breaker behavior

Three cases had near-chain-wide same-family transient failures. v0.10 used one sentinel retry and then stopped when the same failure persisted. It did not fan retries across every tool.

Post-hoc, the already-frozen historical v0.9 recovery policy was run on this same batch only as a cost diagnostic:

| Policy | Verified exact | Calls |
|---|---:|---:|
| Historical v0.9 recovery | **5/10** | **61** |
| v0.10 R1 | **5/10** | **44** |

Same verified accuracy, **17 fewer calls (27.9% reduction)**.

This old-policy comparison is explicitly **post-hoc diagnostic**, not confirmatory evidence.

## Remaining defect

One partial Cross-Source chain had:

```text
upstream producer: success
middle prerequisite: TimeoutError
terminal tool: TimeoutError
```

v0.10 retried the terminal tool. That cannot restore the missing prerequisite.

The next mechanism is therefore **dependency-aware recovery targeting**: retry the earliest failed prerequisite first, then only the newly reachable downstream path.

## Adjudication

```text
PROMPT_BINDING CORE                 = RETAIN
EVIDENCE COMPLETENESS               = RETAIN
CANONICAL COMMIT                    = RETAIN
CORRELATED-FAILURE CIRCUIT BREAKER  = PROSPECTIVE COST/SAFETY PASS
RECOVERY DEFAULT                    = GATED
DEPENDENCY-AWARE TARGETING          = NEXT FALSIFIER
DEVIL_DEFAULT                       = OFF
```

## Artifact receipts

- `TOOLBENCHX_NATIVE_AVR_V10_RESULT.zip` SHA-256: `0d9025f760c94753b796193b00cdb5ec219573d86032d766b2f331f3702d820d`
- AVR v0.10 preregistration SHA-256: `34fd04bb4339dc38efceb25cd5c3d8fd3db346b7ca2cd2f5058959b55a9c8d5a`
- AVR v0.11 preregistration SHA-256: `f063fb13a366e00f4a244466c22de7d2c9ecf287eb8cc8a4a284155d761ad151`

## Boundaries

- 10-task native ToolBench-X subset, not full benchmark.
- Subset and M0/R1 outputs frozen before native `final_answer` or official hints were opened.
- Post-hoc historical-policy comparison is diagnostic only.
- Controller arms are deterministic; no matched independent GPT-5.6 no-hint API run yet.
- No production/runtime changes; research-only receipt.
