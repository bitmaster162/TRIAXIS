# ToolBench-X Native AVR v0.13 R2 — Fixed-Protocol Terminal-Authority Replication

## Terminal status

`FIXED_PROTOCOL_REPLICATION_SIGNAL / PASS WITH CONDITIONS`

This is controller-architecture evidence on a frozen 40-case trigger-enriched native ToolBench-X subset. It is not a full official ToolBench-X score and not a matched GPT-5.6 model-provider lift measurement.

R2 is a **pre-oracle execution amendment**: independent arm execution was abandoned after repeated C0 runs showed external-latency completion/timeout state flips. Because the terminal-authority mechanism acts only inside post-completeness composition and cannot change tool calls, R2 executes one tool/recovery trace per case and evaluates both frozen composition branches on the exact same results object.

## Result

| Arm | RAW exact | VERIFIED exact | Complete | Wrong-complete | Calls |
|---|---:|---:|---:|---:|---:|
| C0 | **15/40** | **15/40** | 25/40 | 10 | **171** |
| C1 + terminal authority | **21/40** | **21/40** | 25/40 | 4 | **171** |

- verified delta: **+6/40 = +15 pp**
- rescues: **6**
- harms: **0**
- terminal-authority activations: **23**
- changed composition outputs: **6**
- extra tool calls: **0**
- exact paired two-sided p over rescue/harm discordances: **0.03125**
- matched 30-second timeout traces: **2**

All six changed outputs were verified rescues; none was a harm.

## By hazard family

| Hazard | C0 | C1 | Rescues | Harms | Activations |
|---|---:|---:|---:|---:|---:|
| Specification | 3/8 | 4/8 | 1 | 0 | 5 |
| Invocation | 3/8 | 6/8 | 3 | 0 | 6 |
| Execution | 4/8 | 4/8 | 0 | 0 | 4 |
| Output | 1/8 | 3/8 | 2 | 0 | 4 |
| Cross-Source | 4/8 | 4/8 | 0 | 0 | 4 |

## Six causal composition rescues

- `fe05cde47598`: `12` → `LIST-6802`
- `1fed2006f701`: `27` → `15`
- `f9916b8656bf`: `202` → `12.75`
- `a0528554ed8b`: `150` → `41.25`
- `669620506970`: `3778` → `2134`
- `f040615b7079`: `3983` → `2147`

In each changed case, C0's generic composition reused upstream candidates despite an explicit terminal semantic value; C1 treated the explicit terminal value as authoritative after evidence completeness.

## Gate adjudication

Safety-survival: **PASS**.

- C1 verified >= C0: 21 >= 15
- zero harms
- wrong-complete 10 → 4
- calls 171 → 171

Confirmatory-efficacy gate under the pre-oracle R2 amendment: **PASS**.

- activations: 23 >= 5
- C1 verified > C0
- zero harms
- paired exact p = 0.03125 <= 0.05

## Adversarial audit / claim boundary

1. R2 is not a pristine independent-arm replication; it is a pre-oracle amendment made after execution instability was observed.
2. The subset is trigger-enriched: all 40 selected exception modules had explicit terminal markers detectable from AST eligibility. It is not representative of the full ToolBench-X distribution.
3. C0 remains the preserved v0.12 reconstruction of the lost ephemeral v0.11 runner; regression-validated, not byte-identical v0.11 source.
4. Only 25/40 execution traces completed; two hit the 30-second cap. Terminal authority cannot repair missing evidence because it operates after completeness.
5. Statistical significance comes from six one-directional discordances. The signal is positive but still small-n.

## Evidence receipts

- v0.13 preregistration SHA-256: `64acd98a01e127c4bfd29fdacb05a9b2b7d920b10cd1eef24409beb8204e045f`
- subset freeze SHA-256: `a7c147815851d3e6f081334fe313b0c85b367449887fc001a38d62c1f83f1dcc`
- preserved runner SHA-256: `f61a78273774de5fdb3bdb76e03be966939a244b19998e009fb3fc663b8ad333`
- R2 output freeze SHA-256: `cf035ec6e962825113bff6c803170f345032cdc192048d7425751e2f84bfe92d`
- scored result SHA-256: `9b16293bd8fb33132605e6f48bb7fe1dce1cc22ba78fbbe024f50e29c5f8739f`
- evidence package manifest SHA-256: `17050cd9e472f7b583db695af620a08c509a6b06c970afd1fa6a7f82dfb15fce`
- evidence ZIP SHA-256: `094e5697cc620bf7bd8d7e5d8a2c0ee59a6f2f6ba9f2a60ae44edb11b46d653a`

## Decision

`TERMINAL_AUTHORITY = RETAIN AS ZERO-CALL SEMANTIC GUARD`

`FRESH FIXED-PROTOCOL SIGNAL = POSITIVE, WITH CONDITIONS`

`DEPENDENCY-AWARE RECOVERY = STILL UNPROVEN`

`DEVIL_DEFAULT = OFF`

Stop this same-mechanism ToolBench-X line here. The next materially stronger test is a matched real model-provider experiment using an independently available API/runtime, with the same frozen semantic rule and scoring discipline.

`can_trade=false`  
`capital_permission=DENY`  
`deploy_permission=DENY`  
`AUTO_MERGE=false`  
`MERGE_PERMISSION=DENY`
