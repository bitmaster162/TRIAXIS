# TRIAXIS Evolution Hidden v0.2 — GPT-5.6 Sol Self Diagnostic

Status: **DOUBLE_CEILING / NO_INCREMENTAL_COMPONENT_VALUE_DEMONSTRATED**

Evidence class: `SELF_DIAGNOSTIC_NON_INDEPENDENT_NON_CONFIRMATORY`.

The frozen mechanism-hidden v0.2 package was used unchanged. All five arm outputs were frozen before private-oracle scoring. The same GPT-5.6 Sol session generated every arm, so this is not an independent replication and cross-arm contamination is possible. The validation receipt had already exposed only the aggregate balance (10 answerable / 10 unanswerable), not per-case labels.

## Results

| Arm | Overall | Answerable | Unanswerable-null | Pair integrity | Overanswer |
|---|---:|---:|---:|---:|---:|
| `H00_DIRECT` | 100% | 100% | 100% | 100% | 0% |
| `H01_SELF_CRITIQUE` | 100% | 100% | 100% | 100% | 0% |
| `H09_MVT_PROPOSER_VERIFIER` | 100% | 100% | 100% | 100% | 0% |
| `H13_EBRC_DUAL_STATE` | 100% | 100% | 100% | 100% | 0% |
| `H14_WMX_EBRC` | 100% | 100% | 100% | 100% | 0% |

All five arms produced the same answer/null vector. Therefore:

- rescues over H00 Direct: **0** for every richer arm;
- harms versus H00 Direct: **0**;
- measurable incremental value of Self-Critique, Proposer+Verifier, EBRC, or WMX on this screen: **not demonstrated**;
- distinct integrated TRIAXIS causal lift: **still unresolved**.

## Interpretation

Removing the explicit v0.1 abstention instructions fixed the strongest `CONTRACT_TEACHES_MECHANISM` defect, but it did not make UMWP20 discriminative for GPT-5.6 Sol. H00 Direct alone reached the ceiling, including the semantically invalid negative-cake case. The richer protocols had no room to improve measured accuracy.

This falsifies a tempting interpretation: **the improved v0.2 self-run does not provide evidence that EBRC/WMX improves GPT-5.6 Sol on UMWP20.** It also does not establish that the protocols are useless in general; this benchmark/model pair is non-discriminative here.

The highest-value remaining discriminator is external execution of the frozen v0.2 screen on an actually weak model, compared against H00 and the simpler H09 Proposer+Verifier baseline.

Governance unchanged: research only; no main write, merge, deploy, production/runtime, or trading permission change.
