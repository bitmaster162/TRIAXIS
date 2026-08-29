# InterveneBench Blind-4 Trialectic Result v0.1

## Status

`EXTERNAL_DATA_SMALL_N_CANDIDATE_SIGNAL`

This is a blind-with-respect-to-`Model type` comparison on four InterveneBench test-set records from `Sii-yuning/STRIDES/test_data.json`.

The same GPT-5.6 Sol session produced both arms, so this is **not** independent replication.

## Arms

- **V2 Active Control** — bind available policy structure, choose the most applicable causal design, and avoid unsupported assumptions.
- **V3 + one action-changing countermodel** — V2 plus exactly one strongest alternative causal-design interpretation when it would change the selected method.

## Frozen raw result

- V2: **2/4 = 50%**
- V3: **3/4 = 75%**
- Raw delta: **+25 pp**

The only changed decision was the Germany `9-Euro-Ticket / Deutschlandticket` case:

- V2: `Difference-in-Differences (DiD)`
- V3: `Propensity Score Matching (PSM)`
- Published InterveneBench label: `Propensity Score Matching (PSM)`

The action-changing countermodel was **endogenous self-selection into ticket ownership**. The public record states that ticket ownership was self-selected and that PSM was used to address selection bias.

## Oracle defect quarantine

The TURF-Reserve item is quarantined symmetrically from the method-comparison score.

Its published field says:

`Model type = Difference-in-Differences (DiD)`

but its own `Model` field explicitly describes:

`Spatial Fuzzy Regression Discontinuity (Spatial FRD) with Instrumental Variables estimation via 2SLS`.

Both V2 and V3 selected RD. Treating the top-level `Model type` label as an unquestioned oracle would therefore score a semantically stronger answer as wrong.

After symmetric quarantine:

- V2: **2/3 = 66.7%**
- V3: **3/3 = 100%**
- Candidate delta: **+33.3 pp**

## External consistency

InterveneBench reports that vanilla GPT-5.1 reaches only 49.3% model-type accuracy. Its error analysis identifies two especially relevant failure modes:

1. DiD/IV ambiguity when temporal rollout and endogeneity concerns coexist.
2. PSM under-selection: models tend to default to DiD or IV rather than considering matching-based designs.

The paper reports that STRIDES resolves 12 of 18 vanilla model-type errors, primarily through a Critic Agent that challenges assumption violations after executable/mock-data analysis, while also introducing three new errors.

The Germany rescue in this blind subset is therefore aligned with a published benchmark-wide failure pattern rather than an arbitrary synthetic corner case.

## Adjudication

This is the first external-data candidate signal that an explicit action-changing countermodel can improve a causal-model selection after a simpler active-control pass.

It is **not enough** to restore Trialectic as a mandatory default stage because:

- sample size is tiny;
- one published label was internally inconsistent;
- both arms came from the same GPT-5.6 Sol session;
- the benchmark-wide STRIDES improvement couples critique with simulation/tool feedback, so it does not isolate pure adversarial reasoning.

Current decision:

> **DEVIL survives as a conditional exception handler, not a mandatory default stage.**

Promotion rule: require reproduction on a larger blind InterveneBench subset and/or a genuinely weak model, with measurable rescue and bounded harm/cost.

Governance remains unchanged:

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
