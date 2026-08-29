# InterveneBench Conditional Countermodel Evidence v0.2

## Strongest result: prospective external-data batch

After an exploratory InterveneBench phase, `CONDITIONAL_COUNTERMODEL_TRIGGER_v0_1` was frozen before a fresh 10-case batch. V2/V3 predictions were then frozen before published `Model type` labels were opened.

Prospective result:

- V2 Active Control: **8/10 = 80%**
- Triggered V3: **10/10 = 100%**
- Delta: **+20 percentage points**
- Trigger invoked: **5/10**
- Action actually changed: **2/10**
- Verified rescues: **2**
- Harms: **0**

Rescues:

1. Full Hukou Liberalization: `DiD -> RD` because the 500,000 population assignment threshold supports an RD-DID/fuzzy-RD identification strategy.
2. Rural social-network poverty analysis: `PSM -> IV` because cross-sectional social-network intensity is materially endogenous to entrepreneurship/resources and the published design uses IV.

The exact paired two-sided sign/McNemar-style p-value is `0.500`; this batch is too small for statistical proof.

## Exploratory phase

After symmetric quarantine of two internally contradictory top-level benchmark labels:

- V2: 7/10 = 70%
- V3: 9/10 = 90%
- candidate delta: +20 pp
- rescues: 3
- harms: 1

Exploratory rescues:

- Germany 9-Euro/Deutschlandticket: `DiD -> PSM`
- Swedish rural grocery support: `DiD -> RD`
- Microfinance wages/turnover: `PSM -> IV`

Exploratory harm:

- New Budget Law: `DiD -> IV`, while the published design uses a high-debt versus low-debt DiD exposure contrast.

The harm motivated the conditional trigger rather than default adversarial execution.

## Descriptive combined evidence

Keeping exploratory and prospective phases distinct, total scoreable external records are 20:

- V2: **15/20 = 75%**
- V3 / triggered V3: **19/20 = 95%**
- descriptive delta: **+20 pp**
- rescues: **5**
- harms: **1**
- exact paired p-value over all discordant cases: `0.21875`

Do not interpret the combined p-value as confirmatory because the first 10 cases were exploratory and case selection was curated rather than random.

## Benchmark-quality findings

Two top-level `Model type` labels were quarantined because they contradicted their own richer `Model` fields:

- TURF-Reserve: top-level label `DiD`, detailed model `Spatial Fuzzy Regression Discontinuity + IV/2SLS`.
- Social-security coverage in China: top-level label `DiD`, detailed record describes a cross-sectional logistic baseline, IV endogeneity correction, and PSM-DID robustness rather than a coherent longitudinal DiD identification design.

An additional already-exposed ALMP record also has `Model type = SCM` while its detailed core evaluation design is PSM. It is not included in blind scoring but further demonstrates label noise.

## Current adjudication

The empirical position has changed from `DEVIL incremental value not demonstrated` to:

> **Conditional countermodel value = candidate external support.**

The surviving mechanism is not persona debate. It is:

`leading design -> identification/applicability gate -> one action-changing countermodel -> commit or one discriminator -> stop`

DEVIL remains outside the mandatory core. Promotion requires independent reproduction on a fresh/random or complete InterveneBench subset and preferably a weaker model, with frozen trigger, hidden labels, matched budget, and measured rescue/harm/cost.

Governance remains unchanged:

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
