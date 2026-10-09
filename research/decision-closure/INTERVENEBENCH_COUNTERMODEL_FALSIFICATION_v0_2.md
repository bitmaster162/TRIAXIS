# InterveneBench Countermodel Falsification v0.2

## Why this file exists

Early exploratory and one prospective InterveneBench batch suggested that exactly one action-changing causal countermodel could rescue some model-selection errors. Subsequent prospective batches were therefore required to determine whether the effect was stable enough to promote DEVIL into the default core.

It was not.

## Prospective sequence

### Batch 3 — trigger v0.1

- V2 Active Control: 8/10
- Triggered V3: 10/10
- rescues: 2
- harms: 0
- delta: +20 pp

### Batch 4 — unchanged trigger v0.1

- V2: 9/10
- Triggered V3: 9/10
- rescue: 1
- harm: 1
- delta: 0 pp

The harm was Missouri UI duration: the countermodel switched DiD -> SCM solely because the intervention affected one state. The published design uses a deliberately selected comparable-state control pool and two-way-fixed-effects DiD. This falsified `single treated unit -> SCM alternative` as a sufficient trigger.

### Trigger v0.2

A positive-affordance requirement was added before the next batch:

- the alternative must have affirmative method-specific support, not merely be possible;
- SCM requires donor-pool/pre-history or explicit synthetic-control affordance;
- IV requires a plausible instrument, not generic endogeneity;
- RD requires an assignment discontinuity;
- DiD requires treatment/control or exposure variation plus timing;
- PSM requires a selection-on-observables/common-support setting.

### Batch 5 — trigger v0.2

After symmetric quarantine of one internally inconsistent SASAC ESG `Model type` label:

- V2: 6/7
- Triggered V3: 6/7
- rescue: EPS Index, IV -> DiD
- harm: Inflation Targeting, PSM -> DiD
- delta: 0 pp

Thus positive method-specific affordance was still not sufficient to make the adversarial path reliably beneficial.

## Prospective rollup

Across scoreable prospective batches 3-5:

- V2: 23/27 = 85.2%
- V3 / triggered V3: 25/27 = 92.6%
- descriptive delta: +7.4 pp
- rescues: 4
- harms: 2
- exact paired two-sided discordant p-value: 0.6875

This rollup is descriptive only because batches 3-4 used trigger v0.1 and batch 5 used v0.2.

## External benchmark limitation

InterveneBench `Model type` is sometimes a lossy headline over studies using multiple estimators. Several records contain internal semantic tension between the top-level label and detailed model specification. This limits the benchmark as a fine-grained oracle for deciding which causal method is uniquely best.

## Adjudication

The evidence now supports two statements simultaneously:

1. A one-countermodel pass can produce genuine external-data rescues in identification-ambiguity cases.
2. We have not found a trigger that makes those rescues stable enough to justify default execution; countermodels also create errors.

Therefore:

> `DEVIL_DEFAULT = OFF`
>
> `DEVIL_STATUS = CONDITIONAL_RESEARCH_FEATURE`

Do not include DEVIL/ANGEL as mandatory stages in the minimum core.

The current minimum core remains:

`state/context -> evidence/provenance -> semantic applicability -> instrument validity -> selective execution -> verified commitment -> reopen/stop`

A countermodel may be requested only by an explicit unresolved-identification path or specialized evaluator, and its output must remain subordinate to direct evidence and external verification.

## Promotion gate

Reconsider default countermodel execution only if a frozen trigger reproduces net positive verified rescue on:

- an independent model or weak model;
- a fresh random/complete external set;
- hidden labels/oracles;
- matched inference/tool budget;
- predefined harm and cost thresholds.

Governance remains unchanged:

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
