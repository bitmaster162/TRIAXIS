# ToolBench-X-derived Hazard-30 Result v0.2

## Source boundary

The hazard taxonomy and recovery semantics are taken from the public ToolBench-X design. ToolBench-X evaluates recoverable unreliability across five categories and preserves at least one valid recovery path such as retry, fallback, verification, or cross-check.

This local test is taxonomy-derived, **not a native ToolBench-X score**.

## Preregistration

AVR recovery rules were frozen before generation of the concrete 30-case set.

Frozen recovery classes:
- transient execution error → retry once if idempotent;
- invocation/schema mismatch → rebind to current schema;
- specification/unit/shape drift → deterministic verified normalization;
- output/invariant failure → block finish and independently recompute/cross-check;
- cross-source conflict → provenance/scope/freshness discriminator.

The public cases did not expose hazard labels or recovery outcomes before X0/X2 action freeze.

## Derived hazard set

30 cases total, six per category:
- Specification Uncertainty
- Invocation Uncertainty
- Execution Uncertainty
- Output Uncertainty
- Cross-Source Uncertainty

Frozen result:

- X0 explicit minimal tool-following baseline: 0/30
- X1 targeted-recovery positive control: 30/30
- X2 AVR v0.3, no hazard labels: 30/30

X0 is deliberately minimal and is **not** a GPT-5.6 Sol no-hint benchmark arm. Do not use the 0→30/30 difference as a general model-lift claim.

## Clean specificity control

10 clean cases with valid, semantically applicable primary results:
- AVR: 10/10
- unnecessary recovery calls: 0

## Adjudication

The useful result is mechanism coverage, not the weak-baseline delta:

> The preregistered AVR recovery state machine spans all five ToolBench-X uncertainty classes on a derived deterministic controller test, while clean cases terminate without recovery.

Native falsifier remains:

`same model + actual ToolBench-X exception tools + native exact-match scorer + no_hint / targeted_hint / AVR`

## Governance

Research only. No runtime/production changes. No merge permission.
