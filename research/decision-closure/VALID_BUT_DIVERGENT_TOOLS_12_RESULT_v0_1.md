# Valid-but-Divergent Tools-12 — Result v0.1

## Result

- V2 Active Gate: **12/12 = 100%**
- V3 + Trialectic: **12/12 = 100%**
- Incremental Trialectic lift: **0.0 pp**

Breakdown:
- Directly disambiguated semantic-binding cases: V2 **100%**, V3 **100%**
- Missing-governing-rule cases requiring one bounded discriminator: V2 **100%**, V3 **100%**

## Interpretation

Both tools passed their own known-good controls. The hard problem was no longer tool correctness but **semantic applicability**.

V2 already did the necessary work:
- bind the target semantics;
- choose the matching valid tool when the rule was supplied;
- refuse to choose between two valid but differently-scoped tools when the governing rule was absent;
- issue one bounded discriminator query.

Adding one ANGEL/DEVIL countermodel did not change a single decision.

## Current implication

Across the current mechanism-isolation sequence:

1. executable verifier produced large positive value;
2. instrument validation plus active routing produced additional positive value;
3. explicit Trialectic adversarial pass produced **0 incremental value** after the control plane was already competent.

This does not prove Trialectic is never useful. It materially weakens the case for making it a default mandatory stage.

## Governance

`AUTHOR_CONTAMINATED=true`
`SYNTHETIC_MECHANISM_ISOLATION=true`
`EXTERNAL_GENERALIZATION_CLAIM=false`
`PRODUCTION_CHANGE=false`
`MERGE_PERMISSION=DENY`
