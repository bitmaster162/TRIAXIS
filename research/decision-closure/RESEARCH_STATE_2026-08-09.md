# Research State — 2026-08-09

## What has been falsified or weakened

- Persona debate is not justified as the core.
- ANGEL/SYNTHESIZER/majority-vote theatre remains killed.
- A broad claim that structured prompting improves final decision accuracy is not supported by current Spark tests.
- Z8.1 and EBD v0.2 Pilot40 hit ceiling: U0 and U1 both achieved perfect action accuracy.

## Boundary-20 result

- U0 Ordinary: 20/20 actions
- U1 Structured: 20/20 actions
- action lift: 0 pp
- action harm: 0 pp
- 4 witness-oracle items quarantined symmetrically after genuine oracle defects were identified
- scoreable evidence-binding items:
  - U0: 14/16
  - U1: 16/16
  - delta: +12.5 pp
- complete scoreable pair action+evidence:
  - U0: 4/6
  - U1: 6/6

## Current leading hypotheses

H1 — Decision Closure:
The method's value is determining whether evidence is sufficient, what would flip the decision, which single observation matters next, and when to stop.

H2 — Decision Trace:
The method's value is not higher answer accuracy but better provenance, traceability, replayability, and auditability of the same decision.

H3 — Narrow mechanism:
The broad method may collapse further to one useful primitive such as discriminator selection or zero-VOI stop control.

## Current product/research rule

Do not claim TRIAXIS improves model intelligence.

Test whether the useful core is one or more of:
- sufficiency detection;
- minimal witness construction;
- flip-boundary prediction;
- cost-aware discriminator selection;
- decision-frontier stopping;
- provenance/traceability/auditability.

TRIAXIS is a contestant in EBD/Decision Closure benchmarks, not the oracle.
