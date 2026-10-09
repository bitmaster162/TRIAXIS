# TRIAXIS Canon Profile R1

Status: **READ-ONLY CONFORMANCE PROFILE / NO RUNTIME AUTHORITY**

Frozen baseline at profile creation:

`main@a292ff969ef291238e8a28a443c090a86e7bd2e7`

## Purpose

This profile places a bounded subset of the external Memory Canon *inside* the TRIAXIS repository as an executable conformance lens. It does not make the canon an authorization source and it does not promote TRIAXIS-local engineering decisions into global canon.

The profile asks one narrow question:

> For each selected canon rule, what evidence level does current TRIAXIS actually support?

The validator fails closed on baseline drift and keeps production/main, draft-candidate, research-only, partial, gap, and outside-system evidence distinct.

## Evidence classes

- `VERIFIED_MAIN` — current main or merged-lineage source/test/receipt evidence supports the bounded assertion.
- `VERIFIED_PROCESS` — exact repository/process evidence supports the rule, but it may not be a runtime primitive.
- `PARTIAL_MAIN` — some mainline semantics exist, but the full canon rule is not proven.
- `PARTIAL_RESEARCH` — research evidence is relevant but is not production/current authority.
- `RESEARCH_ONLY` / `RESEARCH_ONLY_PARTIAL` — research evidence only; cannot satisfy production implementation.
- `GAP` — no bounded current TRIAXIS mechanism was verified.
- `GAP_OR_OUTSIDE` — missing in this pass or possibly belongs to another subsystem boundary.
- `OUTSIDE_TRIAXIS_CORE` — the invariant belongs to the cross-system Control Plane rather than TRIAXIS alone.

## Hard boundaries

This profile does **not** authorize:

- merge;
- deploy;
- provider/vendor invocation;
- production-ledger mutation;
- trading or capital action;
- canon promotion;
- background scheduling;
- autonomous repair.

`PREPARED != external effect completion` remains binding.

A successful profile validation is not production qualification, not complete mediation, and not a statement that every selected canon decision is implemented.

## Current high-value findings

The profile is strongest around authority/effect correctness:

- consequence-derived risk and anti-downgrade;
- exact action/payload/state/policy binding;
- authenticated assurance/state artifacts;
- exact-baseline bounded deltas;
- explicit PREPARED / COMPLETED / UNKNOWN distinctions;
- provider reconciliation and replay blocking;
- external monotonic heads and completion witnesses;
- explicit non-claims and effect ceilings.

Largest bounded gaps in the initial profile include:

- D134 generic parallel-agent lane/owner/read-write-effect/return registry;
- D103 generic adaptation to repeated provider authentication/rate-limit/security friction;
- D127 generic delegated-agent return transport + acceptance remains only partial;
- D136 bounded auto-repair is research/partial rather than a verified autonomous runtime.

D120 and D131 are intentionally classified outside TRIAXIS core because TRIAXIS alone cannot prove the wider Control Center + ContinuityOS + Return Plane composition.

## Baseline drift

The profile is pinned to the exact creation baseline. If `main` moves, the validator returns `HOLD_BASELINE_DRIFT` rather than silently inheriting the prior result.

A future update must fresh-read the new main, re-evaluate the bounded evidence, intentionally update the profile, and rerun tests under a separate exact gate.

## Draft and research isolation

Open draft branches such as provider-HTTP containment candidates may inform future profile revisions but cannot satisfy `VERIFIED_MAIN` before merge and exact-main readback.

Research branches may propose or falsify candidate mechanisms, but they remain research-only until separately promoted through their own evidence and authority gates.

## Validation

Run only the bounded profile tests:

```bash
PYTHONPATH=src:. python -m unittest tests.test_canon_profile_r1 -v
```

The validator is intentionally standard-library-only and performs no external I/O.
