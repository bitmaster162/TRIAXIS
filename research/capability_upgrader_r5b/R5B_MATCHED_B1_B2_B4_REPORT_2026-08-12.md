# TRIAXIS R5-B — MATCHED B1 vs B2 vs B4

Date: 2026-08-12 (Asia/Bangkok)

## Question

Does the full surviving capability router / TRIAXIS-EBRC layer produce verified repo-scale value beyond a targeted repo-behavior donor under the same correction budget?

Arms:
- `B1`: minimal verifier
- `B2`: targeted `D_REPO_BEHAVIOR`
- `B4`: full capability router

## Replay A — evidence path-policy collision

Failed run `31523224555`, head `ebdfa7623f823b683831f68a63a9f14d571dd382`.

This case is **unscored**. The branch put evidence CSVs under `binance-nft-evidence/data/`, while the validated public-repo scanner forbids every `data/` or `logs/` path segment. The README declares the subtree evidence-only, not runtime.

Pre-gold:
- B1: relocate evidence files to a non-runtime namespace;
- B2: same + atomic consumer/reference rebinding;
- B4: validated scanner/provenance/scope, activated no extra donor, same repair as B2.

The historical branch continued to use `data/` and its final observed workflow still failed. Status: `UNSCORED_NO_REPAIR_GOLD`. No arm receives causal credit.

## Replay B — OfferBlaster R27 active-offer tracking

Failed run `31559825334`, head `8023b53455d7effc578215af13267a85a70e320c`.

Observed: scanner PASS, compile PASS, owned tests 3 FAIL / 176 PASS on Python 3.10; Python 3.12 owned tests also failed.

R27 intentionally added `state.upsert_active_offer(...)` before `state.record_submit_event(...)` for durable ETH OfferBlaster submits so a later ledger failure cannot hide a live offer from degraded killswitch fallback.

The real `PositionState.upsert_active_offer()` exists and is idempotent on `order_hash`. The failing R26 test doubles did not implement that new API.

### B1

Frozen diagnosis: `STALE_TEST_DOUBLE`.

Frozen repair:
- add compatible `upsert_active_offer` stubs to affected FakeState classes;
- preserve the intended later `record_submit_event` failure path;
- do not reorder production writes merely to satisfy old tests.

### B2

Same repair, plus repo-behavior verification:
- active row precedes submit ledger;
- ledger failure leaves active row present;
- degraded killswitch can see/cancel the locally persisted ETH offer.

No separate product defect was found.

### B4

Classification:
- `F4_TEST_INSTRUMENT_DRIFT`
- `F5_STATE_CONTRACT_EVOLUTION`

B4 validated production API, state roles, ordering and scope. Freshness was irrelevant. No additional donor was activated. B4 repair = B2 repair.

Frozen: `B4_INCREMENT_OVER_B2 = 0`.

## Post-freeze gold

Next commit `9ff2bd8a59ff6932d9f2ddd48d5e0d374eb3e1c1` (`test(safety): keep R26 accounting suite focused under R27`) added `_ActiveStateStub.upsert_active_offer()` to exactly the affected FakeState classes. Its `public-repo-gates` workflow passed.

Following commit `838c07f1020357adb711043ecb9cd78c559dd3e6` (`test(safety): cover ETH blaster degraded killswitch tracking`) added exactly the wider B2 verification structure:
1. active offer persisted before submit ledger;
2. ledger failure keeps active row then forces safe;
3. active-upsert failure blocks ledger and later submits;
4. degraded killswitch reads and cancels the R27 local active offer.

Its push and PR workflows passed.

## Matched result

| Arm | Immediate repair | Extra material repair | Extra verification |
|---|---|---|---|
| B1 Minimal | PASS | 0 | focused |
| B2 Repo donor | PASS | 0 | +1 repo-behavior coverage |
| B4 Full router | PASS | **0 over B2** | same as B2 |

Thus:
- `B4_INCREMENTAL_MATERIAL_REPAIRS_OVER_B2 = 0`
- `B4_INCREMENTAL_FINDINGS_OVER_B2 = 0`
- `B4_HARMS = 0`
- `FULL_ROUTER_NULL_INCREMENTAL_VALUE`

## Architectural adjudication

This is a second direct collapse signal after matched R4.

R4: `Minimal proposer+verifier == Full TRIAXIS`.

R5-B repo replay: `Targeted repo donor == Full capability router`.

The larger layer may still serve auditability, evidence/state bookkeeping, closure/reopen semantics and orchestration. Those are controller/audit functions, not demonstrated cognitive lift.

Current decision:

`COGNITIVE_COMPLEXITY_PROMOTION = DENY`

Retain:

`gap detector -> minimal router -> targeted donor -> verifier -> bounded correction -> gate -> capability memory`

Full TRIAXIS/EBRC remains a controller/audit layer pending reproducible rescues unavailable to B2 under matched budget.

## Evidence boundary

Not a final falsification: one scored repo replay in R5-B, one unscored replay, historical same-session execution, no independent external-model calls.

`DISTINCT_TRIAXIS_CAUSAL_LIFT = UNRESOLVED_BUT_FURTHER_WEAKENED`

No target-repository write, production change, merge, deploy, or trading/capital action was performed.
