# TRIAXIS R5-A — F5 Repo-Scale Donor Wave 2

Date: 2026-08-12 (Asia/Bangkok)

## Result

Wave 2 upgrades the repo-behavior evidence from **incremental defect discovery** to a **historically verified incremental repair prediction**.

Clean historical replay:
- repo: `bitmaster162/okx-nft-bot`
- failed run: `31529705896`
- failing head: `f82c5dcda1d5592be0c9826b31e8d0cc71cf97d3`
- initial result: two Telegram killswitch integration failures.

B0/B1/B2 were frozen before later branch commits or PR #41 were opened.

## B0 / B1

Both diagnosed the immediate failure as `MISSING_PRODUCTION_WIRING`.

Frozen repair:
- import `activate_multichain_killswitch` and `format_killswitch_result` into `telegram_bot`;
- reject arguments before invoking the coordinator;
- call the coordinator once with `processor.settings`;
- return the formatted coordinator result.

Post-freeze future commit `80a9b76bda81b116df9eefd3a7cd46f95f9b7985` implemented exactly this wiring repair and its `public-repo-gates` workflow completed successfully.

Thus:
- `B0_IMMEDIATE_REPAIR_PREDICTION = VERIFIED`
- `B1_INCREMENT_OVER_B0 = 0`

## B2 repo-behavior donor

Before gold, B2 followed the recovery control-flow boundary.

`activate_multichain_killswitch()` promises per-chain isolation. The failing revision caught `_cancel_chain()` exceptions, built a fatal result, then called `_record_chain_audit()` inside the exception handler without a second containment barrier.

Because `_record_chain_audit()` performs state/audit persistence effects, B2 froze this failure chain:

`chain failure -> fatal handler -> audit persistence failure -> exception escapes -> later chain skipped`

Fingerprint:

`F5_ERROR_PATH_SIDE_EFFECT_BYPASSES_ISOLATION_BOUNDARY`

Frozen B2 repair:
- keep normal audit behavior strict on the normal path;
- use best-effort audit recording in the outer fatal handler;
- log secondary audit failure without allowing it to stop subsequent chains.

Frozen required regression:
- chain A fails;
- audit write for chain A also fails;
- chain B must still reach lookup/cancel.

## Post-freeze future repository repair

Later PR #41 was titled:

`fix(safety): preserve killswitch chain isolation on audit failure`

The actual product patch changed the outer fatal handler from `_record_chain_audit()` to `_record_chain_audit_best_effort()`.

The helper catches audit persistence exceptions and explicitly continues remaining chains.

The PR added the exact regression classes predicted by B2:
1. post-cancel audit failure must not skip the next chain;
2. pre-network chain failure plus audit failure must still reach the next chain.

PR head `ec77e5559156d372b56c0d2805d4a44f62de3beb` passed `public-repo-gates`.

Therefore:

`B2_INCREMENTAL_REPO_REPAIR_PREDICTION_OVER_B1 = 1`

`B2_HARMS = 0`

`D_REPO_BEHAVIOR = SUPPORTED_FOR_HISTORICALLY_VERIFIED_INCREMENTAL_REPAIR_PREDICTION`

## Evidence boundary

This remains a historical replay, not a live prospective trial:
- the B2 hypothesis was frozen before future gold was opened;
- the underlying task is historical;
- the same GPT-5.6 Sol session performed the replay;
- no external Claude/Gemini call occurred;
- evidence is non-independent and non-confirmatory.

The result therefore supports the targeted repo-behavior donor, not broad TRIAXIS superiority.

## Capability memory

Promote conditionally:

`F5_ERROR_PATH_SIDE_EFFECT_BYPASSES_ISOLATION_BOUNDARY`

Trigger:
- code promises per-item/per-chain isolation;
- exception/recovery handlers themselves perform state, audit, logging, or cleanup effects.

Skill:
1. map normal and exceptional control flow;
2. enumerate effects performed inside recovery handlers;
3. inject failure into recovery-side effects;
4. assert subsequent independent work items still execute.

## Architecture consequence

Current state:
- minimal router: retain;
- `D_REPO_BEHAVIOR`: conditionally promote;
- targeted donor has one historically verified incremental repair prediction over B1;
- full B4 TRIAXIS router incremental value remains unproven;
- distinct TRIAXIS causal lift remains unresolved;
- actual multi-model synergy remains untested;
- `DEVIL_DEFAULT=OFF`.

## Next gate

Repeat on fresh repository failures, then compare under matched correction budget:

`B1 minimal verifier` vs `B2 targeted repo donor` vs `B4 full capability router`.

Only reproducible B4 rescues beyond B2 justify retaining additional TRIAXIS complexity.

No target-repository write, production change, merge, deploy, or trading/capital action was performed.
