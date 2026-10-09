# TRIAXIS R5-A — F5 Repo-Scale Donor Wave

Date: 2026-08-12 (Asia/Bangkok)

## Result

This wave tested whether a targeted repository-behavior donor can discover a material repository invariant that a local fix plus focused verifier misses.

Narrow result:

`D_REPO_BEHAVIOR -> 1 incremental defect discovery over B1`

This is **not yet a verified product-repair rescue** because the target repository was not modified.

## Synthetic wrapper-composition sanity check

A synthetic wrapper-composition mutation produced B0 FAIL / B1 FAIL / B2 PASS, but it is excluded from claim-grade evidence because the correct current wrapper order had already been inspected before arm freeze.

Status: `CONTAMINATED_BY_PREEXPOSURE`.

## Real CI replay 1 — R33 killswitch

Failed run: `31561738850`

Head: `690ff69ca76ebeed8145dec5a9d70ea9f5541962`

B0/B1 froze `TEST_STALE`: local SQLite-state failure had intentionally become non-fatal for exchange cancellation, while an old regression still expected a pre-network stop.

Post-freeze history confirmed the stale-test repair class, but the branch also needed a separate positional-compatibility fix. B2 had not predicted that issue, so B2 receives **zero post-hoc credit**.

Capability-memory fingerprint added:

`F5_SCHEMA_ABI`: record/dataclass field insertion or reordering requires explicit positional-construction, destructuring, and serialization compatibility scans before PASS.

## Real CI replay 2 — reconcile-chain integrity R6

Failed run: `31544903853`

Head: `da4098f9300f1d674a67b720e7362f8379e9c7bb`

CI failed because `test_reconcile_persists_chain_scoped_timestamp` still expected `last_reconcile_chain == "eth"`, while the head intentionally stopped writing ETH into a legacy BSC-only key.

### B0 / B1

Both correctly classify the immediate failure as a stale regression expectation.

Local repair:
- legacy `last_reconcile_chain` absent;
- global timestamp retained;
- `last_reconcile_at_eth` equals the reconciliation completion time.

Post-freeze commits confirm this repair class.

### B2 repo-behavior donor

Before gold, B2 followed the authoritative-state graph:

`writer -> integrity validator -> runtime reader`

and found a second defect class.

The multichain implementation makes `last_reconcile_at_<chain>` canonical state. `ops._build_execution_snapshot` reads the per-chain key first. But `PositionState.audit_integrity()` validates runtime datetime values by iterating `_RUNTIME_DATETIME_KEYS`, and that set contains legacy `last_reconcile_at` but not `last_reconcile_at_bsc` or `last_reconcile_at_eth`.

The same omission remains on current `master` as of this wave.

Therefore a malformed canonical per-chain reconcile timestamp can bypass the runtime datetime integrity validator.

Status:

`F5_CANONICAL_STATE_VALIDATION_GAP = CURRENT_SOURCE_STATICALLY_PROVEN_INCREMENTAL_DEFECT_DISCOVERY`

Recommended repair, **not applied**:
1. validate supported `last_reconcile_at_<chain>` keys in `audit_integrity`;
2. add malformed per-chain timestamp quarantine/clear regression;
3. verify valid scoped timestamps survive while malformed values are rejected/cleared.

## Matched adjudication

| Arm | Immediate CI failure | Extra repo defect |
|---|---|---|
| B0 Direct | repair | 0 |
| B1 Minimal verifier | repair | 0 |
| B2 Repo-behavior donor | repair | **1** |

Thus:

`B2_INCREMENTAL_DEFECT_DISCOVERY_OVER_B1 = 1`

but:

`B2_VERIFIED_PRODUCT_REPAIR_LIFT = NOT_YET_DEMONSTRATED`

because target production code was intentionally not changed.

## Architectural effect

The useful donor behavior is now concrete:

`identify authoritative state -> enumerate writers -> enumerate validators -> enumerate readers -> test scope migration`

Capability-memory additions:
- `F5_SCHEMA_ABI`
- `F5_CANONICAL_STATE_VALIDATION_GAP`

Current state:
- `D_REPO_BEHAVIOR = SUPPORTED_ON_ONE_CLEAN_REPLAY_FOR_INCREMENTAL_DEFECT_DISCOVERY`
- `D_LONG_HORIZON = NOT_YET_SEPARATELY_DEMONSTRATED`
- `FULL_TRIAXIS_INCREMENTAL_LIFT = UNRESOLVED`
- `DEVIL_DEFAULT = OFF`

## Next gate

Use a fresh clean replay where B2's additional repo-level finding can be patched in an isolated checkout and run through the actual regression suite while B0/B1 remain local-only.

That is required to upgrade the evidence from **incremental discovery** to **verified repair rescue**.

## Governance

Research only. No target-repository write, production change, merge, deploy, or trading/capital permission.