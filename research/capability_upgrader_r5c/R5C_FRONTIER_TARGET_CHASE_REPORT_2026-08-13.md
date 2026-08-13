# TRIAXIS R5-C — FRONTIER TARGET CHASE

Date: 2026-08-13 (Asia/Bangkok)

## Executive result

R5-C is a **hard negative**.

The current combination:

`GPT-5.6 Sol + D_REPO_BEHAVIOR + D_LONG_HORIZON v1`

did **not** close the selected repo-scale proxy gap.

All four frozen arms converged on the same repair direction:
remove an apparently stale `wizard.ENV_FILE` reference from a legacy closure test.

Future repository gold proved that direction incomplete and materially wrong for compatibility.

Final status:

- `FRONTIER_GAP_CLOSED = NO`
- `B0/B1/B2/B3 = REPAIR_MISMATCH`
- `B3_INCREMENTAL_LIFT = 0`
- `POTENTIAL_COMPATIBILITY_HARM = YES_NOT_APPLIED`
- `D_REPO_BEHAVIOR + D_LONG_HORIZON_V1 = INSUFFICIENT_ON_THIS_PROXY`

No target-repository change was applied.

## Frontier context

The current OpenAI GPT-5.6 benchmark table reports:

- GPT-5.6 Sol: 64.6% SWE-Bench Pro
- Claude Mythos 5: 80.3%
- Claude Fable 5: 80.0%

So the public repo-scale gap motivating this campaign is about 15.7 / 15.4 percentage points.

R5-C is **not a reproduction of SWE-Bench Pro**. It is a historical real-repository proxy
chosen to test whether the proposed donor combination handles the kind of multi-contract
failure that distinguishes repo-scale work from a local patch.

## Frozen task

Repository:
`bitmaster162/continuityos`

Failed workflow run:
`31531821208`

Failed head:
`90b33960e4ebc7c5ecdc38a06c1504611ec90281`

Observed on Ubuntu:
- 1002 tests collected
- 1 failed
- 995 passed
- 6 skipped
- 8 subtests passed
- release-hardening probes 10/10 passed

Failure:

`test_wizard_and_dashboard_block_before_home_or_memory_effect`

The test failed before exercising the intended effect boundary because it attempted:

`monkeypatch.setattr(wizard, "ENV_FILE", home / ".env")`

while the current `wizard` module had no `ENV_FILE`.

## Arms

### B0 — Sol direct

From the CI log only:

`TEST_CONTRACT_DRIFT`

Repair:
remove the obsolete `ENV_FILE` monkeypatch.

### B1 — minimal verifier

Exact failing test plus `wizard.py` confirmed that current setup uses:
- `HOME`
- `STATE_FILE`
- `DASH_FILE`

and no longer writes `.env`.

B1 therefore retained the same test-only deletion.

### B2 — repo-behavior donor

B2 verified that direct-library containment had not disappeared:
package import installs direct-surface guards and the wizard functions remain wrapped by
CurrentEffectBoundary before real effects.

B2 still concluded that deleting the stale `ENV_FILE` monkeypatch was sufficient.

### B3 — repo-behavior + long-horizon/self-test v1

B3 expanded the graph across:
- clean source
- source pytest
- wheel build
- wheel-only isolated site-packages
- editable install
- full suite
- release probes
- setup default/offline/fast modes
- direct-library current-session containment

It still froze:

`SINGLE_STALE_TEST_FIXTURE_IS_SUFFICIENT_EXPLANATION_AT_THIS_HEAD`

No second repair was predicted.

## Gold chain

After every arm was frozen, future history was opened.

### Gold 1 — compatibility identity

Commit:
`d6a20b7b76abe0c3f42eece0e63883393788dc2b`

`Restore setup compatibility symbol without secret writes`

Instead of deleting the legacy dependency, the repository restored:

`ENV_FILE = HOME / ".env"`

as a **compatibility symbol only**.

The old provider-secret/config write behavior remained removed.

This falsifies the R5-C repair direction.

The missing distinction was:

`symbol compatibility != effect authority`

A symbol can remain part of the compatibility surface while the old side effect stays forbidden.

### Gold 2 — policy routing

Commit:
`9ff91805441c2c0be0255d29ef351aea17add5cf`

`Route setup through offline embedder gate before legacy CLI`

The repair added a product-level setup gate before legacy CLI dispatch:
- default/hash/offline setup uses local `HashingEmbedder`;
- unknown mode fails before setup effects;
- fastembed is explicit opt-in;
- the selected embedder policy is carried across legacy execution.

B3's lifecycle scan did not predict this material product repair.

### Gold 3 — fresh-process regression

Commit:
`4812e740dcbdf2d76de6d873e1aa9f6d1fcb2252`

`Add setup offline policy regression test`

The new subprocess regression proves:
- default `cos setup --quick` does not construct fastembed;
- setup does not create `.env`;
- product dashboard output is produced.

## Final CI verification

The final gold head:

`4812e740dcbdf2d76de6d873e1aa9f6d1fcb2252`

ran `review-gates` as run:

`31532374873`

Result:

`SUCCESS`

Both:
- Ubuntu / Python 3.11
- Windows / Python 3.11

passed.

The pipeline reached and passed:
- clean-source tests;
- wheel build;
- wheel-only external-site-packages tests;
- editable install;
- full editable pytest;
- governance regressions;
- portable release-hardening probes;
- Ubuntu symlink/realpath gate.

Thus the gold is a verified repair chain, not an isolated unit-test patch.

## Adjudication

| Arm | Frozen repair | Gold match | Incremental value |
|---|---|---|---|
| B0 Sol | delete stale ENV_FILE fixture | FAIL | 0 |
| B1 Minimal | same | FAIL | 0 |
| B2 Repo donor | same + invariant validation | FAIL | 0 |
| B3 Repo + long-horizon v1 | same after lifecycle scan | FAIL | 0 |

The important failure is not that Sol missed one line.

It missed two **repo-level distinctions**:

1. **compatibility identity vs removed effect authority**
2. **product policy must bind before delegation into a legacy dispatcher**

Those are exactly the kinds of contracts a capability upgrader must learn.

## Capability-memory update

### F5_COMPATIBILITY_SYMBOL_WITHOUT_EFFECT_AUTHORITY

Before deleting an apparently obsolete symbol:
1. inventory imports, `getattr`, monkeypatches, docs and compatibility tests;
2. separate symbol existence from executable authority;
3. test whether an inert compatibility shim preserves callers without re-enabling the old effect.

### F5_ROUTING_POLICY_BEFORE_LEGACY_DISPATCH

When product policy depends on mode but execution delegates to legacy CLI:
1. map product -> policy resolver -> legacy dispatcher;
2. resolve/validate mode before delegation;
3. carry policy context across legacy execution;
4. test default/offline/fast/unknown modes in fresh processes;
5. invalid mode must fail before effects.

### D_LONG_HORIZON_V2 — hypothesis

New candidate sequence:

`contract inventory`
-> `compatibility/effect split`
-> `authority routing graph`
-> `install/state transition matrix`
-> `fresh-process policy probe`
-> `cross-surface regression`

This is **not promoted** yet.

It must beat D_REPO_BEHAVIOR on fresh matched cases.

## Architecture consequence

R5-C does not justify making TRIAXIS larger.

It justifies making capability memory **more precise**.

Retain:

`gap detector -> minimal router -> targeted donor -> verifier -> bounded correction -> gate -> capability memory`

Full TRIAXIS/EBRC remains controller/audit infrastructure pending actual incremental cognitive lift.

Current status:

`FRONTIER_GAP_CLOSED = NO`

`D_REPO_BEHAVIOR + D_LONG_HORIZON_V1 = INSUFFICIENT`

`D_LONG_HORIZON_V2 = HYPOTHESIS_NOT_VERIFIED`

`DISTINCT_TRIAXIS_CAUSAL_LIFT = UNRESOLVED`

`DEVIL_DEFAULT = OFF`

## Next gate

The next experiment should deliberately select a fresh repo case containing one of the two newly
learned fingerprints.

Run matched:
- B1 minimal verifier
- B2 D_REPO_BEHAVIOR
- B3 D_REPO_BEHAVIOR + D_LONG_HORIZON_V2

The V2 skill earns promotion only if it predicts and verifies a material repair B2 misses.

After several clean successes, compare the resulting upgraded Sol portfolio against real
independent Claude/Gemini calls on frozen tasks.

Until those calls exist, no multi-model synergy claim is allowed.

## Governance

Research only.

No ContinuityOS write.
No production change.
No merge.
No deploy.
No trading/capital permission.
