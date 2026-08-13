# TRIAXIS R5-D — LONG-HORIZON V2 REPLICATION

## Question

R5-C taught the capability upgrader two new repo-scale fingerprints:

1. `F5_COMPATIBILITY_SYMBOL_WITHOUT_EFFECT_AUTHORITY`
2. `F5_ROUTING_POLICY_BEFORE_LEGACY_DISPATCH`

From them we formed the candidate donor:

`D_LONG_HORIZON_V2`

with the sequence:

`contract inventory`
→ `compatibility/effect split`
→ `authority routing graph`
→ `install/state-transition matrix`
→ `fresh-process policy probe`
→ `cross-surface regression`

R5-D asks whether that learned mechanism now adds verified repair value beyond
`D_REPO_BEHAVIOR`.

This is the important test: **does TRIAXIS actually learn from its own failure?**

## Frozen matched arms

- `B1`: minimal verifier
- `B2`: targeted repo-behavior donor
- `B3`: B2 + Long-Horizon V2

B3 earns promotion only for a material pre-gold prediction absent from B2 that is later
verified by real repository repair/regression evidence, with no offsetting harm.

No Claude/Gemini call occurred.

## Case 1 — cos connect / Windows path identity

Run:
`31465525402`

Head:
`473acf67028687f75235bd93139d5f498eb7a1cd`

Ubuntu passed. Windows had one dry-run assertion failure.

The connect surface deliberately canonicalized paths with:

`normcase(realpath(abspath(path)))`

while the test compared against display-case `Path.resolve()` spelling.

All three arms converged on the same repair:
compare against authoritative canonical identity.

Future PR #40 explicitly records the Windows path-case repair and its final head
`4c76fabfcb58af73d4696041424f1180b53c9c92` passed both Ubuntu and Windows.

Result:

`B1 = PASS`
`B2 increment = 0`
`B3(V2) increment = 0`

This is a clean null for V2. Importantly, B3 stopped instead of inventing extra work.

## Case 2 — project-memory bootstrap / exact bytes

Run:
`31319121581`

Head:
`c00e6f215bda1997f508b91983ffc388ab5addbe`

Ubuntu passed. Windows had six failures, all collapsing early into:

`BOOTSTRAP_ARTIFACT_INVALID`

### B1

B1 hypothesized a Windows path-identity mismatch.

That was wrong.

### B2

B2 followed the producer → persisted bytes → manifest SHA → consumer verifier graph.

The test helper did:

- build canonical JSON text with LF;
- `write_text(payload)`;
- return `sha256(payload.encode())`.

On Windows the text write could persist CRLF bytes while the manifest bound the pre-write LF
bytes.

The product correctly re-hashed the actual file bytes and failed closed.

B2 froze the repair:

`encode once -> write_bytes(exact bytes) -> hash those same bytes`

and explicitly preserved exact-byte product validation.

Future repository gold does exactly that.

Final head:

`02a3429b09bb15e9951ef4db2a0b93275384d61d`

uses byte-deterministic fixture writing and passed CI.

Therefore:

`B1 = FAIL`
`B2 = PASS`
`B2_INCREMENTAL_RESCUE_OVER_B1 = 1`

### B3 V2

B3 reached the same immediate repair as B2.

It added no material prediction over B2.

Worse for the V2 hypothesis, later gold also hardened rollback ownership using the published
object's device/inode identity so a concurrent replacement could not be deleted during
cleanup.

B3's state-transition matrix did not predict that additional hardening.

Result:

`B3_INCREMENT_OVER_B2 = 0`

## Original Case 3 — quarantined

Run:
`30672956842`

was opened under the batch, but its log exposed:

- wheel-only `.github/workflows/ci.yml` absence;
- `ActionSpec` / `Ledger` helper/import initialization failures.

That exact failure class had already been analyzed in an earlier ContinuityOS forensic replay.

It is therefore:

`PRIOR_EXPOSURE_CONTAMINATED`

and contributes zero evidence.

## Deterministic replacement Case 3R

The replacement rule was frozen before logs:

take the most recent unconsumed failed ContinuityOS run from the already-opened
newest-first failure metadata, excluding used/prior-exposed cases.

Selected:

Run:
`31377482463`

Head:
`e017d0dc6016e23b2d4ec3991da6156bba101be4`

R54 non-authorizing project-update review materializer.

Both platforms had three clean-source failures.

### B1

B1 froze two repair hypotheses:

1. the clean-source entrypoint test should not require installed `importlib.metadata` after CI
   has explicitly proven project metadata absent;
2. the path guard is applied one level too deep: `_safe_parent(out / probe)` requires the
   fresh `out` directory to already exist, contradicting the materializer's own fresh-output
   contract.

### B2

B2 added a repo/instrument finding:

`importlib.metadata.entry_points()` during clean-source validation is not source-bound and can
observe an ambient/stale installed distribution.

The checked-out `pyproject.toml` already declares the new console script.

### B3 V2

Using the compatibility/lifecycle split, B3 froze one additional prediction:

entrypoint identity should be checked twice, against different authorities:

1. clean-source phase → checked-out source/pyproject declaration;
2. isolated wheel phase → actual installed wheel metadata.

That would prevent both source-only and package-only false confidence.

However this branch remains at the same failing head, no PR exists for it, and the canonical
master does not provide a later R54 materializer repair that can verify the prediction.

So Case 3R is:

`UNVERIFIED_NO_LATER_REPAIR_GOLD`

No arm receives score.

## Aggregate

| Case | B1 | B2 over B1 | B3 V2 over B2 |
|---|---:|---:|---:|
| 1 — connect path | PASS | 0 | **0** |
| 2 — bootstrap bytes | FAIL | **+1 rescue** | **0** |
| 3 | quarantined | — | — |
| 3R | unverified | — | — |

Clean scored cases: **2**

- B2 incremental verified rescues: **1**
- B3 V2 incremental verified rescues: **0**
- B3 harms: **0**
- B3 missed later material hardening: **1**

Promotion rule required:

`>=1 clean incremental verified B3 rescue/prediction + 0 harms`

It was not met.

## Decision

`D_REPO_BEHAVIOR = RETAIN_CONDITIONALLY`

`D_LONG_HORIZON_V2 = NOT_PROMOTED`

The R5-C fingerprints remain useful research hypotheses, but they do **not** become default
router skills merely because they sound plausible.

This is important for the user's original target.

A capability upgrader must not just accumulate "best practices" from other frontier systems.
It must prove that each imported mechanism closes a measured weakness beyond the simpler
mechanism already available.

R5-D says:

`repo-behavior donor > minimal verifier` on one clean case,

but:

`repo-behavior + long-horizon-v2 > repo-behavior`

was **not demonstrated**.

## Architecture consequence

Keep:

`gap detector`
→ `minimal router`
→ `targeted donor`
→ `verifier`
→ `bounded correction`
→ `gate`
→ `capability memory`

Do not globally enable Long-Horizon V2.

Do not enlarge full TRIAXIS/EBRC to hide this null.

Current:

`FULL_TRIAXIS_COGNITIVE_COMPLEXITY = DENY_PROMOTION`

`DISTINCT_TRIAXIS_CAUSAL_LIFT = UNRESOLVED_BUT_NOT_SUPPORTED_BY_R5D`

`FRONTIER_GAP_CLOSED = NO`

`MULTI_MODEL_SYNERGY = UNTESTED`

`DEVIL_DEFAULT = OFF`

## Next research gate

The next useful move is no longer a third version of the same emulated long-horizon donor.

We need a genuinely different information source:

1. **real independent frontier-model calls** on frozen repo cases (Claude/Gemini when actually
   connected), or
2. an external official repo-scale benchmark/harness that can run independently.

Then TRIAXIS can learn donor selection from actual cross-model comparative failures rather
than approximating another model's workflow inside the same Sol session.

No target repository was modified.
No production/merge/deploy/trading/capital authority changed.
