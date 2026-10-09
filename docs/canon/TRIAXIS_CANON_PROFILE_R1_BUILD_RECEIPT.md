# TRIAXIS Canon Profile R1 — Build Receipt

Status: `PASS_READBACK_PROFILE_SCRATCH_REGRESSION / DRAFT_ONLY / NO_RUNTIME_EFFECT`

Frozen base:
`main@a292ff969ef291238e8a28a443c090a86e7bd2e7`

Validated implementation head before this receipt-only update:
`7ed1e0fc0d35ca2f2d6886d2162937cc7a16cc52`

Profile branch:
`feat/canon-profile-r1-readonly`

Draft PR:
`#29`

## Exact final delta before receipt update

Five files relative to the frozen base:

1. `canon/TRIAXIS_CANON_PROFILE_R1.json`
2. `src/triaxis/canon_profile.py`
3. `tests/test_canon_profile_r1.py`
4. `docs/canon/TRIAXIS_CANON_PROFILE_R1.md`
5. `docs/canon/TRIAXIS_CANON_PROFILE_R1_BUILD_RECEIPT.md`

No existing TRIAXIS production/runtime source file is modified.

## Exact-byte validation

GitHub readback blob SHAs for the executable profile artifacts:

- `src/triaxis/canon_profile.py`: `b9eba83aa71595facf94b7931f75238cf51fb9f1`
- `tests/test_canon_profile_r1.py`: `1db4d9b4a2cadc8613f39806c0fe00cfc46bfe20`
- `canon/TRIAXIS_CANON_PROFILE_R1.json`: `c7cc0e5a00b453f4d37e7392bd53f4feafae91fe`

Fresh GitHub readback of the repaired profile recomputed to the same git-blob SHA `c7cc0e5a00b453f4d37e7392bd53f4feafae91fe`. No native TRIAXIS checkout was available on the host; validation below is a scratch replay against the read-back profile with the unchanged validator semantics, not GitHub Actions or native-checkout CI.

Bounded test command:

```bash
PYTHONPATH=src:. python tests/test_canon_profile_r1.py
```

Fresh scratch regression result after the D130 evidence repair: **6 / 6 PASS**.

Validated cases:

1. exact frozen baseline -> `PASS_CANON_PROFILE_READ_ONLY`;
2. main SHA drift -> `HOLD_BASELINE_DRIFT`;
3. duplicate decision IDs -> fail closed;
4. research evidence cannot satisfy `VERIFIED_MAIN`;
5. selected-decision/entry mismatch -> fail closed;
6. research/gap/outside states remain non-authoritative and canon promotion remains DENY.

The validator is standard-library-only and performs no external I/O.

## Current evidence ceiling

This PASS proves only that the project-specific canon profile and validator behave as designed on the exact tested bytes.

It does **not** prove:

- all D001–D136 are implemented by TRIAXIS;
- production qualification;
- repository-wide complete mediation;
- draft PR #28 behavior is current main;
- research PR #7 is production current;
- D137+ canon promotion;
- deployment/provider effects;
- production-ledger mutation;
- trading/capital action;
- autonomous repair.

## Effect boundary

- merge: `DENY`
- deploy: `DENY`
- provider/vendor effect: `DENY`
- production ledger mutation: `DENY`
- trading/capital: `DENY`
- canon promotion: `DENY`
- GitHub Actions manual dispatch/rerun: `DENY`

This receipt records one evidence-only profile repair: D130 no longer claims an independent review that is absent on PR #29. Validator source and test source bytes are unchanged; merge/deploy/provider/trading/capital authority remain DENY.
