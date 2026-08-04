# TRIAXIS Recovery Baseline

## Verified Git ancestry

This repository was restored from the physically available and verified
`TRIAXIS_v2.10_RC2.git.bundle`.

```text
BUNDLE SHA-256:
18cb732f349f9f777106fb2566b7333c8219b5e7b561dd0f89208857ead85f2d

VERIFIED BASELINE HEAD:
f107f75c3d0972cc6790bcda03de57c83f06fff0

VERIFIED BASELINE TREE:
9d4db0aadef0e9f5942c26849d1b5b603e39e962

BASELINE TESTS:
47 / 47 PASS
```

## Later artifact import

The files listed in `IMPORTED_ARTIFACTS.sha256` were physically available in
this session as a partial v2.34 artifact snapshot. Their bytes are preserved,
but the claimed intervening Git commits and the complete v2.11-v2.34 source
history were not physically available and are not reconstructed or asserted.

The imported v2.34 code is initially incomplete because referenced modules and
support fixtures were absent. Any replacement implementation is committed in
this recovery lineage as new work and must not be represented as byte-identical
to the unavailable historical implementation.

## Status vocabulary

```text
VERIFIED: v2.10 Git history and exact imported artifact bytes.
SOURCE-BACKED CLAIM: commit/test identities written inside imported reports.
UNVERIFIED: unavailable v2.11-v2.34 Git objects and omitted source files.
RECOVERED IMPLEMENTATION: newly reconstructed code in this Git lineage.
```
