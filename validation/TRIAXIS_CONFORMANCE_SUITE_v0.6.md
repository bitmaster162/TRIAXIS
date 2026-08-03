# TRIAXIS Conformance Suite v0.6

## Holdout layer terminal receipt

| Batch | Candidate at fresh run | Fresh result | Patch version that closed failures |
|---|---|---:|---|
| H1 | v2.3-RC1 | 11/24 | v2.4-RC1 → 24/24 regression |
| H2 | v2.4-RC1 | 23/24 | v2.5-RC1 → 24/24 regression |
| H3 | v2.5-RC1 | 23/24 | v2.6-RC1 → 24/24 regression |
| H4 | v2.6-RC1 | 24/24 | no logic patch |

```text
CURRENT CANDIDATE: v2.6-RC2
HOLDOUT_v1 STATUS: TERMINAL WITHIN ENCODED CASE BANK
CUMULATIVE REGRESSION: PASS 96 / FAIL 0
NEXT VALIDATION CLASS: METAMORPHIC / COMBINATION / FAULT-INJECTION
```
