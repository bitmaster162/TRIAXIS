# TRIAXIS v2.8-RC2 — Validation Receipt

```text
DATE: 2026-08-03
BASELINE_COMMIT: 18d0be31a83771f50dfacf850c99361458125ff7
LOGIC_PATCH_COMMIT: d60a4a5cafbb93d14c8ff9f01e94628bf0dc3313
RC2_VALIDATION_STATE_COMMIT: 686ba76ae0d132de59ae275e0d91947d5516099b
SPECIFICATION_STATUS: RELEASE_CANDIDATE
IMPLEMENTATION_STATUS: PARTIALLY_IMPLEMENTED — DETERMINISTIC GATES ONLY
```

## Deterministic evidence

| Batch | Cases | Result | Case SHA-256 | Result SHA-256 |
|---|---:|---:|---|---|
| H1 | 24 | 24/24 | `a97044760755316801d0c6dcd9de839c9f00e1947386108953ea3aeb6d6cba8b` | `93cdc7ed29b382bf256e0cb5798cb4ef1bfa52c2d221e4f675b43f54c150967b` |
| H2 | 24 | 24/24 | `06b57865e50a5b8437e643b1532a534c5956ca60d3b5104faf675e9888391cf9` | `5f7116ee2a09ceb155a7fc8d4530cba142bd4dde51d0989acc3379f08d1008b7` |
| H3 | 24 | 24/24 | `d72ae88395c23a4a2bfbd27aa25deb621429c0c3b378a3a75e35aed2b1ebcfef` | `7e23b44b79a31afc2a6fcf405b80548c78405d9034cea580d325397bdcf8553c` |
| H4 | 24 | 24/24 | `3999a055bcaf6a5a8e9b76603cffae52d9a770b78dfe3cfe6ae8f4e9d10079ca` | `074795cc8c19c2b57c02058d51837cf0c40683639da5532105819d5879b0c763` |
| P1 | 32 | 32/32 | `75fd6485fe7c939c5c060aed4e51ff69315078e897a7459af583c6a3987b623f` | `1a608a23c12733524ec345913960f662fc71bc79ffbddbfc04dcd57b935e46bb` |
| P2 | 32 | 32/32 | `81d31c8041fd3a52291f8716253510824ee4b5efd5e6e46c4bafb84bcd1a0f3f` | `02d3a1c8f1ceb3f0be3354f2a309c3b740e300139ceb369c33af85ac1eabdbee` |
| Q1 | 28 | 28/28 | `aa42ca757a38ad8f3372d28ef4ea1c770bbafd5657fb650e398596037b7ad15e` | `fc4c644ac4414decf2bc8ee328b256629798a06ac3bcdbd16977140eb90fce62` |
| Q2 | 28 | 28/28 | `4d5afcfea96e445dcd1d228430e3b1937a679c9a3dd79eef82ec2328f3b858a5` | `02c9c1bb21b541a1e353d3bc5d397c1aed10b63934f3264447a149677deeee19` |

```text
TOTAL FROZEN BATCH RELATIONS: PASS 216 / FAIL 0
UNIT TESTS AT RC2: PASS 25 / FAIL 0
FULL INPUT FAULT TEMPLATE BANK: PASS 39 / FAIL 0
```

## Evidence classification

- H/P/Q results are deterministic source-backed test evidence within their exact structured scope.
- Q2 is fresh relative to the v2.8-RC1 logic commit.
- The suite and implementation were produced in the same development process; this is not independent assurance.
- Natural-language extraction, generative control quality, live external actions and production qualification remain unverified.
