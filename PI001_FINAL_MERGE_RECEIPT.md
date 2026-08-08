# TRIAXIS PI-001 Final Merge Receipt

Work Order ID: `TRIAXIS-WO-PRODUCT-PI-001-FINAL-MERGE`
Date: `2026-08-08`
Repository: `bitmaster162/TRIAXIS`
Target Branch: `main`

---

## 0. Canonical Status & Operator Adjudication

`PI001=CLOSED_ACCEPT`
`PI002_UNBLOCKED=true`
`E004_BLOCKED=true`
`RESEARCH_QUEUE_PAUSED=true`
`PROJECT_STATUS=ACCEPTED_PRODUCT_SLICE`
`PRODUCT_INTEGRATION=true`
`PRODUCTION_QUALIFIED=false`
`CAN_TRADE=false`
`CAPITAL_PERMISSION=DENY`
`DEPLOY_PERMISSION=DENY`

---

## 1. Git & Remote Merge Provenance

- **Pull Request**: `#4` (`product/pi-001-authorization-boundary` -> `main`)
- **PR State**: `MERGED`
- **Expected Pre-Merge Main HEAD**: `a5d46712aaed3304dd2c3089ae79567ef3e12dba`
- **Expected PR Feature HEAD**: `5a33297fc11833513a30823027494114f5033e40`
- **Merge Commit SHA**: `53e85b9ee6142ba997e1bad6c3f0be9248333479`
- **Final Full Repository Tree SHA**: `6ae7116c96d087889e0bf6e31df5195ccdcde0b8`
- **Final `HEAD:src` Tree SHA**: `6aa627b4398e9392f624f5d276d5fd5d3ea464bd`
- **Source Tree Verification**: `POST_MERGE_SRC_TREE_GATE=PASS` (matches exact required SHA `6aa627b4398e9392f624f5d276d5fd5d3ea464bd`)

---

## 2. Executable & Policy Provenance

- **Cedar PDP Executable Path**: `/home/bit/.cargo/bin/cedar`
- **Cedar PDP Version**: `cedar-policy-cli 4.12.0`
- **Cedar Binary SHA-256**: `b20d8186de45e57e13d06a981c6b562e171d7f1de94f2746c8857aa4f8126b3d`
- **Cedar Policy File**: `src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar`
- **Cedar Policy SHA-256**: `92b41e33f8ed64fb73a178238a9111ea54f4cc94c77b7df871366a42d99ef472`
- **TRIAXIS Policy SHA-256**: `2d8a91b38e5b4f03d1d2b742020e2415494ba6922ea6151a960ff94c684c0458`

---

## 3. Post-Merge Test Regression Verification

- **Execution Command**: `PYTHONPATH=.:src python3 -m pytest tests/`
- **Raw Pytest Output Artifact**: `evidence/pi-001/PI001_POST_MERGE_RAW_PYTEST_OUTPUT.txt`
- **Total Suite Tests**: `568`
- **Historical Baseline Tests Passed**: `533 / 533`
- **PI-001 / R1 / R2 / R2.1 Product Integration Tests Passed**: `35 / 35`
- **Total Passed**: `568 / 568`
- **Failed**: `0`
- **Existing Regressions**: `0`

---

## 4. Bounded Scope & Safety Invariants

- **No Release Tag**: No git release tag created.
- **No Deployment**: No deployment to staging or production executed.
- **No Production Activation**: Trading engine and capital allocation permissions strictly `DENY`.
- **PI-002 Execution**: PI-002 is unblocked for future execution but NOT started in this turn.
- **Research Queue**: Queue remains `PAUSED` with `E004_BLOCKED=true`.
