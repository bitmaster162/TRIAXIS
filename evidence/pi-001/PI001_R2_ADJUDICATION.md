# TRIAXIS PI-001 R2 Real Cedar End-to-End Adjudication

Work Order: `TRIAXIS-WO-PRODUCT-PI-001-R2`
Date: `2026-08-08`
PR: `#4`
Branch: `product/pi-001-authorization-boundary`

## 0. Final Operator Disposition
`PI001_STATUS=EVIDENCE_READY`
`PRODUCT_INTEGRATION=true`
`PRODUCTION_QUALIFIED=false`
`CAN_TRADE=false`
`CAPITAL_PERMISSION=DENY`
`DEPLOY_PERMISSION=DENY`

## 1. Separate Policy Hash Domains
- `triaxis_policy_sha256`: `2d8a91b38e5b4f03d1d2b742020e2415494ba6922ea6151a960ff94c684c0458`
- `cedar_policy_sha256`: `92b41e33f8ed64fb73a178238a9111ea54f4cc94c77b7df871366a42d99ef472`
- Verified: Both hashes preserved independently without conflation across request, receipt, and authorization token.

## 2. Real Cedar E2E Chain Verification
- Executable: `/home/bit/.cargo/bin/cedar`
- Executable Version: `cedar-policy-cli 4.12.0`
- Executable SHA-256: `b20d8186de45e57e13d06a981c6b562e171d7f1de94f2746c8857aa4f8126b3d`
- Real Subprocess Output: `ALLOW` (Exit Code `0`)
- PEP Verified ALLOW: `True`
- Authorization Token SHA-256: `14469758244217784e0584d85457f357285a3d78906fcc28b5d02b9539fff441`
- SQLite Execution Ledger State: `PREPARED`

## 3. Test Suite Regression Totals
- Historical Baseline Tests Passed: `533 / 533`
- PI-001 / R1 / R2 Tests Passed: `32 / 32`
- Total Suite Passed: `565 / 565`
- Existing Regressions: `0`

## 4. Safety Constraints
- Do NOT merge PR #4.
- Do NOT start PI-002.
- Research queue remains PAUSED (`E004_BLOCKED=true`).
