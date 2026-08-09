# TRIAXIS PI-002 FINAL MERGE RECOVERY RECEIPT

WORK ORDER ID: `TRIAXIS-WO-PRODUCT-PI-002-FINAL-MERGE-RECOVERY`

## 1. Provenance & Head Drift Reconciliation

* **Expected Adjudicated HEAD**: `26889dc32fb5d1015b85524517f0020b71f43da0`
* **Actual Merged PR HEAD**: `620f8dd2c871978ca7cabf4f7586c9bc6a7867d9`
* **Ancestor Status**: `26889dc32fb5d1015b85524517f0020b71f43da0` IS AN ANCESTOR OF `620f8dd2c871978ca7cabf4f7586c9bc6a7867d9` (`git merge-base --is-ancestor` returned True).
* **Reason for Head Advancement**: PR #5 head moved from `26889dc` to `620f8dd` during the final leaf profile correction task to commit the 11 mandatory focused X509 leaf constraint controls and the machine-readable validation matrix `PI002_R1_1_X509_VALIDATION_MATRIX.json` requested by the operator before merge execution.

---

## 2. Tree Integrity & Merge Verification

* **Pre-Merge main HEAD**: `d44a2b6d4987fdf55796cc9199b917e4cc35df90`
* **Pre-Merge main Full Tree**: `23f669ae1667b2ff68f6afcebe098e945c5890fa`
* **Pre-Merge main Src Tree**: `6aa627b4398e9392f624f5d276d5fd5d3ea464bd`
* **PR #5 Head**: `620f8dd2c871978ca7cabf4f7586c9bc6a7867d9`
* **PR #5 Full Tree**: `d5d923b4431c208560ae3a2b3469d721a89a436f`
* **PR #5 Src Tree**: `437cba86c4dfecd5b12498bf22268a35a00c6843`
* **Merge Commit SHA**: `6c70de3715ed9fb0f9e3531c7c646a636544ba5f`
* **Merge Commit Parents**:
  1. `d44a2b6d4987fdf55796cc9199b917e4cc35df90` (pre-merge main)
  2. `620f8dd2c871978ca7cabf4f7586c9bc6a7867d9` (merged PR #5 head)
* **Post-Merge main HEAD**: `6c70de3715ed9fb0f9e3531c7c646a636544ba5f`
* **Post-Merge main Full Tree**: `d5d923b4431c208560ae3a2b3469d721a89a436f`
* **Post-Merge main Src Tree**: `437cba86c4dfecd5b12498bf22268a35a00c6843`

---

## 3. Regression & Security Verification

* **PR State**: `MERGED` (`mergedAt: 2026-08-09T02:57:23Z`)
* **PR Number**: `5`
* **Merge Method**: `merge` (Standard merge commit, no squash, no rebase)
* **Regression Result**: `607 / 607 PASS` (`0 FAILURES`, `0 REGRESSIONS`)
* **Targeted PI-002 Test Suite**: `39 / 39 PASS`
* **Runtime Subprocess Usage**: `0` (Confirmed via `grep -RIn "subprocess" src/triaxis/identity/spiffe_provider.py`)
* **Private Key Serialization**: `NONE_OBSERVED` (Confirmed zero PEM private key leaks in evidence/src)

---

## 4. Classification & Final Status

`HEAD_DRIFT_CLASSIFICATION=NON_SOURCE_EVIDENCE_AND_LEAF_CONSTRAINT_HARDENING`
`PI002=CLOSED_ACCEPT`
`PI003_UNBLOCKED=true`
`E004_BLOCKED=true`
`RESEARCH_QUEUE_PAUSED=true`
