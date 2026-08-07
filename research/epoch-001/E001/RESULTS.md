# EXPERIMENT RESULTS — E001

## Revision History
| Rev | Date | Scope | Evidence Classification |
|:---|:---|:---|:---|
| R0 | 2026-08-07 | Simulator | `EXECUTED_RESULT / LOCAL_MODEL_ONLY` |
| R1 | 2026-08-07 | Real SPIRE v1.15.2 Runtime | `EXECUTED_RESULT` |

## R1 — Real SPIRE Runtime Results (Supersedes R0)

* **Runtime**: SPIRE v1.15.2 (official release binaries)
* **Platform**: Linux LAPTOP-F1UKDD7T 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Th...
* **Trust Domain**: `triaxis.test`
* **Real Server + Agent**: YES (not simulator)
* **Product Integration**: `False`

### Evidence Summary

| Test | Result |
|:---|:---|
| X509-SVID Issuance | `True` |
| SVID Rotation (120s TTL) | `True` |
| Negative Attestation | `PASS: SPIRE correctly withheld unauthorized-workload SVID from current process (UID mismatch)` |
| Entitlement Withdrawal | `EXECUTED` |
| CRL Revocation | `NOT_EXECUTED` |

### Detailed Receipts
All evidence receipts are in `receipts/real-spire/`:
- `SPIRE_RELEASE_PROVENANCE.md` — Tarball hash verification against GitHub release
- `WORKLOAD_API_X509_SVID_RECEIPT.md` — X509-SVID certificate details + chain verification
- `NEGATIVE_ATTESTATION_RECEIPT.md` — UID mismatch prevents unauthorized SVID issuance
- `ROTATION_RECEIPT.md` — SVID fingerprint comparison pre/post TTL window
- `ENTITLEMENT_WITHDRAWAL_RECEIPT.md` — Server entry deletion + Workload API behavior
- `SPIRE_RUNTIME_CONFIG_REDACTED.md` — Configuration (join token redacted)

## R0 — Simulator Results (Reclassified)

* **Original Status**: `EXECUTED_RESULT`
* **Reclassified To**: `EXECUTED_RESULT / LOCAL_MODEL_ONLY`
* **Reclassification Reason**: Operator adjudication — simulator does not constitute real SPIRE runtime evidence
* **Simulator Test Suite Result**: 5 / 5 PASS (0 errors, 0 failures)
* **Simulator Evidence Location**: `receipts/e001_execution_receipt.json`
