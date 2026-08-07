# E003 — FAIL-CLOSED MATRIX

| Condition | Failure Trigger | Handled By | Outcome | Distinction from Engine Denial |
|:---|:---|:---|:---|:---|
| **Network Outage** | Connection Refused on 127.0.0.1:8089 | PEP Fail-Closed | `DENY` | `TRANSPORT/REKOR_UNAVAILABLE` strictly distinguished |
| **Invalid Signature** | Corrupted signature bytes | Cryptography Evaluator | `DENY` | Cryptographic signature failure |
| **Missing Inclusion Proof** | Attestation payload lacks Rekor SET | Transparency Verifier | `DENY` | Missing proof of inclusion |
| **Merkle Root Mismatch** | Corrupted Merkle tree root hash | SET Verifier | `DENY` | Integrity verification failure |
| **Expired Attestation** | Timestamp exceeds max skew | Skew Policy Gate | `DENY` | Policy threshold enforcement |
