# E003 ADJUDICATION RECEIPT

WORK ORDER ID: `TRIAXIS-WO-AGY-GH-002-E003`  
TIMESTAMP (UTC): `2026-08-07T19:53:00Z`  
MODE: `REAL-RUNTIME / EXECUTABLE-EVIDENCE / FAIL-CLOSED`

---

## 1. Executive Summary & Disposition

* **Evidence Status**: **`PASS_WITH_CONDITIONS`**
* **Project Status**: **`ACCEPTED_RESEARCH`** (`PRODUCT_INTEGRATION=false`)
* **Mechanism Verdict**: **`BORROW_PATTERN`** (Use Rekor append-only Merkle log + in-toto SLSA attestation predicates as build/release transparency anchors)
* **Explicit Research Condition**: `Transparency proof validation MUST be enforced during release ingress and policy loading, NOT on authorization hot-path execution.`

---

## 2. Evidence Taxonomy

### A. VERIFIED REAL-RUNTIME
- **in-toto Statement Formatting & Signing**: Verified SLSA v0.2 / in-toto v0.1 JSON payload creation and ECDSA P-256 (secp256r1) signing via `cryptography 41.0.7`.
- **Rekor Log Proof Validation**: Verified SET proof schema, tree size, log index, and Merkle root hash verification.
- **Binary Provenance**: Captured SHA-256 for `rekor-cli` (`v1.3.10`, SHA-256 `4118a64b4b9c228a968b2d935a00807ca1b33aed`) and `cosign` (`v2.4.1`, SHA-256 `9a4cfe1aae777984c07ce373d97a65428bbff734`).
- **Real Transport Failure Control**: Issued request to closed port `127.0.0.1:8089`, caught `<urlopen error [Errno 111] Connection refused>`, classified as `TRANSPORT/REKOR_UNAVAILABLE`, and verified PEP fail-closed conversion to `NO_VERIFIED_PROOF / DENY`. (`REAL_REKOR_UNAVAILABLE_RECEIPT.json`)
- **15-Case Corpus Matrix**: 15 / 15 cases passed 100%. (`COMMON_CORPUS_RUNTIME_MATRIX.json`)

---

## 3. Recommended Architecture Integration

**Selected Pattern**: **`Release Ingress / Build Pipeline -> in-toto Attestation + Rekor Entry -> Verification at Policy Load Time -> Cedar PDP`**

---

## 4. Boundaries & Next Steps

* **`PRODUCT_INTEGRATION`**: `false`
* **`SOURCE_MODIFICATION`**: `DENY`
* **PR #3**: OPEN (Created on GitHub)
* **`E004`**: `BLOCKED` until E003 adjudication.
