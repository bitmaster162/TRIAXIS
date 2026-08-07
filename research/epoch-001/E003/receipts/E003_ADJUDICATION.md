# E003 FINAL ADJUDICATION RECEIPT

WORK ORDER ID: `TRIAXIS-WO-AGY-GH-002-E003-FINAL`  
TIMESTAMP (UTC): `2026-08-07T20:10:00Z`  
MODE: `SCOPE-CORRECTION / HONEST-ADJUDICATION / RESEARCH-CLOSURE`

---

## 1. Executive Summary & Final Verdict

* **`EVIDENCE_STATUS`**: **`PASS_WITH_CONDITIONS`**
* **`PROJECT_STATUS`**: **`ACCEPTED_RESEARCH`** (`PRODUCT_INTEGRATION=false`)
* **`MECHANISM_VERDICT`**: **`BORROW_PATTERN`**
* **Explicit Conditions**:
  1. `REKOR_V2_PRODUCT_INTEGRATION=NOT_ESTABLISHED`
  2. `IN_TOTO_PRODUCT_INTEGRATION=NOT_ESTABLISHED`
  3. `TRANSPARENCY_PATTERN_ONLY=true` (Validation MUST be performed during release ingress, policy loading, or evidence archival; MUST NOT be inserted into authorization hot path)

---

## 2. Granular Evidence Taxonomy & Reclassification

### A. REAL EXTERNAL RUNTIME
- **Real Transport Failure Control**: Attempted connection to closed port `127.0.0.1:8089`, caught `<urlopen error [Errno 111] Connection refused>`, classified as `TRANSPORT/REKOR_UNAVAILABLE`, and verified PEP fail-closed conversion to `NO_VERIFIED_PROOF / DENY`. (`REAL_REKOR_UNAVAILABLE_RECEIPT.json`)

### B. REAL LOCAL RUNTIME
- **Local Binary Executions**: Verified local executable runs for `rekor-cli v1.3.10` and `cosign v2.4.1`. (`BINARY_HASHES.txt`)
- **Local Cryptographic Attestation**: Executed ECDSA P-256 (secp256r1) SHA-256 signing and verification via Python `cryptography 41.0.7`.

### C. LOCAL EXECUTABLE MODEL
- **in-toto Statement Schema Model**: Evaluated 15-case corpus using hand-constructed JSON statements matching SLSA v0.2 / in-toto v0.1 format (`LOCAL_CRYPTOGRAPHIC_ATTESTATION_MODEL`).
- **Rekor SET Inclusion Proof Model**: Validated SET proof schemas, Merkle tree root hashes, and log indices (`LOCAL_TRANSPARENCY_MODEL`).

### D. NOT ESTABLISHED
- **Rekor v2 Production Integration**: `NOT_ESTABLISHED` (Rekor v1 compatibility line used; current `sigstore/rekor-tiles` v2.2.1 not integrated into hot path).
- **in-toto Toolchain Integration**: `NOT_ESTABLISHED` (Direct `in-toto 3.1.0` CLI toolchain not invoked; JSON payload schema modeled).

---

## 3. Explicit Operational Boundaries

```text
SIGNED != TRUE
LOGGED != AUTHORIZED
INCLUDED != CURRENT
TRANSPARENCY != POLICY APPROVAL
```

1. **Attestation Signature != Policy Authorization**: Digital signatures prove origin and non-tampering; they do NOT substitute for Cedar policy evaluation.
2. **Rekor Log Inclusion != Authorization Grant**: Ingestion into a transparency log records audit history; it does NOT grant authorization entitlements.
3. **Log Inclusion != Current Validity**: An inclusion entry proves timestamped existence at log time; it does NOT guarantee the policy is unrevoked or current.

---

## 4. Recommended Architecture

**Selected Pattern**: **`Release Ingress / Build Pipeline -> in-toto Attestation + Rekor Entry -> Verification at Policy Load Time -> Cedar PDP`**

---

## 5. Boundaries & Queue Pause

* **`PRODUCT_INTEGRATION`**: `false`
* **`SOURCE_MODIFICATION`**: `DENY`
* **`CAN_TRADE`**: `false`
* **`CAPITAL_PERMISSION`**: `DENY`
* **`E004`**: `BLOCKED`

**Research queue pauses after E003.**
