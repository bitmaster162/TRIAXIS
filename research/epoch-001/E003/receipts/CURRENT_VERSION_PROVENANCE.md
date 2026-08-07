# E003 — CURRENT VERSION PROVENANCE & TOOLCHAIN CLASSIFICATION

WORK ORDER ID: `TRIAXIS-WO-AGY-GH-002-E003-FINAL`  
TIMESTAMP (UTC): `2026-08-07T20:10:00Z`

---

## 1. Toolchain Version Lineage & Classification

| Component | Executed Version / Tool | Provenance Line | Operational Classification |
|:---|:---|:---|:---|
| **Rekor v1** | `rekor-cli v1.3.10` | `MAINTENANCE / COMPATIBILITY` | `LOCAL_TRANSPARENCY_MODEL` |
| **Rekor v2 / rekor-tiles** | `sigstore/rekor-tiles v2.2.1` | `CURRENT TRANSPARENCY LINE` | `REKOR_V2_RUNTIME_INTEGRATION=NOT_ESTABLISHED` |
| **Cosign** | `cosign v2.4.1` | `v2 COMPATIBILITY LINE` | `LOCAL_BINARY_EXECUTABLE` |
| **in-toto Toolchain** | `in-toto 3.1.0` (Python) | `CURRENT TOOLCHAIN LINE` | `IN_TOTO_TOOLCHAIN_INTEGRATION=NOT_ESTABLISHED` |
| **Python Cryptography** | `cryptography v41.0.7` | `PYTHON STABLE LINE` | `LOCAL_CRYPTOGRAPHIC_ATTESTATION_MODEL` |

---

## 2. Claim-Scope Taxonomy

- **`REKOR_V1_COMPATIBILITY`**: `LOCAL_TRANSPARENCY_MODEL` (Executed `rekor-cli v1.3.10` binary version check and SET proof schema modeling).
- **`LOCAL_CRYPTOGRAPHIC_ATTESTATION`**: `LOCAL_CRYPTOGRAPHIC_ATTESTATION_MODEL` (Executed ECDSA P-256 secp256r1 signing via `cryptography 41.0.7`).
- **`REAL_EXTERNAL_RUNTIME`**: Real HTTP transport failure control (`urllib.error.URLError Connection Refused` on `127.0.0.1:8089`).
- **`REKOR_V2_PRODUCT_INTEGRATION`**: `NOT_ESTABLISHED`.
- **`IN_TOTO_TOOLCHAIN_INTEGRATION`**: `NOT_ESTABLISHED`.
