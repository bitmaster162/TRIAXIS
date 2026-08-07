# E003 — EXPERIMENT DESIGN

**Work Order ID**: `TRIAXIS-WO-AGY-GH-002-E003`  
**Mode**: `REAL-RUNTIME / EXECUTABLE-EVIDENCE / FAIL-CLOSED`

## 1. Experimental Setup
* **Attestation Framework**: in-toto Statement (`https://in-toto.io/Statement/v0.1`) with SLSA Provenance (`https://slsa.dev/provenance/v0.2`).
* **Transparency Log**: Sigstore Rekor append-only Merkle Tree (`rekor-cli v1.3.10`, SHA-256 `4118a64b...`).
* **Signature Algorithm**: ECDSA P-256 (secp256r1) with SHA-256 digest (`cosign v2.4.1`, SHA-256 `9a4cfe1a...`).
* **Evaluation Matrix**: 15 test cases covering valid provenance, payload tampering, invalid signatures, untrusted keys, malformed JSON predicates, clock skew expiration, missing inclusion proofs, Merkle root hash mismatch, key revocation, SLSA compliance level verification, real transport failure control, and log index lookups.

## 2. Test Execution Harness
`research/epoch-001/E003/reproduce/run_e003_rekor_intoto.py` executes natively in Linux WSL2, issuing cryptographic signatures, formatting in-toto Statements, generating Rekor Signed Entry Timestamps (SET), and testing transport fail-closed conversion.
