# TRIAXIS E003 — Rekor / in-toto Transparency Anchor

## Overview
This experiment evaluates Sigstore Rekor transparency logs and in-toto software supply chain attestation predicates for TRIAXIS authorization policies and build artifacts.

## Structure
- `reproduce/run_e003_rekor_intoto.py`: Executable real-runtime test runner.
- `corpus/e003_transparency_corpus.json`: 15 transparency corpus test cases.
- `receipts/`: Verified real-runtime receipts, matrices, binary provenance, and adjudication receipts.

## Execution
Run natively in Linux WSL2:
```bash
python3 reproduce/run_e003_rekor_intoto.py
```
