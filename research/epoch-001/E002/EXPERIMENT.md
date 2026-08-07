# EXPERIMENT DESIGN — E002

## Methodology
The E002 shootout executes the 20-case Common TRIAXIS Authorization Corpus across four authorization candidate architectures:

1. **Cedar (AWS)**: `cedar-policy-cli` v4.1.0 / `cedar` engine evaluating `.cedar` policies and `.json` entities/requests.
2. **OPA (CNCF)**: `opa` v1.0.0 evaluating `.rego` policies and `.json` inputs via `opa eval`.
3. **OpenFGA (CNCF)**: `openfga` v1.8.3 server + `fga` v0.6.3 CLI evaluating `.fga` DSL models, tuples, and check requests.
4. **AuthZEN (OIDF)**: AuthZEN 1.0 Authorization API specification analysis + conformant REST payload mapping.

## Test Harness Architecture
A single master reproduction runner [`reproduce/run_e002_shootout.py`](file:///c:/PROJECTS/continuity_os/tmp_triaxis_closure_clone/research/epoch-001/E002/reproduce/run_e002_shootout.py):
1. Loads [`corpus/triaxis_authorization_corpus.json`](file:///c:/PROJECTS/continuity_os/tmp_triaxis_closure_clone/research/epoch-001/E002/corpus/triaxis_authorization_corpus.json).
2. Executes candidate prototypes in `prototype/`:
   - `prototype/test_cedar.py`
   - `prototype/test_opa.py`
   - `prototype/test_openfga.py`
   - `prototype/test_authzen.py`
3. Records pass/fail, decision accuracy, failure mode behavior, and timing metrics.
4. Outputs JSON execution receipt to `receipts/e002_execution_receipt.json`.

## Rules & Isolation
- **Product Code Modifications**: `0` (Zero edits to `src/`).
- **Execution Platform**: WSL2 Linux (Ubuntu 24.04).
- **FAIL-CLOSED**: Any error, missing policy, or unhandled condition MUST resolve to `DENY`.
