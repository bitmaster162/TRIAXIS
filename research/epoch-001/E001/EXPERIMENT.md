# EXPERIMENT DESIGN — E001

## Executable Prototype Target
Build a standalone Python prototype (`spiffe_identity_model.py`) modeling:
1. Trust Domain setup (`spiffe://triaxis.internal`).
2. Workload Attestor inspecting process execution context.
3. SPIRE Server issuing X.509 & JWT SVIDs with automated cryptographic key signatures.
4. Workload Client fetching SVIDs via Workload API and validating peer identities.
5. SVID rotation and revocation testing.

## Execution Rules
* Zero source code edits to `src/`.
* Reproduction script: `research/epoch-001/E001/reproduce/run_e001_experiment.py`.
