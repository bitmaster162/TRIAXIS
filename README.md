# TRIAXIS

Versioned specification, deterministic governance-gate projection, and validation assets for the TRIAXIS control stack.

Baseline imported from TRIAXIS v2.3-RC1. Generated archives, manifests, reports, and caches are excluded from Git and emitted under `dist/`.

Current candidate: **TRIAXIS v3.10-RC1 Verifier Epoch and Quorum Anchor**; Release Candidate, not production-qualified.

## TRIAXIS v3.10 cryptographic operational assurance

The research-integrated branch now includes executable reference primitives for:

- evidence independence, freshness, subject binding and contradictions;
- policy lifecycle and deterministic policy traces;
- risk-adaptive assurance routing;
- exact action/payload/state/policy binding;
- single-use authorization and durable execution reconciliation;
- Ed25519-authenticated assurance, state, policy, approvals and gate tokens;
- purpose-bound public-key trust registry with validity and revocation;
- root-signed monotonic registry snapshots with durable rollback/fork rejection;
- separately signed external head witness for whole-local-database rollback detection;
- challenge-bound single-use anchor freshness for witness replay resistance;
- ephemeral verifier epochs and distinct-anchor quorum validation;
- equal-budget project-falsification benchmarking.

Run the complete test suite:

```bash
PYTHONPATH=src:. python -m unittest discover -s tests -v
```

Run the cryptographic authenticity closure trigger:

```bash
PYTHONPATH=src:. python validation/TRIAXIS_CRYPTOGRAPHIC_ISSUER_AUTHENTICITY_TRIGGER_v2.py
PYTHONPATH=src:. python validation/TRIAXIS_TRUST_REGISTRY_ROLLBACK_TRIGGER_v2.py
PYTHONPATH=src:. python validation/TRIAXIS_WHOLE_REGISTRY_DATABASE_ROLLBACK_TRIGGER_v2.py
PYTHONPATH=src:. python validation/TRIAXIS_EXTERNAL_ANCHOR_REPLAY_TRIGGER_v2.py
PYTHONPATH=src:. python validation/TRIAXIS_QUORUM_AND_VERIFIER_EPOCH_TRIGGER_v1.py
```

Generate the legacy digest-only end-to-end example:

```bash
PYTHONPATH=src:. python examples/build_operational_assurance_example.py
```

Score a benchmark result file:

```bash
PYTHONPATH=src:. python tools/triaxis_fail_bench.py benchmark/results_template.jsonl
```

The package is not a production gateway. KMS/HSM custody, authenticated quorum policy, threshold-compromise resistance, complete mediation, trusted time and independent empirical validation remain integration requirements.
