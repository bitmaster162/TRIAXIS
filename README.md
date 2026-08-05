# TRIAXIS

Versioned specification, deterministic governance-gate projection, and validation assets for the TRIAXIS control stack.

Baseline imported from TRIAXIS v2.3-RC1. Generated archives, manifests, reports, and caches are excluded from Git and emitted under `dist/`.

Current candidate: **TRIAXIS v2.10-RC2** — RS4 53/53, SI4 37/37, CS3 21/21, unit/regression 47/47; Release Candidate, not Production-qualified.

## TRIAXIS v3.2 operational assurance

The research-integrated branch now includes executable reference primitives for:

- evidence independence, freshness, subject binding and contradictions;
- policy lifecycle and deterministic policy traces;
- risk-adaptive assurance routing;
- exact action/payload/state/policy binding;
- single-use authorization and durable execution reconciliation;
- equal-budget project-falsification benchmarking.

Run the complete test suite:

```bash
PYTHONPATH=src:. python -m unittest discover -s tests -v
```

Generate the end-to-end non-production example:

```bash
PYTHONPATH=src:. python examples/build_operational_assurance_example.py
```

Score a benchmark result file:

```bash
PYTHONPATH=src:. python tools/triaxis_fail_bench.py benchmark/results_template.jsonl
```

The package is not a production gateway. Complete mediation, external identity/KMS, trusted time and independent empirical validation remain integration requirements.
