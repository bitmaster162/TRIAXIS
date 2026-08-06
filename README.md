# TRIAXIS

Versioned specification, deterministic governance-gate projection, and validation assets for the TRIAXIS control stack.

Baseline imported from TRIAXIS v2.3-RC1. Generated archives, manifests, reports, and caches are excluded from Git and emitted under `dist/`.

Current candidate: **TRIAXIS v3.16-RC1 External Policy Transparency Gossip Head**; Release Candidate, not production-qualified.

## TRIAXIS v3.12 external policy-head assurance

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
- root-signed monotonic quorum policy with exact policy-bound witnesses;
- external challenge-bound Policy Head Authority for whole-local-policy-store rollback detection;
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
PYTHONPATH=src:. python validation/TRIAXIS_AUTHENTICATED_QUORUM_POLICY_TRIGGER_v1.py
PYTHONPATH=src:. python validation/TRIAXIS_EXTERNAL_POLICY_HEAD_AUTHORITY_TRIGGER_v1.py
```

Generate the legacy digest-only end-to-end example:

```bash
PYTHONPATH=src:. python examples/build_operational_assurance_example.py
```

Score a benchmark result file:

```bash
PYTHONPATH=src:. python tools/triaxis_fail_bench.py benchmark/results_template.jsonl
```

The package is not a production gateway. v3.12 detects rollback of the local policy store only while an independently operated external Policy Head Authority remains current. KMS/HSM custody, authority-side anti-rollback, multi-authority consistency, complete mediation, trusted time and independent empirical validation remain integration requirements.

## v3.14 Policy Transparency Floor

The v3.14 branch adds an independent challenge-bound transparency-witness quorum that enforces a minimum policy version/digest against the verified local signed history. See `release/TRIAXIS_CONTROL_STACK_v3.14_RC1_POLICY_TRANSPARENCY_FLOOR.md`.

## v3.15 Persistent Policy Transparency Gossip

The v3.15 layer persists the highest verified floor per transparency witness and rejects cross-session rollback or same-version fork claims. See `release/TRIAXIS_CONTROL_STACK_v3.15_RC1_POLICY_TRANSPARENCY_GOSSIP.md`.

## v3.16 External Policy Transparency Gossip Head

The v3.16 layer exports the verifier gossip state into a signed monotonic checkpoint, stores it in an independently persisted external authority, and verifies a fresh challenge-bound head before trusting the local gossip database. See `release/TRIAXIS_CONTROL_STACK_v3.16_RC1_EXTERNAL_GOSSIP_HEAD.md`.
