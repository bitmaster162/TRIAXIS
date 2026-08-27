# TRIAXIS

Versioned specification, deterministic governance-gate projection, and validation assets for the TRIAXIS control stack.

Baseline imported from TRIAXIS v2.3-RC1. Generated archives, manifests, reports, and caches are excluded from Git and emitted under `dist/`.

Current release: **TRIAXIS v3.30-RC2 Completion-Witness Quorum and Logical WORM Anchor**; RC2 is validation-only, classified `PASS_WITH_CONDITIONS`, and not production-qualified.

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

Generate the current authenticated, risk-mediated reference example:

```bash
PYTHONPATH=src:. python examples/build_authenticated_assurance_example.py
```

The authenticated example uses ephemeral local keys, a deterministic in-process risk adapter, a signed risk-mediation receipt, and disposable local SQLite state. It demonstrates the current authenticated PREPARED contract but does not invoke a provider or establish repository-wide complete mediation.

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

## v3.17 External Gossip Head Authority Quorum

The v3.17 layer requires an operator-pinned threshold of distinct external gossip-head authorities to agree on the exact verifier checkpoint under one fresh challenge. See `release/TRIAXIS_CONTROL_STACK_v3.17_RC1_EXTERNAL_GOSSIP_HEAD_QUORUM.md`.


## v3.18 Single-Host Multi-Process Conformance

The v3.18 layer adds a standard-library HTTP boundary, credential-aware authority runner, systemd/Docker deployment references, and a fault-injection harness that starts three separate authority processes with separate keys, ports and SQLite state. The frozen conformance receipt covers process loss, stale state, split views and restart persistence. It explicitly does **not** claim physical or administrative independence.

Run the harness:

```bash
PYTHONPATH=src:. python validation/deployment_conformance/run_v318_single_host_conformance.py \
  --output /tmp/triaxis-v318-conformance.json
```


## v3.27 External Execution Ledger

The v3.27 layer moves mutating-effect idempotency outside the rollback domain of the local dispatch queue. A stable `effect_id` binds the persisted queue item, exact action envelope, and canonical target while excluding volatile claim, dispatch, provider-request, and authorization-token identities. The separately persisted ledger issues Ed25519-signed monotonic receipts and blocks any new attempt while the effect is `RESERVED`, `IN_FLIGHT`, `UNKNOWN`, or `COMPLETED`.

Run the exact closure:

```bash
PYTHONPATH=src:. python validation/execution_ledger/run_v327_external_execution_ledger_closure.py
```

A v3.27 PASS proves only that rollback of the local queue database alone cannot replay an effect while this ledger remains current. It does not prove exactly-once execution under ledger rollback, ledger compromise, a newly generated origin identity, or a provider that lacks authoritative idempotency/reconciliation.

## v3.28 Monotonic Execution Head and Provider Reconciliation

The v3.28 layer anchors the signed execution-ledger chain in a separately persisted monotonic head authority and adds a provider-side idempotency/reconciliation reference keyed by the same stable `effect_id` and exact provider payload digest. A fresh single-use challenge proves that the local ledger head matches the externally remembered sequence, head-event digest, and state root. `IN_FLIGHT`, `UNKNOWN`, and `COMPLETED` provider states block replay; only authoritative `NO_EFFECT` reconciliation supports another generation.

Run the exact closure:

```bash
PYTHONPATH=src:. python validation/execution_ledger_head/run_v328_execution_head_and_provider_closure.py
```

A v3.28 PASS does not grant action authority or establish production exactly-once execution. The included provider is a reference state machine, synchronization gaps fail closed, and coordinated rollback or compromise of the ledger, head authority, and provider store remains a post-product boundary.

## v3.30 Completion-Witness Quorum and Logical WORM Anchor

The v3.30 layer requires an operator-pinned threshold of distinct external completion witnesses and applies a blocking-minority veto when any valid configured witness reports `RESERVED`, `UNKNOWN` or `COMPLETED`. It also consumes signed provider outcomes into a separate signed logical append-only completion anchor with full-chain, head, state-root and fresh status verification.

Run the exact closure and real-process smoke:

```bash
PYTHONPATH=src:. python validation/completion_witness_quorum_worm_anchor/run_v330_completion_witness_quorum_and_worm_anchor_closure.py
PYTHONPATH=src:. python validation/completion_witness_quorum_worm_anchor/run_v330_service_process_smoke.py
```

The included SQLite anchor is not physical WORM storage. A v3.30 PASS does not establish physical independence or production exactly-once behavior under coordinated rollback of quorum thresholds and the anchor.
