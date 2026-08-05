#!/usr/bin/env python3
"""Closure trigger for v3.11 authenticated quorum policy."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from tests.test_v3_11_authenticated_quorum_policy import ManagedPolicyFixture
from triaxis.trust_registry_anchor import TrustRegistryAnchorError
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


def _observe(call):
    try:
        call()
        return "PASS"
    except TrustRegistryAnchorError as exc:
        return exc.code


def run_trigger() -> dict:
    fx = ManagedPolicyFixture()
    abc = ["anchor-service:a", "anchor-service:b", "anchor-service:c"]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        policy = fx.policy(1, None, abc, 3)

        # Positive exact policy.
        store, _, snap2, _, _ = fx.quorum.install_two(root / "positive-registry.db")
        with fx.policy_store(root / "positive-policy.db") as policy_store:
            policy_store.install(fx.signed_policy(policy), 5)
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "positive-challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                witnesses = [fx.signed_member(s, policy, session, challenge, 2, snap2["snapshot_sha256"]) for s in abc]
                observed = _observe(lambda: fx.load(store, policy_store, ledger, challenge, witnesses))
        rows.append({"case_id":"SIGNED_POLICY_EXACT_QUORUM","expected":"PASS","observed":observed,"status":"PASS" if observed=="PASS" else "FAIL","positive_control":True})

        # Caller cannot lower threshold because threshold is no longer an input.
        store, _, snap2, _, _ = fx.quorum.install_two(root / "threshold-registry.db")
        with fx.policy_store(root / "threshold-policy.db") as policy_store:
            policy_store.install(fx.signed_policy(policy), 5)
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "threshold-challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                two = [fx.signed_member(s, policy, session, challenge, 2, snap2["snapshot_sha256"]) for s in abc[:2]]
                observed = _observe(lambda: fx.load(store, policy_store, ledger, challenge, two))
        rows.append({"case_id":"THRESHOLD_DOWNGRADE_ATTEMPT","expected":"anchor_quorum_not_met","observed":observed,"status":"PASS" if observed=="anchor_quorum_not_met" else "FAIL"})

        # Anchor outside current policy cannot substitute into quorum.
        store, _, snap2, _, _ = fx.quorum.install_two(root / "authority-registry.db")
        with fx.policy_store(root / "authority-policy.db") as policy_store:
            policy_store.install(fx.signed_policy(policy), 5)
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "authority-challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                substituted = [
                    fx.signed_member("anchor-service:c", policy, session, challenge, 2, snap2["snapshot_sha256"]),
                    fx.signed_member("anchor-service:d", policy, session, challenge, 2, snap2["snapshot_sha256"]),
                ]
                observed = _observe(lambda: fx.load(store, policy_store, ledger, challenge, substituted))
        rows.append({"case_id":"AUTHORITY_SET_SUBSTITUTION","expected":"anchor_quorum_not_met","observed":observed,"status":"PASS" if observed=="anchor_quorum_not_met" else "FAIL"})

        # Witnesses for a different policy digest do not count.
        store, _, snap2, _, _ = fx.quorum.install_two(root / "digest-registry.db")
        with fx.policy_store(root / "digest-policy.db") as policy_store:
            policy_store.install(fx.signed_policy(policy), 5)
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "digest-challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                wrong = [
                    fx.signed_member(s, policy, session, challenge, 2, snap2["snapshot_sha256"], policy_digest="f"*64)
                    for s in abc
                ]
                observed = _observe(lambda: fx.load(store, policy_store, ledger, challenge, wrong))
        rows.append({"case_id":"POLICY_DIGEST_SUBSTITUTION","expected":"anchor_quorum_not_met","observed":observed,"status":"PASS" if observed=="anchor_quorum_not_met" else "FAIL"})

        # Local monotonic policy rollback is rejected.
        p2 = fx.policy(2, policy["policy_sha256"], abc[1:], 2)
        with fx.policy_store(root / "rollback-policy.db") as policy_store:
            policy_store.install(fx.signed_policy(policy), 5)
            policy_store.install(fx.signed_policy(p2), 6)
            observed = _observe(lambda: policy_store.install(fx.signed_policy(policy), 7))
        rows.append({"case_id":"LOCAL_POLICY_ROLLBACK","expected":"quorum_policy_rollback","observed":observed,"status":"PASS" if observed=="quorum_policy_rollback" else "FAIL"})

    passed=sum(row["status"]=="PASS" for row in rows)
    return {"contract_id":"TRIAXIS_AUTHENTICATED_QUORUM_POLICY_TRIGGER_RESULT_v1","target":"TRIAXIS-v3.11-RC1-AUTHENTICATED-QUORUM-POLICY","status":"PASS" if passed==len(rows) else "FAIL","case_count":len(rows),"pass_count":passed,"rows":rows}


if __name__ == "__main__":
    print(json.dumps(run_trigger(),sort_keys=True,indent=2))
