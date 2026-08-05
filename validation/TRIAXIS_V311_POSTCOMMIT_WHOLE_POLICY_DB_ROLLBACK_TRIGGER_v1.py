#!/usr/bin/env python3
"""Post-v3.11 probe: whole quorum-policy database rollback.

This is outside v3.11's claimed local monotonic-store guarantee. It confirms the
need for an external minimum policy version/digest, transparency log, or other
monotonic anchor.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from tests.test_v3_11_authenticated_quorum_policy import ManagedPolicyFixture
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


def _clean(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def run_trigger() -> dict:
    fx = ManagedPolicyFixture()
    rows = []
    signers_ab = ["anchor-service:a", "anchor-service:b"]
    signers_abc = ["anchor-service:a", "anchor-service:b", "anchor-service:c"]
    p1 = fx.policy(1, None, signers_ab, 2)
    p2 = fx.policy(2, p1["policy_sha256"], signers_abc, 3)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        policy_db = root / "policy.db"
        old_db = root / "policy-v1.db"
        with fx.policy_store(policy_db) as policy_store:
            policy_store.install(fx.signed_policy(p1), 5)
        _clean(policy_db)
        shutil.copy2(policy_db, old_db)
        with fx.policy_store(policy_db) as policy_store:
            policy_store.install(fx.signed_policy(p2), 6)
            current = policy_store.load_current(9)
        rows.append({
            "case_id": "CURRENT_POLICY_HEAD_VERSION_2",
            "expected": 2,
            "observed": current["policy_version"],
            "status": "PASS" if current["policy_version"] == 2 else "FAIL",
            "positive_control": True,
        })

        _clean(policy_db)
        shutil.copy2(old_db, policy_db)
        with fx.policy_store(policy_db) as restored:
            rolled_back = restored.load_current(9)
        rows.append({
            "case_id": "RESTORED_WHOLE_POLICY_DATABASE",
            "claimed_v3_11_guarantee": False,
            "expected_boundary": "external minimum policy version or policy-head witness required",
            "observed_policy_version": rolled_back["policy_version"],
            "status": "OPEN_BOUNDARY_CONFIRMED" if rolled_back["policy_version"] == 1 else "UNEXPECTED",
        })

        # The restored policy can authorize two policy-v1 anchors against the
        # current registry head, proving that rollback has security effect.
        store, _, snap2, _, _ = fx.quorum.install_two(root / "registry.db")
        session = VerifierFreshnessSession.create("verifier:1", 8)
        with store, fx.policy_store(policy_db) as restored, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
            challenge = ledger.issue(8, 20)
            witnesses = [
                fx.signed_member(signer, p1, session, challenge, 2, snap2["snapshot_sha256"])
                for signer in signers_ab
            ]
            fx.load(store, restored, ledger, challenge, witnesses)
        rows.append({
            "case_id": "ROLLED_BACK_POLICY_REDUCES_THRESHOLD_3_TO_2",
            "claimed_v3_11_guarantee": False,
            "expected_boundary": "external policy anti-rollback required",
            "observed": "PASS_UNDER_RESTORED_POLICY_V1",
            "status": "OPEN_BOUNDARY_CONFIRMED",
        })

    open_count = sum(row["status"] == "OPEN_BOUNDARY_CONFIRMED" for row in rows)
    return {
        "contract_id": "TRIAXIS_V311_POSTCOMMIT_WHOLE_POLICY_DB_ROLLBACK_RESULT_v1",
        "target": "TRIAXIS-v3.11-RC1-AUTHENTICATED-QUORUM-POLICY",
        "status": "PASS_WITH_CONDITIONS" if open_count == 2 else "REVISE",
        "case_count": len(rows),
        "open_boundary_count": open_count,
        "logic_defect_within_claimed_scope": False,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
