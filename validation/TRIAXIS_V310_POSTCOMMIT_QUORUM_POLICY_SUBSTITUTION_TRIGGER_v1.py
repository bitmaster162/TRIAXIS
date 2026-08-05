#!/usr/bin/env python3
"""Post-v3.10 trigger: unsigned quorum-policy substitution."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from tests.test_v3_10_quorum_anchor import QuorumFixture
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


def run_trigger() -> dict:
    fx = QuorumFixture()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Intended policy: anchors A/B/C, threshold 3.
        store, _, snap2, _, _ = fx.install_two(root / "intended.db")
        session = VerifierFreshnessSession.create("verifier:1", 8)
        with store, SQLiteEpochChallengeLedger(root / "intended-challenges.db", session) as ledger:
            challenge = ledger.issue(8, 20)
            three = [
                fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"]),
                fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
                fx.signed_member("anchor-service:c", session, challenge, 2, snap2["snapshot_sha256"]),
            ]
            intended_map = {key: fx.authorities[key] for key in ("anchor-service:a", "anchor-service:b", "anchor-service:c")}
            fx.load(store, ledger, challenge, three, threshold=3)
        rows.append({
            "case_id": "INTENDED_THREE_OF_THREE_POLICY",
            "expected": "PASS",
            "observed": "PASS",
            "status": "PASS",
            "positive_control": True,
        })

        # The same product function accepts only A/B if the caller silently
        # lowers the threshold from 3 to 2.
        store, _, snap2, _, _ = fx.install_two(root / "downgrade.db")
        session = VerifierFreshnessSession.create("verifier:1", 8)
        with store, SQLiteEpochChallengeLedger(root / "downgrade-challenges.db", session) as ledger:
            challenge = ledger.issue(8, 20)
            two = [
                fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"]),
                fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
            ]
            fx.load(store, ledger, challenge, two, threshold=2)
        rows.append({
            "case_id": "CALLER_LOWERS_THRESHOLD_3_TO_2",
            "expected": "BLOCK_UNDER_AUTHENTICATED_POLICY",
            "observed": "PASS",
            "status": "FAIL",
        })

        # The caller can also replace the intended A/B/C authority set with C/D
        # and accept a matching old registry view.
        rfx = fx.rfx
        snap1, signed1 = rfx.snapshot(1, None, [rfx.operational_record()], 5)
        old_db = root / "substituted.db"
        with rfx.store(old_db) as old_store:
            old_store.install(signed1, 5)
        session = VerifierFreshnessSession.create("verifier:1", 8)
        substituted = {
            key: fx.authorities[key] for key in ("anchor-service:c", "anchor-service:d")
        }
        with rfx.store(old_db) as old_store, SQLiteEpochChallengeLedger(root / "substituted-challenges.db", session) as ledger:
            challenge = ledger.issue(8, 20)
            witnesses = [
                fx.signed_member("anchor-service:c", session, challenge, 1, snap1["snapshot_sha256"]),
                fx.signed_member("anchor-service:d", session, challenge, 1, snap1["snapshot_sha256"]),
            ]
            from triaxis.trust_registry_quorum import load_registry_with_quorum_anchors
            load_registry_with_quorum_anchors(
                old_store,
                witnesses,
                anchor_registry=fx.anchor_registry,
                challenge_ledger=ledger,
                expected_challenge=challenge,
                evaluation_tick=9,
                trusted_anchor_authorities=substituted,
                expected_anchor_set_id="anchor-set:primary",
                threshold=2,
            )
        rows.append({
            "case_id": "CALLER_SUBSTITUTES_AUTHORITY_SET",
            "expected": "BLOCK_UNDER_AUTHENTICATED_POLICY",
            "observed": "PASS",
            "status": "FAIL",
        })

    failures = sum(row["status"] == "FAIL" for row in rows)
    return {
        "contract_id": "TRIAXIS_V310_POSTCOMMIT_QUORUM_POLICY_SUBSTITUTION_RESULT_v1",
        "target": "TRIAXIS-v3.10-RC1-QUORUM-ANCHOR",
        "status": "FAIL" if failures else "PASS",
        "case_count": len(rows),
        "material_failure_count": failures,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
