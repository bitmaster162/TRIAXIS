#!/usr/bin/env python3
"""Closure trigger for TRIAXIS v3.10 quorum and verifier-epoch controls."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from tests.test_v3_10_quorum_anchor import QuorumFixture
from triaxis.trust_registry_anchor import TrustRegistryAnchorError
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


def _observe(call):
    try:
        call()
        return "PASS"
    except TrustRegistryAnchorError as exc:
        return exc.code


def run_trigger() -> dict:
    fx = QuorumFixture()
    rows: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Positive quorum.
        store, snap1, snap2, _, _ = fx.install_two(root / "current.db")
        session = VerifierFreshnessSession.create("verifier:1", 8)
        with store, SQLiteEpochChallengeLedger(root / "current-challenges.db", session) as ledger:
            challenge = ledger.issue(8, 20)
            current = [
                fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"]),
                fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
            ]
            observed = _observe(lambda: fx.load(store, ledger, challenge, current))
        rows.append({
            "case_id": "TWO_DISTINCT_ANCHORS_CURRENT_HEAD",
            "expected": "PASS",
            "observed": observed,
            "status": "PASS" if observed == "PASS" else "FAIL",
            "positive_control": True,
        })

        # One signer cannot self-authorize a quorum.
        store, _, snap2, _, _ = fx.install_two(root / "single.db")
        session = VerifierFreshnessSession.create("verifier:1", 8)
        with store, SQLiteEpochChallengeLedger(root / "single-challenges.db", session) as ledger:
            challenge = ledger.issue(8, 20)
            one = [fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"])]
            observed = _observe(lambda: fx.load(store, ledger, challenge, one))
        rows.append({
            "case_id": "SINGLE_ANCHOR_BELOW_THRESHOLD",
            "expected": "anchor_quorum_not_met",
            "observed": observed,
            "status": "PASS" if observed == "anchor_quorum_not_met" else "FAIL",
        })

        # One stale view cannot override two agreeing current anchors.
        store, snap1, snap2, _, _ = fx.install_two(root / "majority.db")
        session = VerifierFreshnessSession.create("verifier:1", 8)
        with store, SQLiteEpochChallengeLedger(root / "majority-challenges.db", session) as ledger:
            challenge = ledger.issue(8, 20)
            mixed = [
                fx.signed_member("anchor-service:a", session, challenge, 1, snap1["snapshot_sha256"]),
                fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
                fx.signed_member("anchor-service:c", session, challenge, 2, snap2["snapshot_sha256"]),
            ]
            observed = _observe(lambda: fx.load(store, ledger, challenge, mixed))
        rows.append({
            "case_id": "ONE_STALE_TWO_CURRENT",
            "expected": "PASS",
            "observed": observed,
            "status": "PASS" if observed == "PASS" else "FAIL",
            "positive_control": True,
        })

        # Conflicting threshold groups are fail-closed.
        store, snap1, snap2, _, _ = fx.install_two(root / "split.db")
        session = VerifierFreshnessSession.create("verifier:1", 8)
        with store, SQLiteEpochChallengeLedger(root / "split-challenges.db", session) as ledger:
            challenge = ledger.issue(8, 20)
            split = [
                fx.signed_member("anchor-service:a", session, challenge, 1, snap1["snapshot_sha256"]),
                fx.signed_member("anchor-service:b", session, challenge, 1, snap1["snapshot_sha256"]),
                fx.signed_member("anchor-service:c", session, challenge, 2, snap2["snapshot_sha256"]),
                fx.signed_member("anchor-service:d", session, challenge, 2, snap2["snapshot_sha256"]),
            ]
            observed = _observe(lambda: fx.load(store, ledger, challenge, split))
        rows.append({
            "case_id": "TWO_CONFLICTING_QUORUMS",
            "expected": "multiple_anchor_quorums",
            "observed": observed,
            "status": "PASS" if observed == "multiple_anchor_quorums" else "FAIL",
        })

        # Restored challenge state belongs to the old non-persistent epoch.
        store, _, snap2, _, _ = fx.install_two(root / "epoch.db")
        challenge_db = root / "epoch-challenges.db"
        backup = root / "epoch-challenges-old.db"
        old_session = VerifierFreshnessSession.create("verifier:1", 8)
        with SQLiteEpochChallengeLedger(challenge_db, old_session) as ledger:
            challenge = ledger.issue(8, 20)
        for suffix in ("-wal", "-shm"):
            Path(str(challenge_db) + suffix).unlink(missing_ok=True)
        shutil.copy2(challenge_db, backup)
        new_session = VerifierFreshnessSession.create("verifier:1", 9)
        shutil.copy2(backup, challenge_db)
        old_witnesses = [
            fx.signed_member("anchor-service:a", old_session, challenge, 2, snap2["snapshot_sha256"]),
            fx.signed_member("anchor-service:b", old_session, challenge, 2, snap2["snapshot_sha256"]),
        ]
        with store, SQLiteEpochChallengeLedger(challenge_db, new_session) as ledger:
            observed = _observe(lambda: fx.load(store, ledger, challenge, old_witnesses))
        rows.append({
            "case_id": "RESTORED_LEDGER_OLD_VERIFIER_EPOCH",
            "expected": "challenge_epoch_mismatch",
            "observed": observed,
            "status": "PASS" if observed == "challenge_epoch_mismatch" else "FAIL",
        })

    passed = sum(row["status"] == "PASS" for row in rows)
    return {
        "contract_id": "TRIAXIS_QUORUM_AND_VERIFIER_EPOCH_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.10-RC1-QUORUM-ANCHOR",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
