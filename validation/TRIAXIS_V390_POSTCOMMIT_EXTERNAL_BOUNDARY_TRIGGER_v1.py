#!/usr/bin/env python3
"""Post-v3.9 boundary probe: local challenge rollback and anchor equivocation.

These cases are intentionally outside the guarantees claimed by v3.9-RC1.
The trigger confirms that the documented external-infrastructure requirements are
real rather than rhetorical.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from tests.test_v390_challenge_bound_anchor import ChallengeAnchorFixture
from triaxis.trust_registry_anchor import SQLiteAnchorChallengeLedger, TrustRegistryAnchorError


def _clean_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def run_trigger() -> dict:
    fx = ChallengeAnchorFixture()
    rfx = fx.registry_fx
    rows: list[dict] = []

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Boundary 1: rolling the challenge ledger back to its pre-consumption
        # bytes restores ISSUED state and permits the exact response again.
        registry_db = root / "registry.db"
        challenge_db = root / "challenges.db"
        preconsume = root / "challenges-preconsume.db"
        store, _, snap2, _, _ = fx.install_two(registry_db)
        with SQLiteAnchorChallengeLedger(challenge_db) as ledger:
            challenge = ledger.issue("verifier:1", 8, 20)
        _clean_sidecars(challenge_db)
        shutil.copy2(challenge_db, preconsume)
        signed = fx.signed_witness(challenge, 2, snap2["snapshot_sha256"])
        with store, SQLiteAnchorChallengeLedger(challenge_db) as ledger:
            fx.load(store, ledger, challenge, signed)
        _clean_sidecars(challenge_db)
        shutil.copy2(preconsume, challenge_db)
        with rfx.store(registry_db) as restored_store, SQLiteAnchorChallengeLedger(challenge_db) as restored_ledger:
            try:
                fx.load(restored_store, restored_ledger, challenge, signed)
                observed = "REPLAY_ACCEPTED_AFTER_LEDGER_ROLLBACK"
            except TrustRegistryAnchorError as exc:
                observed = exc.code
        rows.append({
            "case_id": "WHOLE_CHALLENGE_LEDGER_ROLLBACK",
            "claimed_v3_9_guarantee": False,
            "expected_boundary": "external monotonic verifier state required",
            "observed": observed,
            "status": "OPEN_BOUNDARY_CONFIRMED" if observed == "REPLAY_ACCEPTED_AFTER_LEDGER_ROLLBACK" else "UNEXPECTED",
        })

        # Boundary 2: one valid anchor key can sign two internally valid heads
        # for two verifiers. Challenge binding proves freshness, not consistency
        # across observers.
        snap1, signed1 = rfx.snapshot(1, None, [rfx.operational_record()], 5)
        snap2b, signed2 = rfx.snapshot(2, snap1["snapshot_sha256"], [rfx.operational_record(revoked_at=7)], 7)
        db_a = root / "view-a.db"
        db_b = root / "view-b.db"
        with rfx.store(db_a) as view_a:
            view_a.install(signed1, 5)
        with rfx.store(db_b) as view_b:
            view_b.install(signed1, 5)
            view_b.install(signed2, 8)
        ledger_a_path = root / "challenge-a.db"
        ledger_b_path = root / "challenge-b.db"
        with SQLiteAnchorChallengeLedger(ledger_a_path) as ledger_a:
            challenge_a = ledger_a.issue("verifier:a", 8, 20)
            witness_a = fx.signed_witness(
                challenge_a, 1, snap1["snapshot_sha256"], verifier_id="verifier:a"
            )
        with SQLiteAnchorChallengeLedger(ledger_b_path) as ledger_b:
            challenge_b = ledger_b.issue("verifier:b", 8, 20)
            witness_b = fx.signed_witness(
                challenge_b, 2, snap2b["snapshot_sha256"], verifier_id="verifier:b"
            )
        accepted = []
        with rfx.store(db_a) as view_a, SQLiteAnchorChallengeLedger(ledger_a_path) as ledger_a:
            fx.load(view_a, ledger_a, challenge_a, witness_a, verifier_id="verifier:a")
            accepted.append("view_a_sequence_1")
        with rfx.store(db_b) as view_b, SQLiteAnchorChallengeLedger(ledger_b_path) as ledger_b:
            fx.load(view_b, ledger_b, challenge_b, witness_b, verifier_id="verifier:b")
            accepted.append("view_b_sequence_2")
        observed = "+".join(accepted)
        rows.append({
            "case_id": "SINGLE_ANCHOR_SPLIT_VIEW_EQUIVOCATION",
            "claimed_v3_9_guarantee": False,
            "expected_boundary": "threshold witnesses or transparency/gossip required",
            "observed": observed,
            "status": "OPEN_BOUNDARY_CONFIRMED" if len(accepted) == 2 else "UNEXPECTED",
        })

    confirmed = sum(row["status"] == "OPEN_BOUNDARY_CONFIRMED" for row in rows)
    return {
        "contract_id": "TRIAXIS_V390_POSTCOMMIT_EXTERNAL_BOUNDARY_RESULT_v1",
        "target": "TRIAXIS-v3.9-RC1-CHALLENGE-BOUND-ANCHOR",
        "status": "PASS_WITH_CONDITIONS" if confirmed == len(rows) else "REVISE",
        "case_count": len(rows),
        "open_boundary_count": confirmed,
        "logic_defect_within_claimed_scope": False,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
