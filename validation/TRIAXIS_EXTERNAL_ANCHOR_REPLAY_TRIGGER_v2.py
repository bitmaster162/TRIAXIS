#!/usr/bin/env python3
"""Closure trigger for v3.9 challenge-bound external anchor freshness."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from tests.test_v390_challenge_bound_anchor import ChallengeAnchorFixture
from triaxis.trust_registry_anchor import SQLiteAnchorChallengeLedger, TrustRegistryAnchorError


def _observe(callable_):
    try:
        callable_()
        return "PASS"
    except TrustRegistryAnchorError as exc:
        return exc.code


def run_trigger() -> dict:
    fx = ChallengeAnchorFixture()
    rfx = fx.registry_fx
    rows: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        db = root / "registry.db"
        challenge_db = root / "challenges.db"
        store, snap1, snap2, signed1, signed2 = fx.install_two(db)
        with store, SQLiteAnchorChallengeLedger(challenge_db) as ledger:
            challenge = ledger.issue("verifier:1", 8, 20)
            current = fx.signed_witness(challenge, 2, snap2["snapshot_sha256"])
            observed = _observe(lambda: fx.load(store, ledger, challenge, current))
            rows.append({
                "case_id": "FRESH_CHALLENGE_CURRENT_HEAD",
                "expected": "PASS",
                "observed": observed,
                "status": "PASS" if observed == "PASS" else "FAIL",
                "positive_control": True,
            })
            replay = _observe(lambda: fx.load(store, ledger, challenge, current))
            rows.append({
                "case_id": "SAME_WITNESS_AND_CHALLENGE_REPLAY",
                "expected": "challenge_replay",
                "observed": replay,
                "status": "PASS" if replay == "challenge_replay" else "FAIL",
            })

        # A valid old witness cannot answer a newly issued challenge.
        with rfx.store(db) as store, SQLiteAnchorChallengeLedger(challenge_db) as ledger:
            old_challenge = ledger.issue("verifier:1", 10, 30)
            old_witness = fx.signed_witness(
                old_challenge, 2, snap2["snapshot_sha256"], requested_at=10, issued_at=10, valid_until=30
            )
            fresh_challenge = ledger.issue("verifier:1", 10, 30)
            observed = _observe(lambda: fx.load(store, ledger, fresh_challenge, old_witness, tick=10))
            rows.append({
                "case_id": "OLD_WITNESS_VS_NEW_CHALLENGE",
                "expected": "anchor_challenge_mismatch",
                "observed": observed,
                "status": "PASS" if observed == "anchor_challenge_mismatch" else "FAIL",
            })

        # Restore sequence-1 database, but require a fresh challenge. The old
        # witness cannot be replayed even though its signature is still valid.
        old_db = root / "seq1.db"
        db2 = root / "rollback.db"
        with rfx.store(db2) as seq1_store:
            seq1_store.install(signed1, 5)
        shutil.copy2(db2, old_db)
        with rfx.store(db2) as seq2_store:
            seq2_store.install(signed2, 8)
        for suffix in ("-wal", "-shm"):
            Path(str(db2) + suffix).unlink(missing_ok=True)
        shutil.copy2(old_db, db2)
        challenge_db2 = root / "rollback-challenges.db"
        with SQLiteAnchorChallengeLedger(challenge_db2) as ledger:
            prior_challenge = ledger.issue("verifier:1", 8, 20)
            prior_witness = fx.signed_witness(prior_challenge, 1, snap1["snapshot_sha256"])
            fresh_challenge = ledger.issue("verifier:1", 8, 20)
            with rfx.store(db2) as restored:
                observed = _observe(lambda: fx.load(restored, ledger, fresh_challenge, prior_witness))
        rows.append({
            "case_id": "ROLLED_BACK_DB_PLUS_OLD_WITNESS_VS_FRESH_CHALLENGE",
            "expected": "anchor_challenge_mismatch",
            "observed": observed,
            "status": "PASS" if observed == "anchor_challenge_mismatch" else "FAIL",
        })

        # A forged answer must not consume the challenge; a valid answer may
        # still use it afterward.
        with rfx.store(db) as store, SQLiteAnchorChallengeLedger(challenge_db) as ledger:
            challenge = ledger.issue("verifier:1", 12, 30)
            attacker = __import__("triaxis.crypto_trust", fromlist=["generate_ed25519_keypair"]).generate_ed25519_keypair()
            forged = fx.signed_witness(
                challenge,
                2,
                snap2["snapshot_sha256"],
                requested_at=12,
                issued_at=12,
                valid_until=30,
                private_key_b64=attacker["private_key_b64"],
            )
            forged_observed = _observe(lambda: fx.load(store, ledger, challenge, forged, tick=12))
            valid = fx.signed_witness(
                challenge, 2, snap2["snapshot_sha256"], requested_at=12, issued_at=12, valid_until=30
            )
            valid_observed = _observe(lambda: fx.load(store, ledger, challenge, valid, tick=12))
        rows.append({
            "case_id": "FORGED_RESPONSE_DOES_NOT_BURN_CHALLENGE",
            "expected": "invalid_external_anchor_signature_then_PASS",
            "observed": f"{forged_observed}_then_{valid_observed}",
            "status": "PASS" if forged_observed == "invalid_external_anchor_signature" and valid_observed == "PASS" else "FAIL",
            "positive_control": True,
        })

    passed = sum(row["status"] == "PASS" for row in rows)
    return {
        "contract_id": "TRIAXIS_EXTERNAL_ANCHOR_REPLAY_TRIGGER_RESULT_v2",
        "target": "TRIAXIS-v3.9-RC1-CHALLENGE-BOUND-ANCHOR",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
