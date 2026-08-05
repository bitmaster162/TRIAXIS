from __future__ import annotations

import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.test_v370_monotonic_trust_registry import RegistryFixture
from triaxis.crypto_trust import (
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_TRUST_REGISTRY_ANCHOR,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)
from triaxis.trust_registry_anchor import (
    SQLiteAnchorChallengeLedger,
    TrustRegistryAnchorError,
    load_registry_with_challenge_bound_anchor,
    make_challenge_bound_head_witness,
)


def challenge_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ChallengeAnchorFixture:
    def __init__(self) -> None:
        self.registry_fx = RegistryFixture()
        self.anchor_pair = generate_ed25519_keypair()
        self.anchor_record = make_trust_key_record(
            key_id="key:anchor:1",
            signer_id="anchor-service:1",
            trust_domain="domain:anchor",
            public_key_b64=self.anchor_pair["public_key_b64"],
            purposes=[PURPOSE_TRUST_REGISTRY_ANCHOR],
            valid_from=1,
            valid_until=1000,
        )
        self.anchor_registry = TrustKeyRegistry([self.anchor_record])

    def install_two(self, path: Path):
        rfx = self.registry_fx
        snap1, signed1 = rfx.snapshot(1, None, [rfx.operational_record()], 5)
        snap2, signed2 = rfx.snapshot(
            2,
            snap1["snapshot_sha256"],
            [rfx.operational_record(revoked_at=7)],
            7,
        )
        store = rfx.store(path)
        store.install(signed1, 5)
        store.install(signed2, 8)
        return store, snap1, snap2, signed1, signed2

    def signed_witness(
        self,
        challenge: str,
        sequence: int,
        digest: str,
        *,
        verifier_id: str = "verifier:1",
        requested_at: int = 8,
        issued_at: int = 9,
        valid_until: int = 20,
        registry_id: str = "registry:main",
        private_key_b64: str | None = None,
    ):
        witness = make_challenge_bound_head_witness(
            anchor_id="anchor:primary",
            registry_id=registry_id,
            sequence=sequence,
            snapshot_sha256=digest,
            verifier_id=verifier_id,
            challenge_sha256=challenge_sha256(challenge),
            requested_at=requested_at,
            issued_at=issued_at,
            valid_until=valid_until,
        )
        return sign_contract_envelope(
            witness,
            digest_field="witness_sha256",
            purpose=PURPOSE_TRUST_REGISTRY_ANCHOR,
            key_id="key:anchor:1",
            signer_id="anchor-service:1",
            trust_domain="domain:anchor",
            private_key_b64=private_key_b64 or self.anchor_pair["private_key_b64"],
            issued_at=issued_at,
            valid_until=valid_until,
        )

    def load(self, store, ledger, challenge, signed_witness, *, tick: int = 9, verifier_id: str = "verifier:1", max_anchor_age: int = 5):
        return load_registry_with_challenge_bound_anchor(
            store,
            signed_witness,
            anchor_registry=self.anchor_registry,
            challenge_ledger=ledger,
            expected_challenge=challenge,
            evaluation_tick=tick,
            expected_verifier_id=verifier_id,
            expected_anchor_signer_id="anchor-service:1",
            expected_anchor_trust_domain="domain:anchor",
            expected_anchor_id="anchor:primary",
            max_anchor_age=max_anchor_age,
        )


class ChallengeBoundAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = ChallengeAnchorFixture()

    def test_fresh_single_use_challenge_loads_exact_current_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                challenge = ledger.issue("verifier:1", 8, 20)
                registry = self.fx.load(store, ledger, challenge, self.fx.signed_witness(challenge, 2, snap2["snapshot_sha256"]))
        result = verify_contract_envelope(
            self.fx.registry_fx.signed_attestation(),
            registry=registry,
            evaluation_tick=9,
            expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
            expected_digest_field="attestation_sha256",
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("signing_key_revoked", {row["code"] for row in result["errors"]})

    def test_same_challenge_and_witness_cannot_be_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                challenge = ledger.issue("verifier:1", 8, 20)
                signed = self.fx.signed_witness(challenge, 2, snap2["snapshot_sha256"])
                self.fx.load(store, ledger, challenge, signed)
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, signed)
        self.assertEqual(cm.exception.code, "challenge_replay")

    def test_old_witness_cannot_answer_new_challenge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                old_challenge = ledger.issue("verifier:1", 8, 20)
                old_witness = self.fx.signed_witness(old_challenge, 2, snap2["snapshot_sha256"])
                new_challenge = ledger.issue("verifier:1", 8, 20)
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, new_challenge, old_witness)
        self.assertEqual(cm.exception.code, "anchor_challenge_mismatch")

    def test_rolled_back_database_and_old_witness_fail_against_fresh_challenge(self):
        rfx = self.fx.registry_fx
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "registry.db"
            old = root / "old.db"
            snap1, signed1 = rfx.snapshot(1, None, [rfx.operational_record()], 5)
            _, signed2 = rfx.snapshot(2, snap1["snapshot_sha256"], [rfx.operational_record(revoked_at=7)], 7)
            with rfx.store(db) as store:
                store.install(signed1, 5)
            shutil.copy2(db, old)
            old_challenge_db = root / "challenges.db"
            with SQLiteAnchorChallengeLedger(old_challenge_db) as ledger:
                old_challenge = ledger.issue("verifier:1", 8, 20)
                old_witness = self.fx.signed_witness(old_challenge, 1, snap1["snapshot_sha256"])
            with rfx.store(db) as store:
                store.install(signed2, 8)
            for suffix in ("-wal", "-shm"):
                Path(str(db) + suffix).unlink(missing_ok=True)
            shutil.copy2(old, db)
            with rfx.store(db) as restored, SQLiteAnchorChallengeLedger(old_challenge_db) as ledger:
                fresh_challenge = ledger.issue("verifier:1", 8, 20)
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(restored, ledger, fresh_challenge, old_witness)
        self.assertEqual(cm.exception.code, "anchor_challenge_mismatch")

    def test_unknown_challenge_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            unknown = "u" * 43
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                signed = self.fx.signed_witness(unknown, 2, snap2["snapshot_sha256"])
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, unknown, signed)
        self.assertEqual(cm.exception.code, "unknown_challenge")

    def test_expired_challenge_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                challenge = ledger.issue("verifier:1", 8, 9)
                signed = self.fx.signed_witness(challenge, 2, snap2["snapshot_sha256"], valid_until=20)
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, signed, tick=9)
        self.assertEqual(cm.exception.code, "challenge_expired")

    def test_wrong_verifier_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                challenge = ledger.issue("verifier:1", 8, 20)
                signed = self.fx.signed_witness(challenge, 2, snap2["snapshot_sha256"], verifier_id="verifier:other")
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, signed)
        self.assertEqual(cm.exception.code, "anchor_verifier_mismatch")

    def test_request_time_must_match_challenge_issuance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                challenge = ledger.issue("verifier:1", 8, 20)
                signed = self.fx.signed_witness(challenge, 2, snap2["snapshot_sha256"], requested_at=7)
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, signed)
        self.assertEqual(cm.exception.code, "anchor_request_time_mismatch")

    def test_response_age_is_bounded_even_when_signature_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                challenge = ledger.issue("verifier:1", 2, 20)
                signed = self.fx.signed_witness(
                    challenge,
                    2,
                    snap2["snapshot_sha256"],
                    requested_at=2,
                    issued_at=2,
                    valid_until=20,
                )
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, signed, tick=9, max_anchor_age=5)
        self.assertEqual(cm.exception.code, "anchor_response_too_old")

    def test_forged_anchor_signature_is_rejected_without_consuming_challenge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            attacker = generate_ed25519_keypair()
            with store, SQLiteAnchorChallengeLedger(root / "challenges.db") as ledger:
                challenge = ledger.issue("verifier:1", 8, 20)
                forged = self.fx.signed_witness(
                    challenge,
                    2,
                    snap2["snapshot_sha256"],
                    private_key_b64=attacker["private_key_b64"],
                )
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, forged)
                self.assertEqual(cm.exception.code, "invalid_external_anchor_signature")
                # A failed forgery must not burn the verifier's challenge.
                valid = self.fx.signed_witness(challenge, 2, snap2["snapshot_sha256"])
                registry = self.fx.load(store, ledger, challenge, valid)
                self.assertIsNotNone(registry.get("key:assurance:1"))


if __name__ == "__main__":
    unittest.main()
