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
from triaxis.trust_registry_anchor import TrustRegistryAnchorError
from triaxis.trust_registry_quorum import (
    SQLiteEpochChallengeLedger,
    VerifierFreshnessSession,
    load_registry_with_quorum_anchors,
    make_quorum_member_witness,
)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class QuorumFixture:
    def __init__(self, count: int = 4, shared_domain: bool = False) -> None:
        self.rfx = RegistryFixture()
        self.anchor_pairs: dict[str, dict[str, str]] = {}
        self.authorities: dict[str, dict[str, str]] = {}
        records = []
        for index in range(count):
            name = chr(ord("a") + index)
            signer = f"anchor-service:{name}"
            anchor_id = f"anchor:{name}"
            domain = "domain:shared" if shared_domain else f"domain:anchor:{name}"
            pair = generate_ed25519_keypair()
            self.anchor_pairs[signer] = pair
            self.authorities[signer] = {"anchor_id": anchor_id, "trust_domain": domain}
            records.append(
                make_trust_key_record(
                    key_id=f"key:anchor:{name}:1",
                    signer_id=signer,
                    trust_domain=domain,
                    public_key_b64=pair["public_key_b64"],
                    purposes=[PURPOSE_TRUST_REGISTRY_ANCHOR],
                    valid_from=1,
                    valid_until=1000,
                )
            )
        self.anchor_registry = TrustKeyRegistry(records)

    def install_two(self, path: Path):
        snap1, signed1 = self.rfx.snapshot(1, None, [self.rfx.operational_record()], 5)
        snap2, signed2 = self.rfx.snapshot(
            2,
            snap1["snapshot_sha256"],
            [self.rfx.operational_record(revoked_at=7)],
            7,
        )
        store = self.rfx.store(path)
        store.install(signed1, 5)
        store.install(signed2, 8)
        return store, snap1, snap2, signed1, signed2

    def signed_member(
        self,
        signer: str,
        session: VerifierFreshnessSession,
        challenge: str,
        sequence: int,
        snapshot_sha256: str,
        *,
        requested_at: int = 8,
        issued_at: int = 9,
        valid_until: int = 20,
        anchor_id: str | None = None,
    ):
        authority = self.authorities[signer]
        witness = make_quorum_member_witness(
            anchor_set_id="anchor-set:primary",
            anchor_id=anchor_id or authority["anchor_id"],
            registry_id="registry:main",
            sequence=sequence,
            snapshot_sha256=snapshot_sha256,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            challenge_sha256=sha(challenge),
            requested_at=requested_at,
            issued_at=issued_at,
            valid_until=valid_until,
        )
        suffix = signer.rsplit(":", 1)[-1]
        return sign_contract_envelope(
            witness,
            digest_field="witness_sha256",
            purpose=PURPOSE_TRUST_REGISTRY_ANCHOR,
            key_id=f"key:anchor:{suffix}:1",
            signer_id=signer,
            trust_domain=authority["trust_domain"],
            private_key_b64=self.anchor_pairs[signer]["private_key_b64"],
            issued_at=issued_at,
            valid_until=valid_until,
        )

    def load(self, store, ledger, challenge, witnesses, *, tick=9, threshold=2):
        return load_registry_with_quorum_anchors(
            store,
            witnesses,
            anchor_registry=self.anchor_registry,
            challenge_ledger=ledger,
            expected_challenge=challenge,
            evaluation_tick=tick,
            trusted_anchor_authorities=self.authorities,
            expected_anchor_set_id="anchor-set:primary",
            threshold=threshold,
            max_anchor_age=5,
        )


class QuorumAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = QuorumFixture()

    def test_two_distinct_anchors_and_domains_load_current_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                witnesses = [
                    self.fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
                ]
                registry = self.fx.load(store, ledger, challenge, witnesses)
        result = verify_contract_envelope(
            self.fx.rfx.signed_attestation(),
            registry=registry,
            evaluation_tick=9,
            expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
            expected_digest_field="attestation_sha256",
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("signing_key_revoked", {row["code"] for row in result["errors"]})

    def test_single_anchor_cannot_satisfy_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                one = [self.fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"])]
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, one)
        self.assertEqual(cm.exception.code, "anchor_quorum_not_met")

    def test_one_equivocating_or_stale_anchor_cannot_override_two_agreeing_anchors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, snap1, snap2, _, _ = self.fx.install_two(root / "registry.db")
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                witnesses = [
                    self.fx.signed_member("anchor-service:a", session, challenge, 1, snap1["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:c", session, challenge, 2, snap2["snapshot_sha256"]),
                ]
                registry = self.fx.load(store, ledger, challenge, witnesses)
        self.assertIsNotNone(registry.get("key:assurance:1"))

    def test_two_conflicting_quorums_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, snap1, snap2, _, _ = self.fx.install_two(root / "registry.db")
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                witnesses = [
                    self.fx.signed_member("anchor-service:a", session, challenge, 1, snap1["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:b", session, challenge, 1, snap1["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:c", session, challenge, 2, snap2["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:d", session, challenge, 2, snap2["snapshot_sha256"]),
                ]
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, witnesses)
        self.assertEqual(cm.exception.code, "multiple_anchor_quorums")

    def test_same_signer_conflicting_statements_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, snap1, snap2, _, _ = self.fx.install_two(root / "registry.db")
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                witnesses = [
                    self.fx.signed_member("anchor-service:a", session, challenge, 1, snap1["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
                ]
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, witnesses)
        self.assertEqual(cm.exception.code, "anchor_signer_equivocation")

    def test_duplicate_signature_does_not_count_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                signed = self.fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"])
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, [signed, signed])
        self.assertEqual(cm.exception.code, "anchor_quorum_not_met")

    def test_shared_trust_domain_does_not_count_as_independent_quorum(self):
        fx = QuorumFixture(count=2, shared_domain=True)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = fx.install_two(root / "registry.db")
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                witnesses = [
                    fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"]),
                    fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
                ]
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    fx.load(store, ledger, challenge, witnesses)
        self.assertEqual(cm.exception.code, "anchor_quorum_not_met")

    def test_restored_old_challenge_ledger_is_invalid_under_new_session_epoch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            challenge_db = root / "challenges.db"
            old = root / "old-challenges.db"
            session1 = VerifierFreshnessSession.create("verifier:1", 8)
            with SQLiteEpochChallengeLedger(challenge_db, session1) as ledger:
                challenge = ledger.issue(8, 20)
            for suffix in ("-wal", "-shm"):
                Path(str(challenge_db) + suffix).unlink(missing_ok=True)
            shutil.copy2(challenge_db, old)
            session2 = VerifierFreshnessSession.create("verifier:1", 9)
            for suffix in ("-wal", "-shm"):
                Path(str(challenge_db) + suffix).unlink(missing_ok=True)
            shutil.copy2(old, challenge_db)
            witnesses = [
                self.fx.signed_member("anchor-service:a", session1, challenge, 2, snap2["snapshot_sha256"]),
                self.fx.signed_member("anchor-service:b", session1, challenge, 2, snap2["snapshot_sha256"]),
            ]
            with store, SQLiteEpochChallengeLedger(challenge_db, session2) as ledger:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, witnesses)
        self.assertEqual(cm.exception.code, "challenge_epoch_mismatch")

    def test_current_quorum_detects_local_registry_rollback(self):
        rfx = self.fx.rfx
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "registry.db"
            old = root / "seq1.db"
            snap1, signed1 = rfx.snapshot(1, None, [rfx.operational_record()], 5)
            snap2, signed2 = rfx.snapshot(2, snap1["snapshot_sha256"], [rfx.operational_record(revoked_at=7)], 7)
            with rfx.store(db) as store:
                store.install(signed1, 5)
            shutil.copy2(db, old)
            with rfx.store(db) as store:
                store.install(signed2, 8)
            for suffix in ("-wal", "-shm"):
                Path(str(db) + suffix).unlink(missing_ok=True)
            shutil.copy2(old, db)
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                witnesses = [
                    self.fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
                ]
                with rfx.store(db) as restored:
                    with self.assertRaises(TrustRegistryAnchorError) as cm:
                        self.fx.load(restored, ledger, challenge, witnesses)
        self.assertEqual(cm.exception.code, "local_registry_rollback")

    def test_quorum_challenge_is_single_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.install_two(root / "registry.db")
            session = VerifierFreshnessSession.create("verifier:1", 8)
            with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                challenge = ledger.issue(8, 20)
                witnesses = [
                    self.fx.signed_member("anchor-service:a", session, challenge, 2, snap2["snapshot_sha256"]),
                    self.fx.signed_member("anchor-service:b", session, challenge, 2, snap2["snapshot_sha256"]),
                ]
                self.fx.load(store, ledger, challenge, witnesses)
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, ledger, challenge, witnesses)
        self.assertEqual(cm.exception.code, "challenge_replay")


if __name__ == "__main__":
    unittest.main()
