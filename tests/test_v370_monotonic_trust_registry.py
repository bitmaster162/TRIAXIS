from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from triaxis.action_assurance import ASSURANCE_ATTESTATION_CONTRACT_ID, seal_contract
from triaxis.crypto_trust import (
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_TRUST_REGISTRY_SNAPSHOT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)
from triaxis.trust_registry_state import (
    SQLiteTrustRegistryStore,
    TrustRegistryStateError,
    make_trust_registry_snapshot,
)


class RegistryFixture:
    def __init__(self):
        self.root_pair = generate_ed25519_keypair()
        self.operational_pair = generate_ed25519_keypair()
        self.root_record = make_trust_key_record(
            key_id="key:root:1",
            signer_id="trust-root:1",
            trust_domain="domain:root",
            public_key_b64=self.root_pair["public_key_b64"],
            purposes=[PURPOSE_TRUST_REGISTRY_SNAPSHOT],
            valid_from=1,
            valid_until=1000,
        )
        self.root_registry = TrustKeyRegistry([self.root_record])

    def operational_record(self, revoked_at=None):
        return make_trust_key_record(
            key_id="key:assurance:1",
            signer_id="assurance:1",
            trust_domain="domain:assurance",
            public_key_b64=self.operational_pair["public_key_b64"],
            purposes=[PURPOSE_ASSURANCE_ATTESTATION],
            valid_from=1,
            valid_until=500,
            revoked_at=revoked_at,
        )

    def snapshot(self, sequence: int, parent: str | None, records, issued_at: int):
        snapshot = make_trust_registry_snapshot(
            registry_id="registry:main",
            sequence=sequence,
            parent_snapshot_sha256=parent,
            issued_at=issued_at,
            valid_until=200,
            key_records=records,
        )
        signed = sign_contract_envelope(
            snapshot,
            digest_field="snapshot_sha256",
            purpose=PURPOSE_TRUST_REGISTRY_SNAPSHOT,
            key_id="key:root:1",
            signer_id="trust-root:1",
            trust_domain="domain:root",
            private_key_b64=self.root_pair["private_key_b64"],
            issued_at=issued_at,
            valid_until=200,
        )
        return snapshot, signed

    def signed_attestation(self):
        attestation = seal_contract({
            "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
            "attestation_id": "attestation:1",
            "issuer_id": "assurance:1",
            "trust_domain": "domain:assurance",
            "subject_id": "subject:1",
            "decision_case_sha256": "a" * 64,
            "evidence_report_sha256": "b" * 64,
            "assured_action_request_sha256": "c" * 64,
            "assurance_status": "PASS",
            "synthesis_decision": "ACCEPT",
            "attestation_level": "AUTHENTICATED",
            "issued_at": 5,
            "valid_until": 50,
            "attestation_sha256": "",
        }, "attestation_sha256")
        return sign_contract_envelope(
            attestation,
            digest_field="attestation_sha256",
            purpose=PURPOSE_ASSURANCE_ATTESTATION,
            key_id="key:assurance:1",
            signer_id="assurance:1",
            trust_domain="domain:assurance",
            private_key_b64=self.operational_pair["private_key_b64"],
            issued_at=5,
            valid_until=50,
        )

    def store(self, path: Path):
        return SQLiteTrustRegistryStore(
            path,
            root_registry=self.root_registry,
            registry_id="registry:main",
            root_signer_id="trust-root:1",
            root_trust_domain="domain:root",
        )


class MonotonicTrustRegistryTests(unittest.TestCase):
    def setUp(self):
        self.fx = RegistryFixture()

    def test_genesis_install_and_load(self):
        snap1, signed1 = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.store(Path(tmp) / "registry.db") as store:
                head = store.install(signed1, 5)
                registry = store.load_registry(6)
        self.assertEqual(head["sequence"], 1)
        self.assertIsNotNone(registry.get("key:assurance:1"))
        self.assertEqual(head["snapshot_sha256"], snap1["snapshot_sha256"])

    def test_revocation_snapshot_blocks_old_signature(self):
        snap1, signed1 = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        _, signed2 = self.fx.snapshot(2, snap1["snapshot_sha256"], [self.fx.operational_record(revoked_at=7)], 7)
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.store(Path(tmp) / "registry.db") as store:
                store.install(signed1, 5)
                store.install(signed2, 8)
                registry = store.load_registry(8)
        result = verify_contract_envelope(
            self.fx.signed_attestation(),
            registry=registry,
            evaluation_tick=8,
            expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
            expected_digest_field="attestation_sha256",
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("signing_key_revoked", {e["code"] for e in result["errors"]})

    def test_reinstall_old_snapshot_is_rejected(self):
        snap1, signed1 = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        _, signed2 = self.fx.snapshot(2, snap1["snapshot_sha256"], [self.fx.operational_record(revoked_at=7)], 7)
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.store(Path(tmp) / "registry.db") as store:
                store.install(signed1, 5)
                store.install(signed2, 8)
                with self.assertRaises(TrustRegistryStateError) as cm:
                    store.install(signed1, 8)
        self.assertEqual(cm.exception.code, "registry_rollback")

    def test_same_sequence_fork_is_rejected(self):
        snap1, signed1 = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        _, signed2 = self.fx.snapshot(2, snap1["snapshot_sha256"], [self.fx.operational_record(revoked_at=7)], 7)
        other_pair = generate_ed25519_keypair()
        other_record = make_trust_key_record(
            key_id="key:other",
            signer_id="other",
            trust_domain="other-domain",
            public_key_b64=other_pair["public_key_b64"],
            purposes=[PURPOSE_ASSURANCE_ATTESTATION],
            valid_from=1,
            valid_until=100,
        )
        _, fork2 = self.fx.snapshot(2, snap1["snapshot_sha256"], [other_record], 7)
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.store(Path(tmp) / "registry.db") as store:
                store.install(signed1, 5)
                store.install(signed2, 8)
                with self.assertRaises(TrustRegistryStateError) as cm:
                    store.install(fork2, 8)
        self.assertEqual(cm.exception.code, "registry_rollback")

    def test_sequence_gap_is_rejected(self):
        snap1, signed1 = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        _, signed3 = self.fx.snapshot(3, snap1["snapshot_sha256"], [self.fx.operational_record()], 7)
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.store(Path(tmp) / "registry.db") as store:
                store.install(signed1, 5)
                with self.assertRaises(TrustRegistryStateError) as cm:
                    store.install(signed3, 8)
        self.assertEqual(cm.exception.code, "registry_sequence_gap")

    def test_parent_mismatch_is_rejected(self):
        _, signed1 = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        _, signed2 = self.fx.snapshot(2, "f" * 64, [self.fx.operational_record()], 7)
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.store(Path(tmp) / "registry.db") as store:
                store.install(signed1, 5)
                with self.assertRaises(TrustRegistryStateError) as cm:
                    store.install(signed2, 8)
        self.assertEqual(cm.exception.code, "registry_parent_mismatch")

    def test_forged_root_signature_is_rejected(self):
        snapshot, _ = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        attacker = generate_ed25519_keypair()
        forged = sign_contract_envelope(
            snapshot,
            digest_field="snapshot_sha256",
            purpose=PURPOSE_TRUST_REGISTRY_SNAPSHOT,
            key_id="key:root:1",
            signer_id="trust-root:1",
            trust_domain="domain:root",
            private_key_b64=attacker["private_key_b64"],
            issued_at=5,
            valid_until=200,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.store(Path(tmp) / "registry.db") as store:
                with self.assertRaises(TrustRegistryStateError) as cm:
                    store.install(forged, 5)
        self.assertEqual(cm.exception.code, "invalid_root_signature")

    def test_idempotent_exact_snapshot_is_allowed(self):
        _, signed1 = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.store(Path(tmp) / "registry.db") as store:
                first = store.install(signed1, 5)
                second = store.install(signed1, 6)
        self.assertEqual(first["snapshot_sha256"], second["snapshot_sha256"])

    def test_restart_preserves_monotonic_head(self):
        snap1, signed1 = self.fx.snapshot(1, None, [self.fx.operational_record()], 5)
        _, signed2 = self.fx.snapshot(2, snap1["snapshot_sha256"], [self.fx.operational_record(revoked_at=7)], 7)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.db"
            with self.fx.store(path) as store:
                store.install(signed1, 5)
                store.install(signed2, 8)
            with self.fx.store(path) as store:
                self.assertEqual(store.head()["sequence"], 2)
                with self.assertRaises(TrustRegistryStateError) as cm:
                    store.install(signed1, 8)
        self.assertEqual(cm.exception.code, "registry_rollback")


if __name__ == "__main__":
    unittest.main()
