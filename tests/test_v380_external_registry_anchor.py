from __future__ import annotations

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
    TrustRegistryAnchorError,
    load_registry_with_external_anchor,
    make_trust_registry_head_witness,
)


class AnchorFixture:
    def __init__(self):
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

    def signed_anchor(self, sequence: int, digest: str, *, registry_id: str = "registry:main", issued_at: int = 8, valid_until: int = 20, private_key_b64: str | None = None):
        witness = make_trust_registry_head_witness(
            anchor_id="anchor:primary",
            registry_id=registry_id,
            sequence=sequence,
            snapshot_sha256=digest,
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

    def load(self, store, signed_anchor, tick=8):
        return load_registry_with_external_anchor(
            store,
            signed_anchor,
            anchor_registry=self.anchor_registry,
            evaluation_tick=tick,
            expected_anchor_signer_id="anchor-service:1",
            expected_anchor_trust_domain="domain:anchor",
            expected_anchor_id="anchor:primary",
        )


class ExternalRegistryAnchorTests(unittest.TestCase):
    def setUp(self):
        self.fx = AnchorFixture()

    def _install_two(self, path: Path):
        rfx = self.fx.registry_fx
        snap1, signed1 = rfx.snapshot(1, None, [rfx.operational_record()], 5)
        snap2, signed2 = rfx.snapshot(2, snap1["snapshot_sha256"], [rfx.operational_record(revoked_at=7)], 7)
        store = rfx.store(path)
        store.install(signed1, 5)
        store.install(signed2, 8)
        return store, snap1, snap2, signed1, signed2

    def test_exact_external_anchor_loads_current_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _, snap2, _, _ = self._install_two(Path(tmp) / "registry.db")
            with store:
                registry = self.fx.load(store, self.fx.signed_anchor(2, snap2["snapshot_sha256"]))
        result = verify_contract_envelope(
            self.fx.registry_fx.signed_attestation(),
            registry=registry,
            evaluation_tick=8,
            expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
            expected_digest_field="attestation_sha256",
        )
        self.assertEqual(result["status"], "BLOCK")

    def test_whole_database_rollback_is_detected(self):
        rfx = self.fx.registry_fx
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "registry.db"
            old = root / "old.db"
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
            with rfx.store(db) as restored:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(restored, self.fx.signed_anchor(2, snap2["snapshot_sha256"]))
        self.assertEqual(cm.exception.code, "local_registry_rollback")

    def test_forged_anchor_signature_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _, snap2, _, _ = self._install_two(Path(tmp) / "registry.db")
            attacker = generate_ed25519_keypair()
            forged = self.fx.signed_anchor(2, snap2["snapshot_sha256"], private_key_b64=attacker["private_key_b64"])
            with store:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, forged)
        self.assertEqual(cm.exception.code, "invalid_external_anchor_signature")

    def test_stale_anchor_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, snap1, _, _, _ = self._install_two(Path(tmp) / "registry.db")
            with store:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, self.fx.signed_anchor(1, snap1["snapshot_sha256"]))
        self.assertEqual(cm.exception.code, "stale_external_anchor")

    def test_same_sequence_wrong_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _, _, _, _ = self._install_two(Path(tmp) / "registry.db")
            with store:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, self.fx.signed_anchor(2, "f" * 64))
        self.assertEqual(cm.exception.code, "local_registry_fork")

    def test_wrong_registry_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _, snap2, _, _ = self._install_two(Path(tmp) / "registry.db")
            with store:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, self.fx.signed_anchor(2, snap2["snapshot_sha256"], registry_id="registry:other"))
        self.assertEqual(cm.exception.code, "anchor_registry_id_mismatch")

    def test_expired_anchor_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _, snap2, _, _ = self._install_two(Path(tmp) / "registry.db")
            expired = self.fx.signed_anchor(2, snap2["snapshot_sha256"], issued_at=5, valid_until=8)
            with store:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, expired, tick=8)
        self.assertEqual(cm.exception.code, "invalid_external_anchor_signature")

    def test_missing_local_registry_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            rfx = self.fx.registry_fx
            with rfx.store(Path(tmp) / "registry.db") as store:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    self.fx.load(store, self.fx.signed_anchor(1, "a" * 64))
        self.assertEqual(cm.exception.code, "local_registry_missing")


if __name__ == "__main__":
    unittest.main()
