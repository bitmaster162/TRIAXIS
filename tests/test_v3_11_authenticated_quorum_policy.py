from __future__ import annotations

import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.test_v3_10_quorum_anchor import QuorumFixture
from triaxis.anchor_quorum_policy import (
    SQLiteAnchorQuorumPolicyStore,
    make_anchor_quorum_policy,
)
from triaxis.crypto_trust import (
    PURPOSE_ANCHOR_QUORUM_POLICY,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.trust_registry_anchor import TrustRegistryAnchorError
from triaxis.trust_registry_quorum import (
    SQLiteEpochChallengeLedger,
    VerifierFreshnessSession,
    load_registry_with_managed_quorum_policy,
    make_policy_bound_quorum_witness,
)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ManagedPolicyFixture:
    def __init__(self) -> None:
        self.quorum = QuorumFixture()
        self.policy_root_pair = generate_ed25519_keypair()
        self.policy_root_record = make_trust_key_record(
            key_id="key:quorum-policy-root:1",
            signer_id="quorum-policy-root:1",
            trust_domain="domain:quorum-policy-root",
            public_key_b64=self.policy_root_pair["public_key_b64"],
            purposes=[PURPOSE_ANCHOR_QUORUM_POLICY],
            valid_from=1,
            valid_until=1000,
        )
        self.policy_root_registry = TrustKeyRegistry([self.policy_root_record])

    def authorities(self, signers):
        rows = []
        for signer in signers:
            suffix = signer.rsplit(":", 1)[-1]
            authority = self.quorum.authorities[signer]
            rows.append({
                "anchor_id": authority["anchor_id"],
                "signer_id": signer,
                "key_id": f"key:anchor:{suffix}:1",
                "trust_domain": authority["trust_domain"],
            })
        return rows

    def policy(self, version, previous, signers, threshold, *, anchor_set_id="anchor-set:primary"):
        return make_anchor_quorum_policy(
            policy_id="quorum-policy:main",
            policy_version=version,
            previous_policy_sha256=previous,
            registry_id="registry:main",
            anchor_set_id=anchor_set_id,
            threshold=threshold,
            authorities=self.authorities(signers),
            valid_from=1,
            valid_until=200,
        )

    def signed_policy(self, policy, *, private_key_b64=None):
        return sign_contract_envelope(
            policy,
            digest_field="policy_sha256",
            purpose=PURPOSE_ANCHOR_QUORUM_POLICY,
            key_id="key:quorum-policy-root:1",
            signer_id="quorum-policy-root:1",
            trust_domain="domain:quorum-policy-root",
            private_key_b64=private_key_b64 or self.policy_root_pair["private_key_b64"],
            issued_at=5,
            valid_until=200,
        )

    def policy_store(self, path):
        return SQLiteAnchorQuorumPolicyStore(
            path,
            policy_root_registry=self.policy_root_registry,
            policy_id="quorum-policy:main",
            policy_root_signer_id="quorum-policy-root:1",
            policy_root_trust_domain="domain:quorum-policy-root",
        )

    def signed_member(self, signer, policy, session, challenge, sequence, snapshot_sha256, *, policy_digest=None):
        authority = self.quorum.authorities[signer]
        suffix = signer.rsplit(":", 1)[-1]
        witness = make_policy_bound_quorum_witness(
            quorum_policy_sha256=policy_digest or policy["policy_sha256"],
            anchor_set_id=policy["anchor_set_id"],
            anchor_id=authority["anchor_id"],
            registry_id="registry:main",
            sequence=sequence,
            snapshot_sha256=snapshot_sha256,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            challenge_sha256=sha(challenge),
            requested_at=8,
            issued_at=9,
            valid_until=20,
        )
        return sign_contract_envelope(
            witness,
            digest_field="witness_sha256",
            purpose="TRUST_REGISTRY_ANCHOR",
            key_id=f"key:anchor:{suffix}:1",
            signer_id=signer,
            trust_domain=authority["trust_domain"],
            private_key_b64=self.quorum.anchor_pairs[signer]["private_key_b64"],
            issued_at=9,
            valid_until=20,
        )

    def load(self, store, policy_store, ledger, challenge, witnesses):
        return load_registry_with_managed_quorum_policy(
            store,
            witnesses,
            anchor_registry=self.quorum.anchor_registry,
            policy_store=policy_store,
            challenge_ledger=ledger,
            expected_challenge=challenge,
            evaluation_tick=9,
        )


class AuthenticatedQuorumPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fx = ManagedPolicyFixture()
        self.signers_abc = ["anchor-service:a", "anchor-service:b", "anchor-service:c"]

    def test_current_signed_policy_drives_threshold_and_authorities(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.quorum.install_two(root / "registry.db")
            policy = self.fx.policy(1, None, self.signers_abc, 3)
            with self.fx.policy_store(root / "policy.db") as policy_store:
                policy_store.install(self.fx.signed_policy(policy), 5)
                session = VerifierFreshnessSession.create("verifier:1", 8)
                with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                    challenge = ledger.issue(8, 20)
                    witnesses = [
                        self.fx.signed_member(signer, policy, session, challenge, 2, snap2["snapshot_sha256"])
                        for signer in self.signers_abc
                    ]
                    registry = self.fx.load(store, policy_store, ledger, challenge, witnesses)
        self.assertIsNotNone(registry.get("key:assurance:1"))

    def test_caller_cannot_lower_signed_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.quorum.install_two(root / "registry.db")
            policy = self.fx.policy(1, None, self.signers_abc, 3)
            with self.fx.policy_store(root / "policy.db") as policy_store:
                policy_store.install(self.fx.signed_policy(policy), 5)
                session = VerifierFreshnessSession.create("verifier:1", 8)
                with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                    challenge = ledger.issue(8, 20)
                    only_two = [
                        self.fx.signed_member(signer, policy, session, challenge, 2, snap2["snapshot_sha256"])
                        for signer in self.signers_abc[:2]
                    ]
                    with self.assertRaises(TrustRegistryAnchorError) as cm:
                        self.fx.load(store, policy_store, ledger, challenge, only_two)
        self.assertEqual(cm.exception.code, "anchor_quorum_not_met")

    def test_signer_outside_current_policy_does_not_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.quorum.install_two(root / "registry.db")
            policy = self.fx.policy(1, None, self.signers_abc, 3)
            with self.fx.policy_store(root / "policy.db") as policy_store:
                policy_store.install(self.fx.signed_policy(policy), 5)
                session = VerifierFreshnessSession.create("verifier:1", 8)
                with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                    challenge = ledger.issue(8, 20)
                    substituted = [
                        self.fx.signed_member("anchor-service:c", policy, session, challenge, 2, snap2["snapshot_sha256"]),
                        self.fx.signed_member("anchor-service:d", policy, session, challenge, 2, snap2["snapshot_sha256"]),
                    ]
                    with self.assertRaises(TrustRegistryAnchorError) as cm:
                        self.fx.load(store, policy_store, ledger, challenge, substituted)
        self.assertEqual(cm.exception.code, "anchor_quorum_not_met")

    def test_witness_must_bind_exact_current_policy_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.quorum.install_two(root / "registry.db")
            policy = self.fx.policy(1, None, self.signers_abc, 3)
            with self.fx.policy_store(root / "policy.db") as policy_store:
                policy_store.install(self.fx.signed_policy(policy), 5)
                session = VerifierFreshnessSession.create("verifier:1", 8)
                with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                    challenge = ledger.issue(8, 20)
                    wrong = [
                        self.fx.signed_member(signer, policy, session, challenge, 2, snap2["snapshot_sha256"], policy_digest="f" * 64)
                        for signer in self.signers_abc
                    ]
                    with self.assertRaises(TrustRegistryAnchorError) as cm:
                        self.fx.load(store, policy_store, ledger, challenge, wrong)
        self.assertEqual(cm.exception.code, "anchor_quorum_not_met")

    def test_forged_policy_root_signature_is_rejected(self):
        policy = self.fx.policy(1, None, self.signers_abc, 3)
        attacker = generate_ed25519_keypair()
        forged = self.fx.signed_policy(policy, private_key_b64=attacker["private_key_b64"])
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.policy_store(Path(tmp) / "policy.db") as store:
                with self.assertRaises(TrustRegistryAnchorError) as cm:
                    store.install(forged, 5)
        self.assertEqual(cm.exception.code, "invalid_quorum_policy_signature")

    def test_policy_store_rejects_rollback_gap_and_parent_mismatch(self):
        p1 = self.fx.policy(1, None, self.signers_abc, 3)
        p2 = self.fx.policy(2, p1["policy_sha256"], self.signers_abc[1:], 2)
        gap = self.fx.policy(4, p2["policy_sha256"], self.signers_abc[1:], 2)
        wrong_parent = self.fx.policy(3, "f" * 64, self.signers_abc[1:], 2)
        with tempfile.TemporaryDirectory() as tmp:
            with self.fx.policy_store(Path(tmp) / "policy.db") as store:
                store.install(self.fx.signed_policy(p1), 5)
                store.install(self.fx.signed_policy(p2), 6)
                with self.assertRaises(TrustRegistryAnchorError) as rollback:
                    store.install(self.fx.signed_policy(p1), 7)
                with self.assertRaises(TrustRegistryAnchorError) as gap_error:
                    store.install(self.fx.signed_policy(gap), 7)
                with self.assertRaises(TrustRegistryAnchorError) as parent:
                    store.install(self.fx.signed_policy(wrong_parent), 7)
        self.assertEqual(rollback.exception.code, "quorum_policy_rollback")
        self.assertEqual(gap_error.exception.code, "quorum_policy_version_gap")
        self.assertEqual(parent.exception.code, "quorum_policy_parent_mismatch")

    def test_policy_update_changes_authority_set_and_threshold(self):
        p1 = self.fx.policy(1, None, self.signers_abc, 3)
        signers_bc = self.signers_abc[1:]
        p2 = self.fx.policy(2, p1["policy_sha256"], signers_bc, 2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, snap2, _, _ = self.fx.quorum.install_two(root / "registry.db")
            with self.fx.policy_store(root / "policy.db") as policy_store:
                policy_store.install(self.fx.signed_policy(p1), 5)
                policy_store.install(self.fx.signed_policy(p2), 6)
                session = VerifierFreshnessSession.create("verifier:1", 8)
                with store, SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                    challenge = ledger.issue(8, 20)
                    witnesses = [
                        self.fx.signed_member(signer, p2, session, challenge, 2, snap2["snapshot_sha256"])
                        for signer in signers_bc
                    ]
                    registry = self.fx.load(store, policy_store, ledger, challenge, witnesses)
        self.assertIsNotNone(registry.get("key:assurance:1"))


if __name__ == "__main__":
    unittest.main()
