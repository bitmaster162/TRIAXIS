from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import tempfile
import unittest
from pathlib import Path

from tests.test_v3_14_policy_transparency_floor import HEAD_CONFIG_SHA256, PolicyTransparencyFloorFixture
from triaxis.crypto_trust import (
    PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT,
    PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY,
    TrustKeyRegistry, generate_ed25519_keypair, make_trust_key_record,
)
from triaxis.policy_head_authority import PolicyHeadAuthorityError
from triaxis.policy_transparency_floor import SQLitePolicyTransparencyGossipStore, enforce_policy_transparency_floor_quorum_with_gossip
from triaxis.policy_transparency_gossip_head import SQLiteGossipCheckpointIssuer, SQLiteGossipHeadAuthority, enforce_external_gossip_head
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


class ExternalGossipHeadFixture:
    def __init__(self):
        self.floor = PolicyTransparencyFloorFixture()
        self.checkpoint_pair = generate_ed25519_keypair()
        self.authority_pair = generate_ed25519_keypair()
        self.checkpoint_identity = dict(key_id="key:gossip-checkpoint:1", signer_id="verifier:gossip-checkpoint", trust_domain="domain:verifier")
        self.authority_identity = dict(key_id="key:gossip-head:1", signer_id="authority:gossip-head", trust_domain="domain:gossip-head")
        self.checkpoint_registry = TrustKeyRegistry([make_trust_key_record(
            **self.checkpoint_identity, public_key_b64=self.checkpoint_pair["public_key_b64"],
            purposes=[PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT], valid_from=1, valid_until=1000)])
        self.authority_registry = TrustKeyRegistry([make_trust_key_record(
            **self.authority_identity, public_key_b64=self.authority_pair["public_key_b64"],
            purposes=[PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY], valid_from=1, valid_until=1000)])
        self.store_id="gossip-store:main"; self.authority_id="gossip-head-authority:main"; self.counter=0

    def populate(self, stack, root: Path, version: int):
        root.mkdir(parents=True, exist_ok=True)
        gossip=stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))
        local=stack.enter_context(self.floor.store(root / "local-policy.db")); self.floor.install(local, version)
        session=VerifierFreshnessSession.create(f"verifier:populate:{version}", 8)
        ledger=stack.enter_context(SQLiteEpochChallengeLedger(root / "populate-challenges.db", session)); challenge=ledger.issue(8,20)
        responses=[self.floor.signed_view(0, self.floor.policy2 if version==2 else self.floor.policy3, session, challenge), self.floor.signed_view(1, self.floor.policy2 if version==2 else self.floor.policy3, session, challenge)]
        enforce_policy_transparency_floor_quorum_with_gossip(local, responses, gossip_store=gossip,
            witness_registry=self.floor.registry, floor_quorum_config=self.floor.config,
            expected_floor_config_sha256=self.floor.config["config_sha256"],
            expected_policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
            challenge_ledger=ledger, expected_challenge=challenge, evaluation_tick=9)
        return gossip

    def issuer(self, stack, root, gossip):
        root.mkdir(parents=True, exist_ok=True)
        return stack.enter_context(SQLiteGossipCheckpointIssuer(root / "issuer.db", gossip_store=gossip,
            store_id=self.store_id, verifier_id="verifier:main", private_key_b64=self.checkpoint_pair["private_key_b64"], **self.checkpoint_identity))

    def authority(self, stack, root):
        root.mkdir(parents=True, exist_ok=True)
        return stack.enter_context(SQLiteGossipHeadAuthority(root / "authority.db", authority_id=self.authority_id,
            service_id="service:gossip-head", checkpoint_registry=self.checkpoint_registry,
            expected_checkpoint_signer_id=self.checkpoint_identity["signer_id"],
            expected_checkpoint_trust_domain=self.checkpoint_identity["trust_domain"],
            private_key_b64=self.authority_pair["private_key_b64"], **self.authority_identity))

    def verify(self, stack, root, gossip, checkpoint, authority, *, challenge=None, head=None):
        self.counter += 1
        session=VerifierFreshnessSession.create(f"verifier:consumer:{self.counter}", 11)
        ledger=stack.enter_context(SQLiteEpochChallengeLedger(root / f"consumer-challenges-{self.counter}.db", session))
        challenge=challenge or ledger.issue(11,30)
        head=head or authority.issue_head(store_id=self.store_id, challenge=challenge, verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256, requested_at=11, issued_at=12, valid_until=30)
        return enforce_external_gossip_head(gossip_store=gossip, store_id=self.store_id,
            signed_checkpoint=checkpoint, signed_head_response=head, checkpoint_registry=self.checkpoint_registry,
            authority_registry=self.authority_registry, expected_checkpoint_signer_id=self.checkpoint_identity["signer_id"],
            expected_checkpoint_trust_domain=self.checkpoint_identity["trust_domain"], expected_authority_id=self.authority_id,
            expected_authority_signer_id=self.authority_identity["signer_id"],
            expected_authority_trust_domain=self.authority_identity["trust_domain"], challenge_ledger=ledger,
            expected_challenge=challenge, evaluation_tick=12)


class ExternalGossipHeadTests(unittest.TestCase):
    def setUp(self): self.fx=ExternalGossipHeadFixture()

    def test_current_external_head_accepts_exact_local_gossip(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); gossip=self.fx.populate(stack, root/"current", 2)
            issuer=self.fx.issuer(stack, root/"current", gossip); cp=issuer.issue(issued_at=10, valid_until=100)
            authority=self.fx.authority(stack, root); authority.install(cp, 10)
            result=self.fx.verify(stack, root, gossip, cp, authority)
        self.assertEqual(result["status"], "PASS")

    def test_whole_local_gossip_rollback_is_blocked_by_external_head(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp)
            low=self.fx.populate(stack, root/"low", 2)
            high=self.fx.populate(stack, root/"high", 3)
            issuer=self.fx.issuer(stack, root/"high", high); cp=issuer.issue(issued_at=10, valid_until=100)
            authority=self.fx.authority(stack, root); authority.install(cp,10)
            with self.assertRaises(PolicyHeadAuthorityError) as cm: self.fx.verify(stack, root, low, cp, authority)
        self.assertEqual(cm.exception.code, "local_gossip_state_rollback_detected")

    def test_old_head_cannot_answer_new_challenge(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); gossip=self.fx.populate(stack, root/"current", 2)
            issuer=self.fx.issuer(stack, root/"current", gossip); cp=issuer.issue(issued_at=10, valid_until=100)
            authority=self.fx.authority(stack, root); authority.install(cp,10)
            old_session=VerifierFreshnessSession.create("verifier:old",11)
            old_ledger=stack.enter_context(SQLiteEpochChallengeLedger(root/"old.db", old_session)); old_challenge=old_ledger.issue(11,30)
            old_head=authority.issue_head(store_id=self.fx.store_id, challenge=old_challenge, verifier_id=old_session.verifier_id,
                verifier_epoch_sha256=old_session.epoch_sha256, requested_at=11, issued_at=12, valid_until=30)
            new_session=VerifierFreshnessSession.create("verifier:new",11)
            new_ledger=stack.enter_context(SQLiteEpochChallengeLedger(root/"new.db", new_session)); new_challenge=new_ledger.issue(11,30)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                enforce_external_gossip_head(gossip_store=gossip, store_id=self.fx.store_id, signed_checkpoint=cp,
                    signed_head_response=old_head, checkpoint_registry=self.fx.checkpoint_registry,
                    authority_registry=self.fx.authority_registry, expected_checkpoint_signer_id=self.fx.checkpoint_identity["signer_id"],
                    expected_checkpoint_trust_domain=self.fx.checkpoint_identity["trust_domain"], expected_authority_id=self.fx.authority_id,
                    expected_authority_signer_id=self.fx.authority_identity["signer_id"], expected_authority_trust_domain=self.fx.authority_identity["trust_domain"],
                    challenge_ledger=new_ledger, expected_challenge=new_challenge, evaluation_tick=12)
        self.assertEqual(cm.exception.code, "gossip_head_verifier_binding_mismatch")

    def test_forged_authority_signature_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); gossip=self.fx.populate(stack, root/"current", 2)
            issuer=self.fx.issuer(stack, root/"current", gossip); cp=issuer.issue(issued_at=10, valid_until=100)
            authority=self.fx.authority(stack, root); authority.install(cp,10)
            session=VerifierFreshnessSession.create("verifier:consumer",11)
            ledger=stack.enter_context(SQLiteEpochChallengeLedger(root/"consumer-challenges.db",session)); challenge=ledger.issue(11,30)
            head=authority.issue_head(store_id=self.fx.store_id, challenge=challenge, verifier_id=session.verifier_id,
                verifier_epoch_sha256=session.epoch_sha256, requested_at=11, issued_at=12, valid_until=30)
            forged=deepcopy(head); forged["signature_b64"]="A"*88
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                enforce_external_gossip_head(gossip_store=gossip, store_id=self.fx.store_id, signed_checkpoint=cp,
                    signed_head_response=forged, checkpoint_registry=self.fx.checkpoint_registry, authority_registry=self.fx.authority_registry,
                    expected_checkpoint_signer_id=self.fx.checkpoint_identity["signer_id"], expected_checkpoint_trust_domain=self.fx.checkpoint_identity["trust_domain"],
                    expected_authority_id=self.fx.authority_id, expected_authority_signer_id=self.fx.authority_identity["signer_id"],
                    expected_authority_trust_domain=self.fx.authority_identity["trust_domain"], challenge_ledger=ledger,
                    expected_challenge=challenge, evaluation_tick=12)
        self.assertEqual(cm.exception.code, "invalid_gossip_head_signature")

    def test_authority_rejects_checkpoint_rollback(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); low=self.fx.populate(stack, root/"low",2); high=self.fx.populate(stack, root/"high",3)
            issuer1=self.fx.issuer(stack, root/"issuer",low); cp1=issuer1.issue(issued_at=10,valid_until=100); issuer1.close()
            authority=self.fx.authority(stack,root); authority.install(cp1,10)
            issuer2=stack.enter_context(SQLiteGossipCheckpointIssuer(root/"issuer"/"issuer.db", gossip_store=high,
                store_id=self.fx.store_id, verifier_id="verifier:main", private_key_b64=self.fx.checkpoint_pair["private_key_b64"], **self.fx.checkpoint_identity))
            cp2=issuer2.issue(issued_at=22,valid_until=100); authority.install(cp2,22)
            with self.assertRaises(PolicyHeadAuthorityError) as cm: authority.install(cp1,23)
        self.assertEqual(cm.exception.code,"gossip_checkpoint_sequence_gap")

    def test_exact_checkpoint_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); gossip=self.fx.populate(stack, root/"current",2)
            issuer=self.fx.issuer(stack,root/"current",gossip); cp=issuer.issue(issued_at=10,valid_until=100)
            authority=self.fx.authority(stack,root); first=authority.install(cp,10); second=authority.install(cp,11)
        self.assertEqual(first["inner_contract"]["checkpoint_sha256"], second["inner_contract"]["checkpoint_sha256"])

if __name__ == "__main__": unittest.main()
