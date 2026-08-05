from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.test_v3_11_authenticated_quorum_policy import ManagedPolicyFixture
from triaxis.crypto_trust import (
    PURPOSE_POLICY_HEAD_AUTHORITY,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.policy_head_authority import (
    PolicyHeadAuthorityError,
    SQLitePolicyHeadAuthorityService,
    load_policy_with_external_head,
)
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


class PolicyHeadFixture:
    def __init__(self) -> None:
        self.managed = ManagedPolicyFixture()
        self.authority_pair = generate_ed25519_keypair()
        self.authority_record = make_trust_key_record(
            key_id="key:policy-head:1",
            signer_id="policy-head-service:1",
            trust_domain="domain:policy-head",
            public_key_b64=self.authority_pair["public_key_b64"],
            purposes=[PURPOSE_POLICY_HEAD_AUTHORITY],
            valid_from=1,
            valid_until=1000,
        )
        self.authority_registry = TrustKeyRegistry([self.authority_record])
        self.signers = ["anchor-service:a", "anchor-service:b", "anchor-service:c"]
        self.policy1 = self.managed.policy(1, None, self.signers, 2)
        self.policy2 = self.managed.policy(2, self.policy1["policy_sha256"], self.signers, 3)

    def store(self, path: Path):
        return self.managed.policy_store(path)

    def install(self, store, *policies):
        for policy in policies:
            store.install(self.managed.signed_policy(policy), 5)

    def service(self, path: Path, policy_store, *, private_key_b64=None):
        return SQLitePolicyHeadAuthorityService(
            path,
            policy_store=policy_store,
            authority_id="policy-head:primary",
            key_id="key:policy-head:1",
            signer_id="policy-head-service:1",
            trust_domain="domain:policy-head",
            private_key_b64=private_key_b64 or self.authority_pair["private_key_b64"],
        )

    def challenge(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        session = VerifierFreshnessSession.create("verifier:policy-client", 8)
        ledger = SQLiteEpochChallengeLedger(root / "client-challenges.db", session)
        challenge = ledger.issue(8, 20)
        return session, ledger, challenge

    def response(self, service, session, challenge, *, issued_at=9, valid_until=20):
        return service.issue_head_response(
            challenge=challenge,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            requested_at=8,
            issued_at=issued_at,
            valid_until=valid_until,
        )

    def load(self, local_store, signed_response, ledger, challenge, **kwargs):
        return load_policy_with_external_head(
            local_store,
            signed_response,
            authority_registry=self.authority_registry,
            challenge_ledger=ledger,
            expected_challenge=challenge,
            evaluation_tick=9,
            expected_authority_id="policy-head:primary",
            expected_policy_id="quorum-policy:main",
            expected_authority_signer_id="policy-head-service:1",
            expected_authority_trust_domain="domain:policy-head",
            **kwargs,
        )


class PolicyHeadAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = PolicyHeadFixture()

    def test_exact_current_local_policy_matches_external_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "authority-policy.db") as authority_store, self.fx.store(root / "local-policy.db") as local_store:
                self.fx.install(authority_store, self.fx.policy1, self.fx.policy2)
                self.fx.install(local_store, self.fx.policy1, self.fx.policy2)
                with self.fx.service(root / "authority-responses.db", authority_store) as service:
                    session, ledger, challenge = self.fx.challenge(root)
                    with ledger:
                        signed = self.fx.response(service, session, challenge)
                        policy = self.fx.load(local_store, signed, ledger, challenge)
        self.assertEqual(policy["policy_version"], 2)
        self.assertEqual(policy["policy_sha256"], self.fx.policy2["policy_sha256"])

    def test_local_whole_database_rollback_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "authority-policy.db") as authority_store, self.fx.store(root / "rolled-back-local.db") as local_store:
                self.fx.install(authority_store, self.fx.policy1, self.fx.policy2)
                self.fx.install(local_store, self.fx.policy1)
                with self.fx.service(root / "authority-responses.db", authority_store) as service:
                    session, ledger, challenge = self.fx.challenge(root)
                    with ledger:
                        signed = self.fx.response(service, session, challenge)
                        with self.assertRaises(PolicyHeadAuthorityError) as cm:
                            self.fx.load(local_store, signed, ledger, challenge)
                        ledger.inspect_issued(challenge, 9)
        self.assertEqual(cm.exception.code, "local_policy_rollback")

    def test_same_version_policy_fork_is_rejected(self):
        fork = self.fx.managed.policy(
            2,
            self.fx.policy1["policy_sha256"],
            self.fx.signers,
            2,
            anchor_set_id="anchor-set:fork",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "authority-policy.db") as authority_store, self.fx.store(root / "forked-local.db") as local_store:
                self.fx.install(authority_store, self.fx.policy1, self.fx.policy2)
                self.fx.install(local_store, self.fx.policy1, fork)
                with self.fx.service(root / "authority-responses.db", authority_store) as service:
                    session, ledger, challenge = self.fx.challenge(root)
                    with ledger:
                        signed = self.fx.response(service, session, challenge)
                        with self.assertRaises(PolicyHeadAuthorityError) as cm:
                            self.fx.load(local_store, signed, ledger, challenge)
        self.assertEqual(cm.exception.code, "local_policy_fork")

    def test_old_response_cannot_answer_new_challenge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "policy.db") as store:
                self.fx.install(store, self.fx.policy1, self.fx.policy2)
                with self.fx.service(root / "responses.db", store) as service:
                    session = VerifierFreshnessSession.create("verifier:policy-client", 8)
                    with SQLiteEpochChallengeLedger(root / "challenges.db", session) as ledger:
                        old_challenge = ledger.issue(8, 20)
                        old = self.fx.response(service, session, old_challenge)
                        new_challenge = ledger.issue(8, 20)
                        with self.assertRaises(PolicyHeadAuthorityError) as cm:
                            self.fx.load(store, old, ledger, new_challenge)
        self.assertEqual(cm.exception.code, "policy_head_challenge_mismatch")

    def test_forged_authority_signature_is_rejected_without_consuming_challenge(self):
        attacker = generate_ed25519_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "policy.db") as store:
                self.fx.install(store, self.fx.policy1, self.fx.policy2)
                with self.fx.service(root / "responses.db", store, private_key_b64=attacker["private_key_b64"]) as service:
                    session, ledger, challenge = self.fx.challenge(root)
                    with ledger:
                        forged = self.fx.response(service, session, challenge)
                        with self.assertRaises(PolicyHeadAuthorityError) as cm:
                            self.fx.load(store, forged, ledger, challenge)
                        ledger.inspect_issued(challenge, 9)
        self.assertEqual(cm.exception.code, "invalid_policy_head_signature")

    def test_minimum_operator_floor_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "policy.db") as store:
                self.fx.install(store, self.fx.policy1, self.fx.policy2)
                with self.fx.service(root / "responses.db", store) as service:
                    session, ledger, challenge = self.fx.challenge(root)
                    with ledger:
                        signed = self.fx.response(service, session, challenge)
                        with self.assertRaises(PolicyHeadAuthorityError) as cm:
                            self.fx.load(store, signed, ledger, challenge, minimum_policy_version=3)
        self.assertEqual(cm.exception.code, "minimum_policy_version_not_met")

    def test_minimum_digest_pin_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "policy.db") as store:
                self.fx.install(store, self.fx.policy1, self.fx.policy2)
                with self.fx.service(root / "responses.db", store) as service:
                    session, ledger, challenge = self.fx.challenge(root)
                    with ledger:
                        signed = self.fx.response(service, session, challenge)
                        with self.assertRaises(PolicyHeadAuthorityError) as cm:
                            self.fx.load(store, signed, ledger, challenge, minimum_policy_sha256="f" * 64)
        self.assertEqual(cm.exception.code, "minimum_policy_digest_not_met")

    def test_same_challenge_is_idempotent_for_same_head_and_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "policy.db") as store:
                self.fx.install(store, self.fx.policy1, self.fx.policy2)
                with self.fx.service(root / "responses.db", store) as service:
                    session, ledger, challenge = self.fx.challenge(root)
                    with ledger:
                        first = self.fx.response(service, session, challenge)
                        second = self.fx.response(service, session, challenge)
        self.assertEqual(first, second)

    def test_challenge_reuse_after_policy_change_is_rejected(self):
        policy3 = self.fx.managed.policy(3, self.fx.policy2["policy_sha256"], self.fx.signers, 2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.fx.store(root / "policy.db") as store:
                self.fx.install(store, self.fx.policy1, self.fx.policy2)
                with self.fx.service(root / "responses.db", store) as service:
                    session, ledger, challenge = self.fx.challenge(root)
                    with ledger:
                        self.fx.response(service, session, challenge)
                        store.install(self.fx.managed.signed_policy(policy3), 9)
                        with self.assertRaises(PolicyHeadAuthorityError) as cm:
                            self.fx.response(service, session, challenge)
        self.assertEqual(cm.exception.code, "challenge_reuse_conflict")


if __name__ == "__main__":
    unittest.main()
