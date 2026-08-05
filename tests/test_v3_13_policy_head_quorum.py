from __future__ import annotations

from contextlib import ExitStack
import hashlib
import tempfile
import unittest
from pathlib import Path

from tests.test_v3_12_policy_head_authority import PolicyHeadFixture
from triaxis.crypto_trust import (
    PURPOSE_POLICY_HEAD_AUTHORITY,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.policy_head_authority import PolicyHeadAuthorityError, SQLitePolicyHeadAuthorityService, make_policy_head_response
from triaxis.policy_head_quorum import (
    load_policy_with_external_head_quorum,
    make_policy_head_quorum_config,
    validate_policy_head_quorum_config,
)
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


class PolicyHeadQuorumFixture:
    def __init__(self) -> None:
        self.base = PolicyHeadFixture()
        self.authorities = []
        records = []
        for suffix in ("a", "b", "c"):
            pair = generate_ed25519_keypair()
            row = {
                "authority_id": f"policy-head:{suffix}",
                "signer_id": f"policy-head-service:{suffix}",
                "key_id": f"key:policy-head:{suffix}:1",
                "trust_domain": f"domain:policy-head:{suffix}",
                "pair": pair,
            }
            self.authorities.append(row)
            records.append(make_trust_key_record(
                key_id=row["key_id"],
                signer_id=row["signer_id"],
                trust_domain=row["trust_domain"],
                public_key_b64=pair["public_key_b64"],
                purposes=[PURPOSE_POLICY_HEAD_AUTHORITY],
                valid_from=1,
                valid_until=1000,
            ))
        self.registry = TrustKeyRegistry(records)
        self.config = make_policy_head_quorum_config(
            config_id="policy-head-quorum:main",
            authority_set_id="policy-head-set:primary",
            policy_id="quorum-policy:main",
            threshold=2,
            authorities=self.authorities,
            minimum_policy_version=2,
            minimum_policy_sha256=None,
            valid_from=1,
            valid_until=200,
        )

    def config_rows(self):
        return [
            {name: row[name] for name in ("authority_id", "signer_id", "key_id", "trust_domain")}
            for row in self.authorities
        ]

    def open_services(self, stack: ExitStack, root: Path, versions: tuple[int, int, int]):
        root.mkdir(parents=True, exist_ok=True)
        services = []
        for index, (authority, version) in enumerate(zip(self.authorities, versions)):
            store = stack.enter_context(self.base.store(root / f"policy-{index}.db"))
            self.base.install(store, self.base.policy1)
            if version >= 2:
                self.base.install(store, self.base.policy2)
            service = stack.enter_context(SQLitePolicyHeadAuthorityService(
                root / f"responses-{index}.db",
                policy_store=store,
                authority_id=authority["authority_id"],
                key_id=authority["key_id"],
                signer_id=authority["signer_id"],
                trust_domain=authority["trust_domain"],
                private_key_b64=authority["pair"]["private_key_b64"],
            ))
            services.append(service)
        return services

    def responses(self, services, session, challenge):
        return [service.issue_head_response(
            challenge=challenge,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            requested_at=8,
            issued_at=9,
            valid_until=20,
        ) for service in services]

    def load(self, local_store, responses, ledger, challenge, *, config=None, expected_digest=None):
        return load_policy_with_external_head_quorum(
            local_store,
            responses,
            authority_registry=self.registry,
            quorum_config=config or self.config,
            expected_config_sha256=expected_digest or self.config["config_sha256"],
            challenge_ledger=ledger,
            expected_challenge=challenge,
            evaluation_tick=9,
        )

    def signed_view(self, authority_index, policy, session, challenge):
        authority = self.authorities[authority_index]
        response = make_policy_head_response(
            authority_id=authority["authority_id"],
            policy_id=policy["policy_id"],
            policy_version=policy["policy_version"],
            policy_sha256=policy["policy_sha256"],
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            challenge_sha256=hashlib.sha256(challenge.encode()).hexdigest(),
            requested_at=8,
            issued_at=9,
            valid_until=20,
        )
        return sign_contract_envelope(
            response,
            digest_field="response_sha256",
            purpose=PURPOSE_POLICY_HEAD_AUTHORITY,
            key_id=authority["key_id"],
            signer_id=authority["signer_id"],
            trust_domain=authority["trust_domain"],
            private_key_b64=authority["pair"]["private_key_b64"],
            issued_at=9,
            valid_until=20,
        )


class PolicyHeadQuorumTests(unittest.TestCase):
    def setUp(self):
        self.fx = PolicyHeadQuorumFixture()

    def test_two_of_three_current_authorities_load_policy(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root, (2, 2, 2))
            local = stack.enter_context(self.fx.base.store(root / "local.db"))
            self.fx.base.install(local, self.fx.base.policy1, self.fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            result = self.fx.load(local, self.fx.responses(services[:2], session, challenge), ledger, challenge)
        self.assertEqual(result["policy"]["policy_version"], 2)
        self.assertEqual(len(result["quorum"]["members"]), 2)

    def test_one_rolled_back_authority_cannot_override_two_current(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root, (1, 2, 2))
            local = stack.enter_context(self.fx.base.store(root / "local.db"))
            self.fx.base.install(local, self.fx.base.policy1, self.fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            result = self.fx.load(local, self.fx.responses(services, session, challenge), ledger, challenge)
        self.assertEqual(result["policy"]["policy_sha256"], self.fx.base.policy2["policy_sha256"])

    def test_split_views_without_threshold_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root, (1, 2, 1))
            local = stack.enter_context(self.fx.base.store(root / "local.db"))
            self.fx.base.install(local, self.fx.base.policy1, self.fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            # Only one current and one old response; neither reaches 2.
            responses = self.fx.responses([services[0], services[1]], session, challenge)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, responses, ledger, challenge)
        self.assertEqual(cm.exception.code, "policy_head_quorum_not_met")

    def test_config_threshold_cannot_be_lowered_under_pinned_digest(self):
        lower = make_policy_head_quorum_config(
            config_id="policy-head-quorum:main",
            authority_set_id="policy-head-set:primary",
            policy_id="quorum-policy:main",
            threshold=2,
            authorities=self.fx.config_rows(),
            minimum_policy_version=1,
            minimum_policy_sha256=None,
            valid_from=1,
            valid_until=200,
        )
        strict = make_policy_head_quorum_config(
            config_id="policy-head-quorum:main",
            authority_set_id="policy-head-set:primary",
            policy_id="quorum-policy:main",
            threshold=3,
            authorities=self.fx.config_rows(),
            minimum_policy_version=2,
            minimum_policy_sha256=None,
            valid_from=1,
            valid_until=200,
        )
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root, (2, 2, 2))
            local = stack.enter_context(self.fx.base.store(root / "local.db"))
            self.fx.base.install(local, self.fx.base.policy1, self.fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, self.fx.responses(services[:2], session, challenge), ledger, challenge, config=lower, expected_digest=strict["config_sha256"])
        self.assertEqual(cm.exception.code, "policy_head_quorum_config_substitution")

    def test_same_signer_equivocation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            local = stack.enter_context(self.fx.base.store(root / "local.db"))
            self.fx.base.install(local, self.fx.base.policy1, self.fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            responses = [
                self.fx.signed_view(0, self.fx.base.policy1, session, challenge),
                self.fx.signed_view(0, self.fx.base.policy2, session, challenge),
                self.fx.signed_view(1, self.fx.base.policy2, session, challenge),
            ]
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, responses, ledger, challenge)
        self.assertEqual(cm.exception.code, "policy_head_signer_equivocation")

    def test_threshold_requires_distinct_trust_domains(self):
        rows = self.fx.config_rows()
        rows[1]["trust_domain"] = rows[0]["trust_domain"]
        config = make_policy_head_quorum_config(
            config_id="bad",
            authority_set_id="bad-set",
            policy_id="quorum-policy:main",
            threshold=3,
            authorities=rows,
            minimum_policy_version=1,
            minimum_policy_sha256=None,
            valid_from=1,
            valid_until=200,
        )
        result = validate_policy_head_quorum_config(config, 9)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("insufficient_domain_diversity", {row["code"] for row in result["errors"]})


if __name__ == "__main__":
    unittest.main()
