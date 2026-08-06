from __future__ import annotations

from contextlib import ExitStack
import hashlib
import tempfile
import unittest
from pathlib import Path

from tests.test_v3_11_authenticated_quorum_policy import ManagedPolicyFixture
from triaxis.crypto_trust import (
    PURPOSE_POLICY_TRANSPARENCY_WITNESS,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.policy_head_authority import PolicyHeadAuthorityError
from triaxis.policy_transparency_floor import (
    SQLitePolicyTransparencyWitnessService,
    enforce_policy_transparency_floor_quorum,
    make_policy_transparency_floor_quorum_config,
    make_policy_transparency_floor_response,
    validate_policy_transparency_floor_quorum_config,
)
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


HEAD_CONFIG_SHA256 = "a" * 64


class PolicyTransparencyFloorFixture:
    def __init__(self) -> None:
        self.managed = ManagedPolicyFixture()
        self.signers = ["anchor-service:a", "anchor-service:b", "anchor-service:c"]
        self.policy1 = self.managed.policy(1, None, self.signers, 2)
        self.policy2 = self.managed.policy(2, self.policy1["policy_sha256"], self.signers, 3)
        self.policy3 = self.managed.policy(3, self.policy2["policy_sha256"], self.signers, 2)
        self.witnesses = []
        records = []
        for suffix in ("a", "b", "c"):
            pair = generate_ed25519_keypair()
            row = {
                "witness_id": f"policy-transparency-witness:{suffix}",
                "log_id": f"policy-transparency-log:{suffix}",
                "key_id": f"key:policy-transparency:{suffix}:1",
                "signer_id": f"policy-transparency-signer:{suffix}",
                "trust_domain": f"domain:policy-transparency:{suffix}",
                "pair": pair,
            }
            self.witnesses.append(row)
            records.append(make_trust_key_record(
                key_id=row["key_id"],
                signer_id=row["signer_id"],
                trust_domain=row["trust_domain"],
                public_key_b64=pair["public_key_b64"],
                purposes=[PURPOSE_POLICY_TRANSPARENCY_WITNESS],
                valid_from=1,
                valid_until=1000,
            ))
        self.registry = TrustKeyRegistry(records)
        self.config = make_policy_transparency_floor_quorum_config(
            config_id="policy-transparency-floor:main",
            witness_set_id="policy-transparency-set:primary",
            policy_id="quorum-policy:main",
            policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
            threshold=2,
            witnesses=self.config_rows(),
            valid_from=1,
            valid_until=200,
        )

    def config_rows(self):
        return [
            {name: row[name] for name in ("witness_id", "log_id", "signer_id", "key_id", "trust_domain")}
            for row in self.witnesses
        ]

    def store(self, path: Path):
        return self.managed.policy_store(path)

    def install(self, store, version: int):
        policies = [self.policy1, self.policy2, self.policy3]
        for policy in policies[:version]:
            store.install(self.managed.signed_policy(policy), 5)

    def open_services(self, stack: ExitStack, root: Path, versions: tuple[int, int, int]):
        root.mkdir(parents=True, exist_ok=True)
        services = []
        for index, (row, version) in enumerate(zip(self.witnesses, versions)):
            policy_store = stack.enter_context(self.store(root / f"policy-{index}.db"))
            self.install(policy_store, version)
            service = stack.enter_context(SQLitePolicyTransparencyWitnessService(
                root / f"responses-{index}.db",
                policy_store=policy_store,
                witness_id=row["witness_id"],
                log_id=row["log_id"],
                policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
                key_id=row["key_id"],
                signer_id=row["signer_id"],
                trust_domain=row["trust_domain"],
                private_key_b64=row["pair"]["private_key_b64"],
            ))
            services.append(service)
        return services

    def responses(self, services, session, challenge):
        return [service.issue_floor_response(
            challenge=challenge,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            requested_at=8,
            issued_at=9,
            valid_until=20,
        ) for service in services]

    def load(self, local_store, responses, ledger, challenge, *, config=None, expected_digest=None):
        return enforce_policy_transparency_floor_quorum(
            local_store,
            responses,
            witness_registry=self.registry,
            floor_quorum_config=config or self.config,
            expected_floor_config_sha256=expected_digest or self.config["config_sha256"],
            expected_policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
            challenge_ledger=ledger,
            expected_challenge=challenge,
            evaluation_tick=9,
        )

    def signed_view(self, witness_index, policy, session, challenge, *, head_config_sha256=HEAD_CONFIG_SHA256):
        row = self.witnesses[witness_index]
        response = make_policy_transparency_floor_response(
            witness_id=row["witness_id"],
            log_id=row["log_id"],
            policy_head_quorum_config_sha256=head_config_sha256,
            policy_id=policy["policy_id"],
            minimum_policy_version=policy["policy_version"],
            minimum_policy_sha256=policy["policy_sha256"],
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
            purpose=PURPOSE_POLICY_TRANSPARENCY_WITNESS,
            key_id=row["key_id"],
            signer_id=row["signer_id"],
            trust_domain=row["trust_domain"],
            private_key_b64=row["pair"]["private_key_b64"],
            issued_at=9,
            valid_until=20,
        )


class PolicyTransparencyFloorTests(unittest.TestCase):
    def setUp(self):
        self.fx = PolicyTransparencyFloorFixture()

    def _session(self):
        return VerifierFreshnessSession.create("verifier:floor", 8)

    def test_two_of_three_current_witnesses_accept_current_policy(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root / "witnesses", (2, 2, 2))
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 2)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            result = self.fx.load(local, self.fx.responses(services[:2], session, challenge), ledger, challenge)
        self.assertEqual(result["transparency_floor"]["minimum_policy_version"], 2)
        self.assertEqual(len(result["transparency_floor"]["members"]), 2)

    def test_transparency_floor_blocks_rolled_back_head_and_local_policy(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root / "witnesses", (2, 2, 2))
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 1)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, self.fx.responses(services[:2], session, challenge), ledger, challenge)
            ledger.inspect_issued(challenge, 9)
        self.assertEqual(cm.exception.code, "policy_below_transparency_floor")

    def test_one_stale_witness_cannot_override_two_current_witnesses(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root / "witnesses", (1, 2, 2))
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 2)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            result = self.fx.load(local, self.fx.responses(services, session, challenge), ledger, challenge)
        self.assertEqual(result["transparency_floor"]["minimum_policy_version"], 2)

    def test_split_floor_without_threshold_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root / "witnesses", (1, 2, 1))
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 2)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, self.fx.responses(services[:2], session, challenge), ledger, challenge)
        self.assertEqual(cm.exception.code, "transparency_floor_quorum_not_met")

    def test_current_policy_above_floor_requires_exact_floor_in_history(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root / "witnesses", (2, 2, 2))
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 3)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            result = self.fx.load(local, self.fx.responses(services[:2], session, challenge), ledger, challenge)
        self.assertEqual(result["policy"]["policy_version"], 3)
        self.assertEqual(result["transparency_floor"]["minimum_policy_version"], 2)

    def test_same_version_different_digest_is_not_in_local_history(self):
        fork = self.fx.managed.policy(
            2,
            self.fx.policy1["policy_sha256"],
            self.fx.signers,
            2,
            anchor_set_id="anchor-set:fork",
        )
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            local = stack.enter_context(self.fx.store(root / "local.db"))
            local.install(self.fx.managed.signed_policy(self.fx.policy1), 5)
            local.install(self.fx.managed.signed_policy(fork), 5)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            responses = [self.fx.signed_view(0, self.fx.policy2, session, challenge), self.fx.signed_view(1, self.fx.policy2, session, challenge)]
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, responses, ledger, challenge)
        self.assertEqual(cm.exception.code, "transparency_floor_not_in_local_history")

    def test_floor_config_cannot_be_substituted_under_pinned_digest(self):
        lower = make_policy_transparency_floor_quorum_config(
            config_id="policy-transparency-floor:main",
            witness_set_id="policy-transparency-set:primary",
            policy_id="quorum-policy:main",
            policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
            threshold=2,
            witnesses=self.fx.config_rows(),
            valid_from=1,
            valid_until=200,
        )
        strict = make_policy_transparency_floor_quorum_config(
            config_id="policy-transparency-floor:main",
            witness_set_id="policy-transparency-set:primary",
            policy_id="quorum-policy:main",
            policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
            threshold=3,
            witnesses=self.fx.config_rows(),
            valid_from=1,
            valid_until=200,
        )
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root / "witnesses", (2, 2, 2))
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 2)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, self.fx.responses(services[:2], session, challenge), ledger, challenge, config=lower, expected_digest=strict["config_sha256"])
        self.assertEqual(cm.exception.code, "transparency_floor_config_substitution")

    def test_witness_equivocation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 2)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            responses = [
                self.fx.signed_view(0, self.fx.policy1, session, challenge),
                self.fx.signed_view(0, self.fx.policy2, session, challenge),
                self.fx.signed_view(1, self.fx.policy2, session, challenge),
            ]
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, responses, ledger, challenge)
        self.assertEqual(cm.exception.code, "transparency_witness_equivocation")

    def test_response_bound_to_exact_head_quorum_config(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 2)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            challenge = ledger.issue(8, 20)
            responses = [
                self.fx.signed_view(0, self.fx.policy2, session, challenge, head_config_sha256="b" * 64),
                self.fx.signed_view(1, self.fx.policy2, session, challenge, head_config_sha256="b" * 64),
            ]
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, responses, ledger, challenge)
        self.assertEqual(cm.exception.code, "transparency_floor_quorum_not_met")

    def test_old_response_cannot_answer_new_challenge(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            services = self.fx.open_services(stack, root / "witnesses", (2, 2, 2))
            local = stack.enter_context(self.fx.store(root / "local.db"))
            self.fx.install(local, 2)
            session = self._session()
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "challenges.db", session))
            old_challenge = ledger.issue(8, 20)
            old = self.fx.responses(services[:2], session, old_challenge)
            new_challenge = ledger.issue(8, 20)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self.fx.load(local, old, ledger, new_challenge)
        self.assertEqual(cm.exception.code, "transparency_floor_quorum_not_met")

    def test_threshold_requires_distinct_trust_domains(self):
        rows = self.fx.config_rows()
        rows[1]["trust_domain"] = rows[0]["trust_domain"]
        config = make_policy_transparency_floor_quorum_config(
            config_id="bad",
            witness_set_id="bad-set",
            policy_id="quorum-policy:main",
            policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
            threshold=3,
            witnesses=rows,
            valid_from=1,
            valid_until=200,
        )
        result = validate_policy_transparency_floor_quorum_config(config, 9)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("insufficient_domain_diversity", {row["code"] for row in result["errors"]})


if __name__ == "__main__":
    unittest.main()
