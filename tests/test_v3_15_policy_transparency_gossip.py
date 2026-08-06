from __future__ import annotations

from contextlib import ExitStack
import tempfile
import unittest
from pathlib import Path

from tests.test_v3_14_policy_transparency_floor import (
    HEAD_CONFIG_SHA256,
    PolicyTransparencyFloorFixture,
)
from triaxis.policy_head_authority import PolicyHeadAuthorityError
from triaxis.policy_transparency_floor import (
    SQLitePolicyTransparencyGossipStore,
    enforce_policy_transparency_floor_quorum_with_gossip,
)
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


class PolicyTransparencyGossipTests(unittest.TestCase):
    def setUp(self):
        self.fx = PolicyTransparencyFloorFixture()

    def _load(self, local, responses, ledger, challenge, gossip):
        return enforce_policy_transparency_floor_quorum_with_gossip(
            local,
            responses,
            gossip_store=gossip,
            witness_registry=self.fx.registry,
            floor_quorum_config=self.fx.config,
            expected_floor_config_sha256=self.fx.config["config_sha256"],
            expected_policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
            challenge_ledger=ledger,
            expected_challenge=challenge,
            evaluation_tick=9,
        )

    def _session(self, verifier):
        return VerifierFreshnessSession.create(verifier, 8)

    def test_cross_session_witness_rollback_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))

            local3 = stack.enter_context(self.fx.store(root / "local3.db")); self.fx.install(local3, 3)
            s1 = self._session("verifier:A")
            l1 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c1.db", s1)); c1 = l1.issue(8, 20)
            higher = [self.fx.signed_view(0, self.fx.policy3, s1, c1), self.fx.signed_view(1, self.fx.policy3, s1, c1)]
            self._load(local3, higher, l1, c1, gossip)

            local2 = stack.enter_context(self.fx.store(root / "local2.db")); self.fx.install(local2, 2)
            s2 = self._session("verifier:B")
            l2 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c2.db", s2)); c2 = l2.issue(8, 20)
            lower = [self.fx.signed_view(0, self.fx.policy2, s2, c2), self.fx.signed_view(2, self.fx.policy2, s2, c2)]
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self._load(local2, lower, l2, c2, gossip)
            l2.inspect_issued(c2, 9)
        self.assertEqual(cm.exception.code, "transparency_witness_rollback_detected")

    def test_same_version_fork_is_rejected_across_sessions(self):
        fork = self.fx.managed.policy(
            2,
            self.fx.policy1["policy_sha256"],
            self.fx.signers,
            2,
            anchor_set_id="anchor-set:gossip-fork",
        )
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))
            local = stack.enter_context(self.fx.store(root / "local.db")); self.fx.install(local, 2)

            s1 = self._session("verifier:A")
            l1 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c1.db", s1)); c1 = l1.issue(8, 20)
            accepted = [self.fx.signed_view(0, self.fx.policy2, s1, c1), self.fx.signed_view(1, self.fx.policy2, s1, c1)]
            self._load(local, accepted, l1, c1, gossip)

            s2 = self._session("verifier:B")
            l2 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c2.db", s2)); c2 = l2.issue(8, 20)
            conflicting = [self.fx.signed_view(0, fork, s2, c2), self.fx.signed_view(2, fork, s2, c2)]
            with self.assertRaises(PolicyHeadAuthorityError) as cm:
                self._load(local, conflicting, l2, c2, gossip)
        self.assertEqual(cm.exception.code, "transparency_witness_fork_detected")

    def test_exact_floor_is_idempotent_across_sessions(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))
            local = stack.enter_context(self.fx.store(root / "local.db")); self.fx.install(local, 2)
            for suffix in ("A", "B"):
                session = self._session(f"verifier:{suffix}")
                ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / f"c{suffix}.db", session))
                challenge = ledger.issue(8, 20)
                responses = [self.fx.signed_view(0, self.fx.policy2, session, challenge), self.fx.signed_view(1, self.fx.policy2, session, challenge)]
                result = self._load(local, responses, ledger, challenge, gossip)
                self.assertEqual(result["transparency_floor"]["minimum_policy_version"], 2)
            self.assertEqual(gossip.head(self.fx.witnesses[0]["signer_id"])["minimum_policy_version"], 2)

    def test_higher_floor_advances_persistent_pin(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))
            local2 = stack.enter_context(self.fx.store(root / "local2.db")); self.fx.install(local2, 2)
            s1 = self._session("verifier:A")
            l1 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c1.db", s1)); c1 = l1.issue(8, 20)
            self._load(local2, [self.fx.signed_view(0, self.fx.policy2, s1, c1), self.fx.signed_view(1, self.fx.policy2, s1, c1)], l1, c1, gossip)

            local3 = stack.enter_context(self.fx.store(root / "local3.db")); self.fx.install(local3, 3)
            s2 = self._session("verifier:B")
            l2 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c2.db", s2)); c2 = l2.issue(8, 20)
            self._load(local3, [self.fx.signed_view(0, self.fx.policy3, s2, c2), self.fx.signed_view(1, self.fx.policy3, s2, c2)], l2, c2, gossip)
            self.assertEqual(gossip.head(self.fx.witnesses[0]["signer_id"])["minimum_policy_version"], 3)

    def test_gossip_pin_survives_process_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with ExitStack() as stack:
                gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))
                local3 = stack.enter_context(self.fx.store(root / "local3.db")); self.fx.install(local3, 3)
                s1 = self._session("verifier:A")
                l1 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c1.db", s1)); c1 = l1.issue(8, 20)
                self._load(local3, [self.fx.signed_view(0, self.fx.policy3, s1, c1), self.fx.signed_view(1, self.fx.policy3, s1, c1)], l1, c1, gossip)
            with ExitStack() as stack:
                gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))
                local2 = stack.enter_context(self.fx.store(root / "local2.db")); self.fx.install(local2, 2)
                s2 = self._session("verifier:B")
                l2 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c2.db", s2)); c2 = l2.issue(8, 20)
                with self.assertRaises(PolicyHeadAuthorityError) as cm:
                    self._load(local2, [self.fx.signed_view(0, self.fx.policy2, s2, c2), self.fx.signed_view(2, self.fx.policy2, s2, c2)], l2, c2, gossip)
        self.assertEqual(cm.exception.code, "transparency_witness_rollback_detected")

    def test_independent_signers_have_independent_pins(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))
            local3 = stack.enter_context(self.fx.store(root / "local3.db")); self.fx.install(local3, 3)
            s1 = self._session("verifier:A")
            l1 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c1.db", s1)); c1 = l1.issue(8, 20)
            self._load(local3, [self.fx.signed_view(0, self.fx.policy3, s1, c1), self.fx.signed_view(1, self.fx.policy3, s1, c1)], l1, c1, gossip)
            self.assertIsNone(gossip.head(self.fx.witnesses[2]["signer_id"]))

    def test_gossip_history_records_only_monotonic_advances(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))
            local2 = stack.enter_context(self.fx.store(root / "local2.db")); self.fx.install(local2, 2)
            s1 = self._session("verifier:A")
            l1 = stack.enter_context(SQLiteEpochChallengeLedger(root / "c1.db", s1)); c1 = l1.issue(8, 20)
            self._load(local2, [self.fx.signed_view(0, self.fx.policy2, s1, c1), self.fx.signed_view(1, self.fx.policy2, s1, c1)], l1, c1, gossip)
            count = gossip._conn.execute("SELECT COUNT(*) FROM transparency_witness_pin_history").fetchone()[0]
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
