from __future__ import annotations

from collections.abc import Iterator, Mapping
from copy import deepcopy
import unittest

from triaxis import (
    AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V2_CONTRACT_ID,
    AuthorityAnalysisSession,
)
from triaxis.provenance_trust_state import (
    ProvenanceTrustStateGuard,
    TrustSnapshotStateError,
)
from validation.analysis_support_v5 import (
    build_valid_analysis_bundle_v5,
    reseal_analysis_bundle_v5,
)
from validation.provenance_trust.authority_analysis_atomicity_trigger_v27 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import (
    build_snapshot_authority_root,
    seal_snapshot_envelope,
)


class V234AuthorityAnalysisAtomicityTests(unittest.TestCase):
    @staticmethod
    def _bundle(*, tick: int = 5) -> dict:
        return _bind(
            build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=tick),
            REVIEW_REF,
        )

    @staticmethod
    def _session(bundle: Mapping[str, object], *, tick: int = 5):
        snapshot = build_trust_fixture_v2(bundle, evaluation_tick=tick).snapshot
        root = build_snapshot_authority_root(valid_until=200)
        envelope = seal_snapshot_envelope(
            snapshot,
            sequence=1,
            previous_envelope_sha256=None,
            issued_at=tick,
            valid_until=200,
        )
        guard = ProvenanceTrustStateGuard(authority_roots=[root])
        return AuthorityAnalysisSession(trust_guard=guard), envelope

    def test_session_contract_is_bumped_without_erasing_v2(self) -> None:
        self.assertEqual(
            AUTHORITY_ANALYSIS_SESSION_V2_CONTRACT_ID,
            "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v2",
        )
        self.assertEqual(
            AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID,
            "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v3",
        )

    def test_frozen_v27_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9)
        self.assertEqual(result["positive_control_pass_count"], 4)
        self.assertEqual(
            result["rows_sha256"],
            "05c12354d1142896875be5435b4c2e6a8b9ef5be436b138e8e998660c4241b82",
        )

    def test_analysis_rejection_does_not_commit_genesis(self) -> None:
        valid = self._bundle()
        invalid = deepcopy(valid)
        invalid["synthesis"]["rationale_claim_ids"] = ["D_ACTION_RISK"]
        invalid = reseal_analysis_bundle_v5(invalid)
        session, envelope = self._session(valid)
        result = session.validate(
            invalid,
            trust_envelope=envelope,
            trusted_evaluation_tick=5,
        )
        self.assertEqual(result["status"], "BLOCK", result)
        self.assertEqual(
            {item["code"] for item in result["errors"]},
            {"invalid_rationale_role"},
        )
        self.assertIsNone(session.checkpoint)

    def test_rejected_successor_preserves_exact_prior_checkpoint(self) -> None:
        first = self._bundle(tick=5)
        session, first_envelope = self._session(first, tick=5)
        accepted = session.validate(
            first,
            trust_envelope=first_envelope,
            trusted_evaluation_tick=5,
        )
        self.assertEqual(accepted["status"], "PASS", accepted)
        checkpoint = session.checkpoint

        valid_second = self._bundle(tick=6)
        invalid_second = deepcopy(valid_second)
        invalid_second["synthesis"]["rationale_claim_ids"] = ["D_ACTION_RISK"]
        invalid_second = reseal_analysis_bundle_v5(invalid_second)
        snapshot = build_trust_fixture_v2(valid_second, evaluation_tick=6).snapshot
        second_envelope = seal_snapshot_envelope(
            snapshot,
            sequence=2,
            previous_envelope_sha256=first_envelope["envelope_sha256"],
            issued_at=6,
            valid_until=200,
        )
        rejected = session.validate(
            invalid_second,
            trust_envelope=second_envelope,
            trusted_evaluation_tick=6,
        )
        self.assertEqual(rejected["status"], "BLOCK", rejected)
        self.assertEqual(session.checkpoint, checkpoint)

    def test_rejected_analysis_never_calls_mutating_accept(self) -> None:
        class CountingGuard(ProvenanceTrustStateGuard):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.accept_calls = 0

            def accept(self, value, *, evaluation_tick):
                self.accept_calls += 1
                return super().accept(value, evaluation_tick=evaluation_tick)

        valid = self._bundle()
        invalid = deepcopy(valid)
        invalid["synthesis"]["rationale_claim_ids"] = ["D_ACTION_RISK"]
        invalid = reseal_analysis_bundle_v5(invalid)
        snapshot = build_trust_fixture_v2(valid, evaluation_tick=5).snapshot
        root = build_snapshot_authority_root(valid_until=200)
        envelope = seal_snapshot_envelope(
            snapshot,
            sequence=1,
            previous_envelope_sha256=None,
            issued_at=5,
            valid_until=200,
        )
        guard = CountingGuard(authority_roots=[root])
        result = AuthorityAnalysisSession(trust_guard=guard).validate(
            invalid,
            trust_envelope=envelope,
            trusted_evaluation_tick=5,
        )
        self.assertEqual(result["status"], "BLOCK", result)
        self.assertEqual(guard.accept_calls, 0)
        self.assertIsNone(guard.checkpoint)

    def test_final_commit_recheck_failure_blocks_without_state(self) -> None:
        class RacingGuard(ProvenanceTrustStateGuard):
            def accept(self, value, *, evaluation_tick):
                raise TrustSnapshotStateError(
                    "simulated_concurrent_state_change",
                    "state changed after preparation",
                )

        valid = self._bundle()
        snapshot = build_trust_fixture_v2(valid, evaluation_tick=5).snapshot
        root = build_snapshot_authority_root(valid_until=200)
        envelope = seal_snapshot_envelope(
            snapshot,
            sequence=1,
            previous_envelope_sha256=None,
            issued_at=5,
            valid_until=200,
        )
        guard = RacingGuard(authority_roots=[root])
        result = AuthorityAnalysisSession(trust_guard=guard).validate(
            valid,
            trust_envelope=envelope,
            trusted_evaluation_tick=5,
        )
        self.assertEqual(result["primary_reason"], "BLOCKED_BY_TRUST_SNAPSHOT_STATE")
        self.assertEqual(
            {item["code"] for item in result["errors"]},
            {"simulated_concurrent_state_change"},
        )
        self.assertIsNone(guard.checkpoint)

    def test_hostile_bundle_mapping_blocks_without_checkpoint_mutation(self) -> None:
        class BrokenMapping(Mapping[str, object]):
            def __getitem__(self, key: str) -> object:
                raise RuntimeError("broken bundle")

            def __iter__(self) -> Iterator[str]:
                raise RuntimeError("broken bundle")

            def __len__(self) -> int:
                return 1

        valid = self._bundle()
        session, envelope = self._session(valid)
        result = session.validate(
            BrokenMapping(),
            trust_envelope=envelope,
            trusted_evaluation_tick=5,
        )
        self.assertEqual(result["primary_reason"], "BLOCKED_BY_ANALYSIS_CONTRACT")
        self.assertEqual(
            {item["code"] for item in result["errors"]},
            {"invalid_analysis_bundle_materialization"},
        )
        self.assertIsNone(session.checkpoint)


if __name__ == "__main__":
    unittest.main()
