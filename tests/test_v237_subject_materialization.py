from __future__ import annotations

import unittest

from triaxis import (
    AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V5_CONTRACT_ID,
    AuthorityAnalysisSession,
)
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_subject_materialization_trigger_v30 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope


class V237SubjectMaterializationTests(unittest.TestCase):
    @staticmethod
    def _bundle() -> dict:
        return _bind(
            build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=6),
            REVIEW_REF,
        )

    @staticmethod
    def _session_and_envelope(source: dict):
        snapshot = build_trust_fixture_v2(source, evaluation_tick=6).snapshot
        envelope = seal_snapshot_envelope(
            snapshot,
            sequence=1,
            previous_envelope_sha256=None,
            issued_at=6,
            valid_until=200,
        )
        guard = ProvenanceTrustStateGuard(
            authority_roots=[build_snapshot_authority_root(valid_until=200)]
        )
        return AuthorityAnalysisSession(trust_guard=guard), guard, envelope

    def test_contract_bumps_to_v6_without_erasing_v5(self) -> None:
        self.assertEqual(
            AUTHORITY_ANALYSIS_SESSION_V5_CONTRACT_ID,
            "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v5",
        )
        self.assertEqual(
            AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID,
            "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v6",
        )

    def test_frozen_v30_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_nested_set_returns_contract_block_without_state(self) -> None:
        source = self._bundle()
        malformed = dict(source)
        malformed["provenance_registry"] = {"records": {"not-json"}}
        session, guard, envelope = self._session_and_envelope(source)
        result = session.validate(
            malformed,
            trust_envelope=envelope,
            trusted_evaluation_tick=6,
        )
        self.assertEqual(result["status"], "BLOCK", result)
        self.assertEqual(result["primary_reason"], "BLOCKED_BY_ANALYSIS_CONTRACT")
        self.assertEqual(
            {item["code"] for item in result["errors"]},
            {"invalid_analysis_bundle_materialization"},
        )
        self.assertIsNone(guard.checkpoint)

    def test_cyclic_registry_returns_contract_block_without_state(self) -> None:
        source = self._bundle()
        malformed = dict(source)
        cycle = {}
        cycle["self"] = cycle
        malformed["provenance_registry"] = cycle
        session, guard, envelope = self._session_and_envelope(source)
        result = session.validate(
            malformed,
            trust_envelope=envelope,
            trusted_evaluation_tick=6,
        )
        self.assertEqual(result["status"], "BLOCK", result)
        self.assertEqual(
            {item["code"] for item in result["errors"]},
            {"invalid_analysis_bundle_materialization"},
        )
        self.assertIsNone(guard.checkpoint)


if __name__ == "__main__":
    unittest.main()
