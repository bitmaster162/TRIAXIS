from __future__ import annotations

from copy import deepcopy
import unittest

from triaxis import (
    AUTHORITY_ANALYSIS_SESSION_V4_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V5_CONTRACT_ID,
    AuthorityAnalysisSession,
)
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import (
    ProvenanceTrustStateGuard,
    TrustSnapshotStateError,
)
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_snapshot_subject_binding_trigger_v29 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import (
    build_snapshot_authority_root,
    seal_snapshot_envelope,
)


class V236SnapshotSubjectBindingTests(unittest.TestCase):
    @staticmethod
    def _bundle(tick: int = 6) -> dict:
        return _bind(
            build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=tick),
            REVIEW_REF,
        )

    @staticmethod
    def _guard() -> ProvenanceTrustStateGuard:
        return ProvenanceTrustStateGuard(
            authority_roots=[build_snapshot_authority_root(valid_until=200)]
        )

    @staticmethod
    def _envelope(snapshot: dict, *, tick: int = 6) -> dict:
        return seal_snapshot_envelope(
            snapshot,
            sequence=1,
            previous_envelope_sha256=None,
            issued_at=tick,
            valid_until=200,
        )

    def test_contract_bumps_to_v5_without_erasing_v4(self) -> None:
        self.assertEqual(
            AUTHORITY_ANALYSIS_SESSION_V4_CONTRACT_ID,
            "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v4",
        )
        self.assertEqual(
            AUTHORITY_ANALYSIS_SESSION_V5_CONTRACT_ID,
            "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v5",
        )

    def test_frozen_v29_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_direct_guard_requires_subject_binding(self) -> None:
        bundle = self._bundle()
        snapshot = build_trust_fixture_v2(bundle, evaluation_tick=6).snapshot
        envelope = self._envelope(snapshot)
        guard = self._guard()
        with self.assertRaises(TrustSnapshotStateError) as caught:
            guard.accept(envelope, evaluation_tick=6)
        self.assertEqual(caught.exception.code, "trust_snapshot_subject_binding_required")
        self.assertIsNone(guard.checkpoint)

    def test_direct_guard_rechecks_exact_bundle_digest(self) -> None:
        bundle = self._bundle()
        snapshot = build_trust_fixture_v2(bundle, evaluation_tick=6).snapshot
        envelope = self._envelope(snapshot)
        guard = self._guard()
        with self.assertRaises(TrustSnapshotStateError) as caught:
            guard.accept(
                envelope,
                evaluation_tick=6,
                expected_bundle_sha256="0" * 64,
                expected_trust_records_sha256=canonical_sha256(bundle["provenance_registry"]),
            )
        self.assertEqual(caught.exception.code, "trust_snapshot_bundle_binding_mismatch")
        self.assertIsNone(guard.checkpoint)

    def test_provenance_mismatch_is_state_neutral(self) -> None:
        bundle = self._bundle()
        snapshot = deepcopy(build_trust_fixture_v2(bundle, evaluation_tick=6).snapshot)
        snapshot["trust_records_sha256"] = canonical_sha256({"records": []})
        envelope = self._envelope(snapshot)
        guard = self._guard()
        result = AuthorityAnalysisSession(trust_guard=guard).validate(
            bundle,
            trust_envelope=envelope,
            trusted_evaluation_tick=6,
        )
        self.assertEqual(result["status"], "BLOCK", result)
        self.assertEqual(
            {item["code"] for item in result["errors"]},
            {"trust_snapshot_provenance_binding_mismatch"},
        )
        self.assertIsNone(guard.checkpoint)


if __name__ == "__main__":
    unittest.main()
