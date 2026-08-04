from __future__ import annotations

from copy import deepcopy
import unittest

from triaxis import (
    AUTHORITY_ANALYSIS_SESSION_V3_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V4_CONTRACT_ID,
    AuthorityAnalysisSession,
)
from triaxis.provenance_trust_state import (
    ProvenanceTrustStateGuard,
    TrustSnapshotStateError,
)
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_snapshot_freshness_trigger_v28 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import (
    build_snapshot_authority_root,
    seal_snapshot_envelope,
)


class V235SnapshotFreshnessTests(unittest.TestCase):
    @staticmethod
    def _bundle(tick: int) -> dict:
        return _bind(
            build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=tick),
            REVIEW_REF,
        )

    @staticmethod
    def _envelope(source: dict, *, snapshot_tick: int, sequence: int = 1, parent=None, issued_at=None):
        issued_at = snapshot_tick if issued_at is None else issued_at
        snapshot = build_trust_fixture_v2(source, evaluation_tick=snapshot_tick).snapshot
        return seal_snapshot_envelope(
            snapshot,
            sequence=sequence,
            previous_envelope_sha256=parent,
            issued_at=issued_at,
            valid_until=200,
        )

    @staticmethod
    def _guard() -> ProvenanceTrustStateGuard:
        return ProvenanceTrustStateGuard(
            authority_roots=[build_snapshot_authority_root(valid_until=200)]
        )

    def test_contract_bumps_to_v4_without_erasing_v3(self) -> None:
        self.assertEqual(
            AUTHORITY_ANALYSIS_SESSION_V3_CONTRACT_ID,
            "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v3",
        )
        self.assertEqual(
            AUTHORITY_ANALYSIS_SESSION_V4_CONTRACT_ID,
            "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v4",
        )

    def test_frozen_v28_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_stale_genesis_snapshot_blocks_without_checkpoint(self) -> None:
        bundle = self._bundle(6)
        envelope = self._envelope(bundle, snapshot_tick=5, issued_at=6)
        guard = self._guard()
        result = AuthorityAnalysisSession(trust_guard=guard).validate(
            bundle,
            trust_envelope=envelope,
            trusted_evaluation_tick=6,
        )
        self.assertEqual(result["status"], "BLOCK", result)
        self.assertEqual(result["primary_reason"], "BLOCKED_BY_TRUST_SNAPSHOT_STATE")
        self.assertEqual(
            {item["code"] for item in result["errors"]},
            {"stale_trust_snapshot_state"},
        )
        self.assertIsNone(guard.checkpoint)

    def test_stale_successor_preserves_exact_checkpoint(self) -> None:
        first = self._bundle(5)
        first_envelope = self._envelope(first, snapshot_tick=5)
        guard = self._guard()
        session = AuthorityAnalysisSession(trust_guard=guard)
        accepted = session.validate(
            first,
            trust_envelope=first_envelope,
            trusted_evaluation_tick=5,
        )
        self.assertEqual(accepted["status"], "PASS", accepted)
        checkpoint = deepcopy(guard.checkpoint)

        second = self._bundle(6)
        stale = self._envelope(
            second,
            snapshot_tick=5,
            sequence=2,
            parent=first_envelope["envelope_sha256"],
            issued_at=6,
        )
        rejected = session.validate(
            second,
            trust_envelope=stale,
            trusted_evaluation_tick=6,
        )
        self.assertEqual(rejected["status"], "BLOCK", rejected)
        self.assertEqual(guard.checkpoint, checkpoint)

    def test_direct_guard_cannot_bypass_snapshot_time_binding(self) -> None:
        bundle = self._bundle(6)
        envelope = self._envelope(bundle, snapshot_tick=5, issued_at=6)
        guard = self._guard()
        with self.assertRaises(TrustSnapshotStateError) as caught:
            guard.accept(
                envelope,
                evaluation_tick=6,
                expected_bundle_sha256=bundle["bundle_sha256"],
                expected_trust_records_sha256=__import__("triaxis.integrity", fromlist=["canonical_sha256"]).canonical_sha256(bundle["provenance_registry"]),
            )
        self.assertEqual(caught.exception.code, "stale_trust_snapshot_state")
        self.assertIsNone(guard.checkpoint)


if __name__ == "__main__":
    unittest.main()
