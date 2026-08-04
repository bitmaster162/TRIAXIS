from __future__ import annotations

from copy import deepcopy
import unittest

from triaxis import AuthorityAnalysisSession
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import (
    ProvenanceTrustStateGuard,
    TrustSnapshotStateError,
)
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_checkpoint_restore_trigger_v32 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import (
    build_snapshot_authority_root,
    seal_snapshot_envelope,
)


class V239CheckpointRestoreTests(unittest.TestCase):
    @staticmethod
    def _bundle(tick: int, run_id: str = "restore-unit") -> dict:
        return _bind(
            build_valid_analysis_bundle_v5(
                control_profile="A3",
                evaluation_tick=tick,
                run_id=f"{run_id}-{tick}",
            ),
            REVIEW_REF,
        )

    @staticmethod
    def _root() -> dict:
        return build_snapshot_authority_root(valid_until=200)

    @classmethod
    def _envelope(cls, bundle: dict, *, tick: int, sequence: int, parent=None) -> dict:
        snapshot = build_trust_fixture_v2(bundle, evaluation_tick=tick).snapshot
        return seal_snapshot_envelope(
            snapshot,
            sequence=sequence,
            previous_envelope_sha256=parent,
            issued_at=tick,
            valid_until=200,
        )

    @classmethod
    def _accepted_genesis(cls):
        bundle = cls._bundle(5)
        envelope = cls._envelope(bundle, tick=5, sequence=1)
        guard = ProvenanceTrustStateGuard(authority_roots=[cls._root()])
        result = AuthorityAnalysisSession(trust_guard=guard).validate(
            bundle,
            trust_envelope=envelope,
            trusted_evaluation_tick=5,
        )
        if result.get("status") != "PASS":
            raise AssertionError(result)
        return bundle, envelope, guard.checkpoint.as_dict()

    def test_frozen_v32_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 10, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_exact_restore_reproduces_receipt(self) -> None:
        _, envelope, receipt = self._accepted_genesis()
        restored = ProvenanceTrustStateGuard.from_checkpoint(
            authority_roots=[self._root()],
            checkpoint_receipt=receipt,
            trust_envelope=envelope,
            expected_checkpoint_sha256=receipt["checkpoint_sha256"],
        )
        self.assertEqual(restored.checkpoint.as_dict(), receipt)

    def test_external_head_mismatch_blocks_rollback(self) -> None:
        _, envelope, receipt = self._accepted_genesis()
        with self.assertRaises(TrustSnapshotStateError) as caught:
            ProvenanceTrustStateGuard.from_checkpoint(
                authority_roots=[self._root()],
                checkpoint_receipt=receipt,
                trust_envelope=envelope,
                expected_checkpoint_sha256="f" * 64,
            )
        self.assertEqual(caught.exception.code, "checkpoint_restore_head_mismatch")

    def test_valid_receipt_cannot_be_paired_with_another_valid_envelope(self) -> None:
        _, _, receipt = self._accepted_genesis()
        other = self._bundle(5, run_id="other")
        other_envelope = self._envelope(other, tick=5, sequence=1)
        with self.assertRaises(TrustSnapshotStateError) as caught:
            ProvenanceTrustStateGuard.from_checkpoint(
                authority_roots=[self._root()],
                checkpoint_receipt=receipt,
                trust_envelope=other_envelope,
                expected_checkpoint_sha256=receipt["checkpoint_sha256"],
            )
        self.assertEqual(caught.exception.code, "checkpoint_restore_envelope_mismatch")

    def test_tampered_receipt_is_rejected_before_hydration(self) -> None:
        _, envelope, receipt = self._accepted_genesis()
        tampered = deepcopy(receipt)
        tampered["sequence"] = 2
        with self.assertRaises(TrustSnapshotStateError) as caught:
            ProvenanceTrustStateGuard.from_checkpoint(
                authority_roots=[self._root()],
                checkpoint_receipt=tampered,
                trust_envelope=envelope,
                expected_checkpoint_sha256=receipt["checkpoint_sha256"],
            )
        self.assertEqual(caught.exception.code, "checkpoint_receipt_digest_mismatch")

    def test_restored_guard_accepts_only_exact_successor(self) -> None:
        first, first_envelope, receipt = self._accepted_genesis()
        restored = ProvenanceTrustStateGuard.from_checkpoint(
            authority_roots=[self._root()],
            checkpoint_receipt=receipt,
            trust_envelope=first_envelope,
            expected_checkpoint_sha256=receipt["checkpoint_sha256"],
        )
        second = self._bundle(6)
        second_envelope = self._envelope(
            second,
            tick=6,
            sequence=2,
            parent=first_envelope["envelope_sha256"],
        )
        result = AuthorityAnalysisSession(trust_guard=restored).validate(
            second,
            trust_envelope=second_envelope,
            trusted_evaluation_tick=6,
        )
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(restored.checkpoint.sequence, 2)
        self.assertEqual(
            restored.checkpoint.previous_envelope_sha256,
            first_envelope["envelope_sha256"],
        )
        self.assertEqual(
            restored.checkpoint.snapshot_sha256,
            second_envelope["snapshot_sha256"],
        )
        self.assertEqual(
            restored.checkpoint.evaluation_tick,
            second["frame"]["evaluation_tick"],
        )
        self.assertEqual(
            canonical_sha256(second["provenance_registry"]),
            second_envelope["snapshot"]["trust_records_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
