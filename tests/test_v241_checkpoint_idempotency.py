from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_checkpoint_idempotency_trigger_v34 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope


class V241CheckpointIdempotencyTests(unittest.TestCase):
    @staticmethod
    def _root() -> dict:
        return build_snapshot_authority_root(valid_until=200)

    @staticmethod
    def _bundle(tick: int) -> dict:
        return _bind(
            build_valid_analysis_bundle_v5(
                run_id=f"v241-{tick}", control_profile="A3", evaluation_tick=tick,
            ),
            REVIEW_REF,
        )

    @classmethod
    def _chain(cls):
        b1 = cls._bundle(5)
        e1 = seal_snapshot_envelope(
            build_trust_fixture_v2(b1, evaluation_tick=5).snapshot,
            sequence=1, previous_envelope_sha256=None, issued_at=5, valid_until=200,
        )
        guard = ProvenanceTrustStateGuard(authority_roots=[cls._root()])
        session = AuthorityAnalysisSession(trust_guard=guard)
        self_result = session.validate(b1, trust_envelope=e1, trusted_evaluation_tick=5)
        if self_result.get("status") != "PASS": raise AssertionError(self_result)
        c1 = guard.checkpoint.as_dict()
        b2 = cls._bundle(6)
        e2 = seal_snapshot_envelope(
            build_trust_fixture_v2(b2, evaluation_tick=6).snapshot,
            sequence=2, previous_envelope_sha256=e1["envelope_sha256"], issued_at=6, valid_until=200,
        )
        second = session.validate(b2, trust_envelope=e2, trusted_evaluation_tick=6)
        if second.get("status") != "PASS": raise AssertionError(second)
        return c1, e1, guard.checkpoint.as_dict(), e2

    def test_frozen_v34_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 10, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_exact_retry_returns_same_head_without_history_growth(self) -> None:
        c1, e1, c2, e2 = self._chain()
        with tempfile.TemporaryDirectory() as td, SQLiteCheckpointStore(Path(td) / "s.db", namespace="N") as store:
            h1 = store.commit(checkpoint_receipt=c1, trust_envelope=e1, authority_roots=[self._root()], expected_previous_head=None)
            h2 = store.commit(checkpoint_receipt=c2, trust_envelope=e2, authority_roots=[self._root()], expected_previous_head=h1)
            again = store.commit(checkpoint_receipt=c2, trust_envelope=e2, authority_roots=[self._root()], expected_previous_head=h1)
            self.assertEqual(again, h2)
            self.assertEqual(len(store.history()), 2)

    def test_exact_pair_with_false_predecessor_is_not_reconciled(self) -> None:
        c1, e1, c2, e2 = self._chain()
        with tempfile.TemporaryDirectory() as td, SQLiteCheckpointStore(Path(td) / "s.db", namespace="N") as store:
            h1 = store.commit(checkpoint_receipt=c1, trust_envelope=e1, authority_roots=[self._root()], expected_previous_head=None)
            store.commit(checkpoint_receipt=c2, trust_envelope=e2, authority_roots=[self._root()], expected_previous_head=h1)
            with self.assertRaises(CheckpointStoreError) as caught:
                store.commit(checkpoint_receipt=c2, trust_envelope=e2, authority_roots=[self._root()], expected_previous_head="f" * 64)
            self.assertEqual(caught.exception.code, "checkpoint_store_cas_mismatch")
            self.assertEqual(len(store.history()), 2)


if __name__ == "__main__":
    unittest.main()
