from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.integrity import canonical_json_bytes
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_checkpoint_history_integrity_trigger_v37 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope


class V243HistoryIntegrityTests(unittest.TestCase):
    NAMESPACE = "unit:history"

    @staticmethod
    def _root() -> dict:
        return build_snapshot_authority_root(valid_until=200)

    @classmethod
    def _chain(cls) -> list[tuple[dict, dict]]:
        guard = ProvenanceTrustStateGuard(authority_roots=[cls._root()])
        session = AuthorityAnalysisSession(trust_guard=guard)
        result = []
        parent = None
        for sequence, tick in enumerate((5, 6, 7), 1):
            bundle = _bind(
                build_valid_analysis_bundle_v5(
                    run_id=f"v243-{tick}",
                    control_profile="A3",
                    evaluation_tick=tick,
                ),
                REVIEW_REF,
            )
            envelope = seal_snapshot_envelope(
                build_trust_fixture_v2(bundle, evaluation_tick=tick).snapshot,
                sequence=sequence,
                previous_envelope_sha256=parent,
                issued_at=tick,
                valid_until=200,
            )
            outcome = session.validate(
                bundle,
                trust_envelope=envelope,
                trusted_evaluation_tick=tick,
            )
            if outcome.get("status") != "PASS" or guard.checkpoint is None:
                raise AssertionError(outcome)
            result.append((guard.checkpoint.as_dict(), envelope))
            parent = envelope["envelope_sha256"]
        return result

    @classmethod
    def _populate(cls, path: Path) -> list[tuple[dict, dict]]:
        items = cls._chain()
        previous = None
        with SQLiteCheckpointStore(path, namespace=cls.NAMESPACE) as store:
            for receipt, envelope in items:
                previous = store.commit(
                    checkpoint_receipt=receipt,
                    trust_envelope=envelope,
                    authority_roots=[cls._root()],
                    expected_previous_head=previous,
                )
        return items

    def test_frozen_v37_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_missing_middle_blocks_current_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            self._populate(path)
            conn = sqlite3.connect(path)
            conn.execute(
                "DELETE FROM checkpoint_history WHERE namespace = ? AND sequence = 2",
                (self.NAMESPACE,),
            )
            conn.commit()
            conn.close()
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                with self.assertRaises(CheckpointStoreError) as caught:
                    store.get_current()
            self.assertEqual(caught.exception.code, "checkpoint_store_history_incomplete")

    def test_current_behind_history_tip_blocks_restore(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            items = self._populate(path)
            receipt, envelope = items[1]
            conn = sqlite3.connect(path)
            conn.execute(
                "UPDATE checkpoint_current SET head_sha256=?, sequence=?, receipt_json=?, envelope_json=? "
                "WHERE namespace=?",
                (
                    receipt["checkpoint_sha256"],
                    2,
                    canonical_json_bytes(receipt),
                    canonical_json_bytes(envelope),
                    self.NAMESPACE,
                ),
            )
            conn.commit()
            conn.close()
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                with self.assertRaises(CheckpointStoreError) as caught:
                    store.load_guard(
                        authority_roots=[self._root()],
                        expected_checkpoint_sha256=receipt["checkpoint_sha256"],
                    )
            self.assertEqual(caught.exception.code, "checkpoint_store_current_not_history_tip")

    def test_intact_history_authenticates_every_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            items = self._populate(path)
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                guard = store.load_guard(
                    authority_roots=[self._root()],
                    expected_checkpoint_sha256=items[-1][0]["checkpoint_sha256"],
                )
                self.assertEqual(guard.checkpoint.as_dict(), items[-1][0])
                self.assertEqual([x["receipt"]["sequence"] for x in store.history()], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
