from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.integrity import canonical_json_bytes
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_checkpoint_namespace_confinement_trigger_v36 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope


class V242NamespaceConfinementTests(unittest.TestCase):
    @staticmethod
    def _root() -> dict:
        return build_snapshot_authority_root(valid_until=200)

    @classmethod
    def _chain(cls, label: str = "A") -> tuple[dict, dict]:
        bundle = _bind(
            build_valid_analysis_bundle_v5(
                run_id=f"v242-{label}",
                control_profile="A3",
                evaluation_tick=5,
            ),
            REVIEW_REF,
        )
        envelope = seal_snapshot_envelope(
            build_trust_fixture_v2(bundle, evaluation_tick=5).snapshot,
            sequence=1,
            previous_envelope_sha256=None,
            issued_at=5,
            valid_until=200,
        )
        guard = ProvenanceTrustStateGuard(authority_roots=[cls._root()])
        result = AuthorityAnalysisSession(trust_guard=guard).validate(
            bundle,
            trust_envelope=envelope,
            trusted_evaluation_tick=5,
        )
        if result.get("status") != "PASS" or guard.checkpoint is None:
            raise AssertionError(result)
        return guard.checkpoint.as_dict(), envelope

    @classmethod
    def _commit(cls, path: Path, namespace: str, receipt: dict, envelope: dict) -> str:
        with SQLiteCheckpointStore(path, namespace=namespace) as store:
            return store.commit(
                checkpoint_receipt=receipt,
                trust_envelope=envelope,
                authority_roots=[cls._root()],
                expected_previous_head=None,
            )

    def test_frozen_v36_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_same_identity_cannot_cross_namespace(self) -> None:
        receipt, envelope = self._chain()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            self._commit(path, "tenant:A", receipt, envelope)
            with self.assertRaises(CheckpointStoreError) as caught:
                self._commit(path, "tenant:B", receipt, envelope)
            self.assertEqual(caught.exception.code, "checkpoint_store_namespace_replay")

    def test_distinct_identity_can_use_another_namespace(self) -> None:
        left_receipt, left_envelope = self._chain("A")
        right_receipt, right_envelope = self._chain("B")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            left = self._commit(path, "tenant:A", left_receipt, left_envelope)
            right = self._commit(path, "tenant:B", right_receipt, right_envelope)
            self.assertNotEqual(left, right)

    def test_missing_ownership_row_is_corrupt_state(self) -> None:
        receipt, envelope = self._chain()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            self._commit(path, "tenant:A", receipt, envelope)
            conn = sqlite3.connect(path)
            conn.execute("DELETE FROM checkpoint_ownership")
            conn.commit()
            conn.close()
            with SQLiteCheckpointStore(path, namespace="tenant:A") as store:
                with self.assertRaises(CheckpointStoreError) as caught:
                    store.get_current()
            self.assertEqual(caught.exception.code, "checkpoint_store_corrupt_state")

    def test_clean_v1_database_migrates_through_v2_to_current_schema(self) -> None:
        receipt, envelope = self._chain()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            conn = sqlite3.connect(path)
            conn.execute(
                "CREATE TABLE checkpoint_current(namespace TEXT PRIMARY KEY, head_sha256 TEXT NOT NULL, "
                "sequence INTEGER NOT NULL, receipt_json BLOB NOT NULL, envelope_json BLOB NOT NULL) WITHOUT ROWID"
            )
            conn.execute(
                "CREATE TABLE checkpoint_history(namespace TEXT NOT NULL, sequence INTEGER NOT NULL, "
                "checkpoint_sha256 TEXT NOT NULL, receipt_json BLOB NOT NULL, envelope_json BLOB NOT NULL, "
                "PRIMARY KEY(namespace, sequence), UNIQUE(namespace, checkpoint_sha256)) WITHOUT ROWID"
            )
            conn.execute("PRAGMA user_version = 1")
            rb = canonical_json_bytes(receipt)
            eb = canonical_json_bytes(envelope)
            conn.execute(
                "INSERT INTO checkpoint_current VALUES (?, ?, ?, ?, ?)",
                ("tenant:A", receipt["checkpoint_sha256"], 1, rb, eb),
            )
            conn.execute(
                "INSERT INTO checkpoint_history VALUES (?, ?, ?, ?, ?)",
                ("tenant:A", 1, receipt["checkpoint_sha256"], rb, eb),
            )
            conn.commit()
            conn.close()
            with SQLiteCheckpointStore(path, namespace="tenant:A") as store:
                self.assertEqual(store.get_current()["head_sha256"], receipt["checkpoint_sha256"])
            conn = sqlite3.connect(path)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 3)
            owner = conn.execute(
                "SELECT namespace, checkpoint_sha256 FROM checkpoint_ownership"
            ).fetchone()
            conn.close()
            self.assertEqual(owner, ("tenant:A", receipt["checkpoint_sha256"]))


if __name__ == "__main__":
    unittest.main()
