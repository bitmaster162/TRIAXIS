from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from triaxis import (
    AuthorityAnalysisSession,
    CheckpointStoreError,
    SQLiteCheckpointStore,
    checkpoint_scope_schema_document,
)
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_checkpoint_scope_binding_trigger_v38 import (
    run_trigger,
    seal_scope,
)
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope


class V244CheckpointScopeTests(unittest.TestCase):
    NAMESPACE = "tenant:scope-unit"

    @staticmethod
    def _root() -> dict:
        return build_snapshot_authority_root(valid_until=200)

    @classmethod
    def _chain(cls, ticks: tuple[int, ...] = (5, 6)) -> list[tuple[dict, dict, dict]]:
        guard = ProvenanceTrustStateGuard(authority_roots=[cls._root()])
        session = AuthorityAnalysisSession(trust_guard=guard)
        parent = None
        result: list[tuple[dict, dict, dict]] = []
        for sequence, tick in enumerate(ticks, 1):
            bundle = _bind(
                build_valid_analysis_bundle_v5(
                    run_id=f"v244-{sequence}-{tick}",
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
            receipt = guard.checkpoint.as_dict()
            scope = seal_scope(
                namespace=cls.NAMESPACE,
                receipt=receipt,
                envelope=envelope,
                issued_at=tick,
                valid_until=200,
            )
            result.append((receipt, envelope, scope))
            parent = envelope["envelope_sha256"]
        return result

    def test_scope_schema_artifact_matches_runtime_contract(self) -> None:
        path = Path("validation/schemas/triaxis_checkpoint_scope_envelope_v1.schema.json")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), checkpoint_scope_schema_document())

    def test_frozen_v38_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_scoped_chain_persists_and_restores(self) -> None:
        items = self._chain()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            previous = None
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                for receipt, envelope, scope in items:
                    previous = store.commit_scoped(
                        checkpoint_receipt=receipt,
                        trust_envelope=envelope,
                        checkpoint_scope_envelope=scope,
                        authority_roots=[self._root()],
                        expected_previous_head=previous,
                        trusted_evaluation_tick=receipt["evaluation_tick"],
                    )
                restored = store.load_guard_scoped(
                    authority_roots=[self._root()],
                    expected_checkpoint_sha256=items[-1][0]["checkpoint_sha256"],
                    trusted_evaluation_tick=items[-1][0]["evaluation_tick"],
                )
                self.assertEqual(restored.checkpoint.as_dict(), items[-1][0])
                binding = store.get_scope_binding(
                    checkpoint_sha256=items[-1][0]["checkpoint_sha256"]
                )
                self.assertEqual(binding["scope"], items[-1][2])

    def test_legacy_api_cannot_downgrade_scoped_lineage(self) -> None:
        receipt, envelope, scope = self._chain((5,))[0]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                store.commit_scoped(
                    checkpoint_receipt=receipt,
                    trust_envelope=envelope,
                    checkpoint_scope_envelope=scope,
                    authority_roots=[self._root()],
                    expected_previous_head=None,
                    trusted_evaluation_tick=5,
                )
                with self.assertRaises(CheckpointStoreError) as commit_error:
                    store.commit(
                        checkpoint_receipt=receipt,
                        trust_envelope=envelope,
                        authority_roots=[self._root()],
                        expected_previous_head=None,
                    )
                self.assertEqual(
                    commit_error.exception.code,
                    "checkpoint_scope_envelope_required",
                )
                with self.assertRaises(CheckpointStoreError) as restore_error:
                    store.load_guard(
                        authority_roots=[self._root()],
                        expected_checkpoint_sha256=receipt["checkpoint_sha256"],
                    )
                self.assertEqual(
                    restore_error.exception.code,
                    "checkpoint_scope_envelope_required",
                )

    def test_missing_scope_row_blocks_scoped_restore(self) -> None:
        receipt, envelope, scope = self._chain((5,))[0]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                store.commit_scoped(
                    checkpoint_receipt=receipt,
                    trust_envelope=envelope,
                    checkpoint_scope_envelope=scope,
                    authority_roots=[self._root()],
                    expected_previous_head=None,
                    trusted_evaluation_tick=5,
                )
            conn = sqlite3.connect(path)
            conn.execute("DELETE FROM checkpoint_scope")
            conn.commit()
            conn.close()
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                with self.assertRaises(CheckpointStoreError) as caught:
                    store.load_guard_scoped(
                        authority_roots=[self._root()],
                        expected_checkpoint_sha256=receipt["checkpoint_sha256"],
                        trusted_evaluation_tick=5,
                    )
            self.assertEqual(caught.exception.code, "checkpoint_scope_history_incomplete")

    def test_v2_database_migrates_to_schema_v3_without_claiming_scope(self) -> None:
        receipt, envelope, _ = self._chain((5,))[0]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                store.commit(
                    checkpoint_receipt=receipt,
                    trust_envelope=envelope,
                    authority_roots=[self._root()],
                    expected_previous_head=None,
                )
            conn = sqlite3.connect(path)
            conn.execute("DROP TABLE checkpoint_scope")
            conn.execute("PRAGMA user_version = 2")
            conn.commit()
            conn.close()
            with SQLiteCheckpointStore(path, namespace=self.NAMESPACE) as store:
                self.assertEqual(store.get_current()["head_sha256"], receipt["checkpoint_sha256"])
                self.assertIsNone(
                    store.get_scope_binding(checkpoint_sha256=receipt["checkpoint_sha256"])
                )
            conn = sqlite3.connect(path)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertIsNotNone(
                conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='checkpoint_scope'"
                ).fetchone()
            )
            conn.close()


if __name__ == "__main__":
    unittest.main()
