from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile

from triaxis.harness_durability_v3 import SQLiteDurableDispatchQueue, seal_queued_input
from triaxis.integrity import canonical_sha256

D = "d" * 64
E = "e" * 64
F = "f" * 64


def item() -> dict:
    return seal_queued_input({
        "queue_id": "queue:rollback:1",
        "thread_id": "thread:rollback",
        "content_ref": "content:rollback:1",
        "content_sha256": D,
        "risk_class": "MUTATING",
        "created_at_tick": 1,
        "attachments": [],
        "metadata": {"fixture": "whole_queue_db_rollback"},
    })


def run() -> dict:
    rows = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        db = root / "queue.sqlite"
        snapshot = root / "queue.pre_dispatch.sqlite"

        store = SQLiteDurableDispatchQueue(str(db))
        store.enqueue(item())
        store.close()
        shutil.copy2(db, snapshot)

        store = SQLiteDurableDispatchQueue(str(db))
        claim = store.claim_next(thread_id="thread:rollback", thread_idle=True, claim_id="claim:delivered", now_tick=2)["claim"]
        store.begin_dispatch("queue:rollback:1", claim_id="claim:delivered", dispatch_id=claim["dispatch_id"], now_tick=3)
        store.acknowledge_persisted(
            "queue:rollback:1", claim_id="claim:delivered", dispatch_id=claim["dispatch_id"],
            persisted_receipt_sha256=E, now_tick=4,
        )
        no_restore = store.claim_next(thread_id="thread:rollback", thread_idle=True, claim_id="claim:control", now_tick=5)
        rows.append({
            "case_id": "QB01_DELIVERED_STATE_PREVENTS_REDISPATCH_WITHOUT_ROLLBACK",
            "observed": no_restore["status"],
            "expected": "EMPTY",
            "status": "PASS" if no_restore["status"] == "EMPTY" else "FAIL",
        })
        store.close()

        # Restore the entire queue database to the snapshot taken before dispatch.
        for suffix in ("-wal", "-shm"):
            Path(str(db) + suffix).unlink(missing_ok=True)
        shutil.copy2(snapshot, db)

        restored = SQLiteDurableDispatchQueue(str(db))
        revived = restored.claim_next(thread_id="thread:rollback", thread_idle=True, claim_id="claim:revived", now_tick=6)
        rows.append({
            "case_id": "QB02_WHOLE_DB_ROLLBACK_REVIVES_DELIVERED_MUTATING_INPUT",
            "observed": revived["status"],
            "expected_secure_result": "BLOCK_OR_EXTERNAL_RECONCILIATION",
            "status": "FAIL_EXPECTED" if revived["status"] == "PASS" else "PASS",
            "duplicate_effect_risk": revived["status"] == "PASS",
        })
        restored.close()

    return {
        "protocol_id": "TRIAXIS_v3.26_POSTCOMMIT_WHOLE_QUEUE_DB_ROLLBACK_BOUNDARY",
        "exact_subject_tag": "TRIAXIS-v3.26-RC1-DURABLE-DISPATCH",
        "exact_subject_commit": "f147b480e6e292fc418ad412e29e06131f745edf",
        "status": "BOUNDARY_CONFIRMED" if rows[0]["status"] == "PASS" and rows[1]["status"] == "FAIL_EXPECTED" else "UNEXPECTED",
        "claim": "A local queue database cannot prove its own freshness after whole-file rollback.",
        "required_external_control": [
            "external monotonic dispatch head",
            "separately administered execution ledger",
            "or authoritative external idempotency and reconciliation",
        ],
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    result = run()
    path = Path("evidence/TRIAXIS_v3.26_POSTCOMMIT_WHOLE_QUEUE_DB_ROLLBACK_BOUNDARY.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
