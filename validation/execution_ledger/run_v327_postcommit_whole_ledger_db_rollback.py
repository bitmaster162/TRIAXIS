from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile

from triaxis.crypto_trust import generate_ed25519_keypair
from triaxis.external_execution_ledger import SQLiteExternalExecutionLedger, seal_execution_intent
from triaxis.harness_durability_v3 import SQLiteDurableDispatchQueue, seal_queued_input
from triaxis.integrity import canonical_sha256

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
E = "e" * 64


def queued_item() -> dict:
    return seal_queued_input({
        "queue_id": "queue:ledger-rollback:1",
        "thread_id": "thread:ledger-rollback",
        "content_ref": "content:ledger-rollback:1",
        "content_sha256": A,
        "risk_class": "MUTATING",
        "created_at_tick": 1,
        "attachments": [],
        "metadata": {"fixture": "v3.27_whole_ledger_rollback"},
    })


def execution_intent(item: dict) -> dict:
    return seal_execution_intent({
        "queue_id": item["queue_id"],
        "queued_input_sha256": item["queued_input_sha256"],
        "action_envelope_sha256": B,
        "authorization_token_sha256": C,
        "canonical_target_sha256": D,
        "risk_class": "MUTATING",
        "created_at_tick": 2,
        "metadata": {"fixture": "v3.27_whole_ledger_rollback"},
    })


def open_ledger(path: Path, private_key_b64: str) -> SQLiteExternalExecutionLedger:
    return SQLiteExternalExecutionLedger(
        str(path),
        ledger_id="ledger:rollback-boundary",
        authority_id="authority:ledger:rollback-boundary",
        key_id="key:ledger:rollback-boundary",
        signer_id="signer:ledger:rollback-boundary",
        trust_domain="triaxis:execution-ledger",
        private_key_b64=private_key_b64,
        receipt_ttl=100,
    )


def restore_file(snapshot: Path, target: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(target) + suffix).unlink(missing_ok=True)
    shutil.copy2(snapshot, target)


def run() -> dict:
    rows = []
    keys = generate_ed25519_keypair()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        queue_db = root / "queue.sqlite"
        queue_snapshot = root / "queue.pre_dispatch.sqlite"
        ledger_db = root / "ledger.sqlite"
        ledger_snapshot = root / "ledger.pre_dispatch.sqlite"

        item = queued_item()
        intent = execution_intent(item)

        queue = SQLiteDurableDispatchQueue(str(queue_db))
        queue.enqueue(item)
        queue.close()
        shutil.copy2(queue_db, queue_snapshot)

        ledger = open_ledger(ledger_db, keys["private_key_b64"])
        ledger.close()
        shutil.copy2(ledger_db, ledger_snapshot)

        queue = SQLiteDurableDispatchQueue(str(queue_db))
        ledger = open_ledger(ledger_db, keys["private_key_b64"])
        claim = queue.claim_next(
            thread_id=item["thread_id"], thread_idle=True, claim_id="claim:completed", now_tick=2
        )["claim"]
        ledger.reserve(intent, attempt_id="attempt:completed", dispatch_id=claim["dispatch_id"], now_tick=2)
        ledger.start(intent["effect_id"], attempt_id="attempt:completed", dispatch_id=claim["dispatch_id"], now_tick=3)
        queue.begin_dispatch(item["queue_id"], claim_id="claim:completed", dispatch_id=claim["dispatch_id"], now_tick=3)
        completed = ledger.record_outcome(
            intent["effect_id"], attempt_id="attempt:completed", dispatch_id=claim["dispatch_id"],
            outcome="COMPLETED", evidence_sha256=E, now_tick=4,
        )
        queue.acknowledge_persisted(
            item["queue_id"], claim_id="claim:completed", dispatch_id=claim["dispatch_id"],
            persisted_receipt_sha256=completed["signed_receipt"]["inner_contract"]["event_sha256"], now_tick=4,
        )
        current_head = ledger.head(now_tick=5)["inner_contract"]
        blocked = ledger.reserve(
            intent, attempt_id="attempt:control", dispatch_id=canonical_sha256({"dispatch": "control"}), now_tick=5
        )
        rows.append({
            "case_id": "ELRB01_CURRENT_LEDGER_BLOCKS_DUPLICATE_EFFECT",
            "observed": blocked["status"],
            "current_state": blocked.get("current_state"),
            "ledger_sequence": current_head["sequence"],
            "expected": "BLOCK/COMPLETED",
            "status": "PASS" if blocked["status"] == "BLOCK" and blocked.get("current_state") == "COMPLETED" else "FAIL",
        })
        queue.close()
        ledger.close()

        # Restore both local queue and execution ledger to their pre-dispatch files.
        restore_file(queue_snapshot, queue_db)
        restore_file(ledger_snapshot, ledger_db)

        restored_queue = SQLiteDurableDispatchQueue(str(queue_db))
        restored_ledger = open_ledger(ledger_db, keys["private_key_b64"])
        revived_claim = restored_queue.claim_next(
            thread_id=item["thread_id"], thread_idle=True, claim_id="claim:revived", now_tick=6
        )["claim"]
        restored_head_before = restored_ledger.head(now_tick=6)["inner_contract"]
        revived = restored_ledger.reserve(
            intent, attempt_id="attempt:revived", dispatch_id=revived_claim["dispatch_id"], now_tick=6
        )
        restored_head_after = restored_ledger.head(now_tick=7)["inner_contract"]
        rows.append({
            "case_id": "ELRB02_WHOLE_LEDGER_ROLLBACK_REVIVES_COMPLETED_EFFECT",
            "observed": revived["status"],
            "same_effect_id": revived.get("effect", {}).get("effect_id") == intent["effect_id"],
            "new_dispatch_id": revived_claim["dispatch_id"] != claim["dispatch_id"],
            "pre_rollback_sequence": current_head["sequence"],
            "restored_sequence_before_reserve": restored_head_before["sequence"],
            "restored_sequence_after_reserve": restored_head_after["sequence"],
            "expected_secure_result": "BLOCK_OR_EXTERNAL_HEAD_REJECTION",
            "status": "FAIL_EXPECTED" if revived["status"] == "PASS" else "PASS",
            "duplicate_effect_risk": revived["status"] == "PASS",
        })
        restored_queue.close()
        restored_ledger.close()

    return {
        "protocol_id": "TRIAXIS_v3.27_POSTCOMMIT_WHOLE_EXECUTION_LEDGER_DB_ROLLBACK_BOUNDARY",
        "exact_subject_tag": "TRIAXIS-v3.27-RC1-EXTERNAL-EXECUTION-LEDGER",
        "exact_subject_commit": "06c2e2930a4ef8d922c170df28e4b2b0e0e85050",
        "status": "BOUNDARY_CONFIRMED" if rows[0]["status"] == "PASS" and rows[1]["status"] == "FAIL_EXPECTED" else "UNEXPECTED",
        "claim": "A separately persisted execution ledger blocks rollback of the local queue, but cannot prove its own freshness after whole-ledger rollback.",
        "required_next_control": [
            "independently persisted monotonic execution-ledger head with rollback-aware verifier or quorum",
            "provider-side idempotency keyed by stable effect_id",
            "or authoritative provider-side reconciliation before any retry",
        ],
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    result = run()
    path = Path("evidence/TRIAXIS_v3.27_POSTCOMMIT_WHOLE_EXECUTION_LEDGER_DB_ROLLBACK_BOUNDARY.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
