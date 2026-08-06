from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from triaxis.harness_durability_v3 import (
    DispatchQueueError,
    SQLiteDurableDispatchQueue,
    seal_provider_request_receipt,
    seal_queued_input,
)
from triaxis.integrity import verify_sealed_mapping

D = "d" * 64
E = "e" * 64
F = "f" * 64


def queued(queue_id: str, *, thread_id="thread:1", risk="MUTATING", created=1, attachment=True):
    return seal_queued_input({
        "queue_id": queue_id,
        "thread_id": thread_id,
        "content_ref": f"content:{queue_id}",
        "content_sha256": D if queue_id.endswith("1") else E,
        "risk_class": risk,
        "created_at_tick": created,
        "attachments": ([{
            "artifact_id": f"file:{queue_id}", "storage_ref": f"snapshot:{queue_id}",
            "media_type": "text/plain", "content_sha256": F, "size_bytes": 12,
        }] if attachment else []),
        "metadata": {"source": "user"},
    })


class DurableDispatchTests(unittest.TestCase):
    def test_queue_persists_snapshots_and_fifo_across_reopen(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "queue.sqlite")
            store = SQLiteDurableDispatchQueue(path)
            store.enqueue(queued("q:2", created=2), rank=10)
            store.enqueue(queued("q:1", created=1), rank=0)
            store.close()
            reopened = SQLiteDurableDispatchQueue(path)
            items = reopened.list_thread("thread:1", states=["QUEUED"])
            self.assertEqual([x["queue_id"] for x in items], ["q:1", "q:2"])
            self.assertEqual(items[0]["attachments"][0]["content_sha256"], F)
            reopened.close()

    def test_dispatch_only_when_idle_and_ack_after_persistence(self):
        store = SQLiteDurableDispatchQueue()
        try:
            store.enqueue(queued("q:1"))
            hold = store.claim_next(thread_id="thread:1", thread_idle=False, claim_id="claim:1", now_tick=2)
            self.assertEqual(hold["status"], "HOLD")
            claimed = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=2)
            self.assertEqual(claimed["status"], "PASS")
            claim = claimed["claim"]
            dispatching = store.begin_dispatch("q:1", claim_id="claim:1", dispatch_id=claim["dispatch_id"], now_tick=3)
            self.assertEqual(dispatching["state"], "DISPATCHING")
            delivered = store.acknowledge_persisted("q:1", claim_id="claim:1", dispatch_id=claim["dispatch_id"], persisted_receipt_sha256=E, now_tick=4)
            self.assertEqual(delivered["state"], "DELIVERED")
            self.assertEqual(delivered["delivered_receipt_sha256"], E)
        finally:
            store.close()

    def test_failure_before_dispatch_requeues_but_post_dispatch_timeout_becomes_unknown(self):
        store = SQLiteDurableDispatchQueue()
        try:
            store.enqueue(queued("q:1"))
            first = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=2)["claim"]
            requeued = store.fail_before_dispatch("q:1", claim_id="claim:1", dispatch_id=first["dispatch_id"], now_tick=3, failure_sha256=F)
            self.assertEqual(requeued["state"], "QUEUED")
            second = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:2", now_tick=4)["claim"]
            store.begin_dispatch("q:1", claim_id="claim:2", dispatch_id=second["dispatch_id"], now_tick=5)
            unknown = store.mark_unknown("q:1", claim_id="claim:2", dispatch_id=second["dispatch_id"], now_tick=6, failure_sha256=F)
            self.assertEqual(unknown["state"], "UNKNOWN")
            self.assertEqual(store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:3", now_tick=7)["status"], "EMPTY")
        finally:
            store.close()

    def test_unknown_requires_exact_reconciliation(self):
        store = SQLiteDurableDispatchQueue()
        try:
            store.enqueue(queued("q:1"))
            claim = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=2)["claim"]
            store.begin_dispatch("q:1", claim_id="claim:1", dispatch_id=claim["dispatch_id"], now_tick=3)
            store.mark_unknown("q:1", claim_id="claim:1", dispatch_id=claim["dispatch_id"], now_tick=4, failure_sha256=F)
            with self.assertRaises(DispatchQueueError):
                store.reconcile_unknown("q:1", dispatch_id="wrong", outcome="NO_EFFECT", evidence_sha256=E, now_tick=5)
            requeued = store.reconcile_unknown("q:1", dispatch_id=claim["dispatch_id"], outcome="NO_EFFECT", evidence_sha256=E, now_tick=5)
            self.assertEqual(requeued["state"], "QUEUED")
            self.assertEqual(requeued["reconciliation_sha256"], E)
        finally:
            store.close()

    def test_completed_reconciliation_does_not_redeliver(self):
        store = SQLiteDurableDispatchQueue()
        try:
            store.enqueue(queued("q:1"))
            claim = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=2)["claim"]
            store.begin_dispatch("q:1", claim_id="claim:1", dispatch_id=claim["dispatch_id"], now_tick=3)
            store.mark_unknown("q:1", claim_id="claim:1", dispatch_id=claim["dispatch_id"], now_tick=4, failure_sha256=F)
            delivered = store.reconcile_unknown("q:1", dispatch_id=claim["dispatch_id"], outcome="COMPLETED", evidence_sha256=E, now_tick=5)
            self.assertEqual(delivered["state"], "DELIVERED")
            self.assertEqual(store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:2", now_tick=6)["status"], "EMPTY")
        finally:
            store.close()

    def test_expired_claim_requeues_but_expired_dispatch_becomes_unknown(self):
        store = SQLiteDurableDispatchQueue()
        try:
            store.enqueue(queued("q:1"))
            store.enqueue(queued("q:2", created=2))
            claim1 = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=2, lease_ticks=2)["claim"]
            counts = store.recover_expired(now_tick=4)
            self.assertEqual(counts["requeued_claimed"], 1)
            # Reorder q:2 before the requeued q:1 and begin a dispatch that will expire.
            q2 = store.get("q:2")
            store.reorder("q:2", new_rank=-1, expected_version=q2["version"], tick=5)
            claim2 = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:2", now_tick=5, lease_ticks=2)["claim"]
            self.assertEqual(store.get(claim2["queue_id"])["queue_id"], "q:2")
            store.begin_dispatch("q:2", claim_id="claim:2", dispatch_id=claim2["dispatch_id"], now_tick=5)
            counts2 = store.recover_expired(now_tick=7)
            self.assertEqual(counts2["unknown_dispatching"], 1)
            self.assertEqual(store.get("q:2")["state"], "UNKNOWN")
        finally:
            store.close()

    def test_claim_and_rank_mutations_are_cas_and_replay_safe(self):
        store = SQLiteDurableDispatchQueue()
        try:
            store.enqueue(queued("q:1"))
            item = store.get("q:1")
            store.reorder("q:1", new_rank=4, expected_version=item["version"], tick=2)
            with self.assertRaises(DispatchQueueError):
                store.reorder("q:1", new_rank=5, expected_version=item["version"], tick=3)
            first = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=4)
            self.assertEqual(first["status"], "PASS")
            with self.assertRaises(DispatchQueueError):
                store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=4)
        finally:
            store.close()

    def test_event_log_is_atomic_and_digest_sealed(self):
        store = SQLiteDurableDispatchQueue()
        try:
            store.enqueue(queued("q:1"))
            claim = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=2)["claim"]
            store.begin_dispatch("q:1", claim_id="claim:1", dispatch_id=claim["dispatch_id"], now_tick=3)
            rows = store.events("q:1")
            self.assertEqual([x["to_state"] for x in rows], ["QUEUED", "CLAIMED", "DISPATCHING"])
            self.assertTrue(all(verify_sealed_mapping(row, "transition_sha256") for row in rows))
        finally:
            store.close()

    def test_provider_request_id_is_provenance_not_authority(self):
        receipt = seal_provider_request_receipt({
            "provider_id": "openai", "model_id": "model:x", "provider_request_id": "req_123",
            "run_id": "run:1", "trace_id": "trace:1", "internal_request_sha256": D,
            "provider_request_sha256": E, "provider_response_sha256": F,
            "started_at_tick": 1, "ended_at_tick": 2, "status": "PASS",
        })
        self.assertTrue(verify_sealed_mapping(receipt, "provider_receipt_sha256"))
        self.assertNotIn("authority", receipt)


if __name__ == "__main__":
    unittest.main()
