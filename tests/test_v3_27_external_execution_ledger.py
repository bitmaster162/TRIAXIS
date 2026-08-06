from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest

from triaxis.crypto_trust import (
    PURPOSE_EXECUTION_RECEIPT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.external_execution_ledger import (
    ExecutionLedgerError,
    SQLiteExternalExecutionLedger,
    compute_effect_id,
    seal_execution_intent,
    validate_execution_intent,
    verify_execution_ledger_receipt,
    verify_external_effect_guard,
)
from triaxis.external_execution_ledger_http import ExecutionLedgerHTTPApplication
from triaxis.harness_durability_v3 import SQLiteDurableDispatchQueue, seal_queued_input
from triaxis.integrity import canonical_sha256, verify_sealed_mapping

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
E = "e" * 64
F = "f" * 64


def make_intent(queue_id: str = "queue:1", *, metadata: dict | None = None):
    return seal_execution_intent({
        "queue_id": queue_id,
        "queued_input_sha256": A,
        "action_envelope_sha256": B,
        "authorization_token_sha256": C,
        "canonical_target_sha256": D,
        "risk_class": "MUTATING",
        "created_at_tick": 1,
        "metadata": metadata or {"fixture": "v3.27"},
    })


def identities():
    keys = generate_ed25519_keypair()
    record = make_trust_key_record(
        key_id="key:ledger:1",
        signer_id="signer:ledger:1",
        trust_domain="triaxis:execution-ledger",
        public_key_b64=keys["public_key_b64"],
        purposes=[PURPOSE_EXECUTION_RECEIPT],
        valid_from=0,
        valid_until=10_000,
    )
    return keys, TrustKeyRegistry([record])


def open_ledger(path: str, keys: dict[str, str]):
    return SQLiteExternalExecutionLedger(
        path,
        ledger_id="ledger:primary",
        authority_id="authority:ledger:primary",
        key_id="key:ledger:1",
        signer_id="signer:ledger:1",
        trust_domain="triaxis:execution-ledger",
        private_key_b64=keys["private_key_b64"],
        receipt_ttl=100,
    )


class ExternalExecutionLedgerTests(unittest.TestCase):
    def test_effect_id_is_stable_and_excludes_attempt_and_dispatch(self):
        intent = make_intent()
        expected = compute_effect_id(
            queue_id="queue:1",
            queued_input_sha256=A,
            action_envelope_sha256=B,
            canonical_target_sha256=D,
        )
        self.assertEqual(intent["effect_id"], expected)
        self.assertNotIn("attempt", intent)
        self.assertNotIn("dispatch_id", intent)
        self.assertTrue(verify_sealed_mapping(intent, "intent_sha256"))

    def test_authorization_token_rotation_cannot_create_a_new_effect_id(self):
        first = make_intent()
        second = seal_execution_intent({
            "queue_id": "queue:1",
            "queued_input_sha256": A,
            "action_envelope_sha256": B,
            "authorization_token_sha256": E,
            "canonical_target_sha256": D,
            "risk_class": "MUTATING",
            "created_at_tick": 1,
            "metadata": {"fixture": "v3.27"},
        })
        self.assertEqual(first["effect_id"], second["effect_id"])
        self.assertNotEqual(first["intent_sha256"], second["intent_sha256"])

    def test_tampered_or_substituted_intent_fails_closed(self):
        intent = make_intent()
        tampered = copy.deepcopy(intent)
        tampered["canonical_target_sha256"] = E
        result = validate_execution_intent(tampered)
        self.assertEqual(result["status"], "BLOCK")
        self.assertTrue(any(row["code"] in {"digest_mismatch", "effect_id_mismatch"} for row in result["errors"]))
        with self.assertRaises(ValueError):
            seal_execution_intent({**intent, "effect_id": F, "intent_sha256": ""})

    def test_reserve_start_and_guard_are_signed_but_not_action_authority(self):
        keys, registry = identities()
        ledger = open_ledger(":memory:", keys)
        try:
            intent = make_intent()
            dispatch_id = canonical_sha256({"dispatch": 1})
            reserved = ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch_id, now_tick=2)
            self.assertEqual(reserved["status"], "PASS")
            started = ledger.start(intent["effect_id"], attempt_id="attempt:1", dispatch_id=dispatch_id, now_tick=3)
            guard = verify_external_effect_guard(
                intent,
                started["signed_receipt"],
                registry=registry,
                evaluation_tick=3,
                expected_ledger_id="ledger:primary",
                expected_authority_id="authority:ledger:primary",
                expected_signer_id="signer:ledger:1",
                expected_trust_domain="triaxis:execution-ledger",
                expected_attempt_id="attempt:1",
                expected_dispatch_id=dispatch_id,
            )
            self.assertEqual(guard["status"], "PASS")
            self.assertFalse(guard["authority_granted"])
            self.assertTrue(guard["required_separate_authorization"])
            wrong = verify_external_effect_guard(
                intent,
                started["signed_receipt"],
                registry=registry,
                evaluation_tick=3,
                expected_ledger_id="ledger:primary",
                expected_authority_id="authority:ledger:primary",
                expected_signer_id="signer:ledger:1",
                expected_trust_domain="triaxis:execution-ledger",
                expected_attempt_id="attempt:wrong",
                expected_dispatch_id=dispatch_id,
            )
            self.assertEqual(wrong["status"], "BLOCK")
        finally:
            ledger.close()

    def test_completed_effect_blocks_new_claim_identity(self):
        keys, _ = identities()
        ledger = open_ledger(":memory:", keys)
        try:
            intent = make_intent()
            first_dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=first_dispatch, now_tick=2)
            ledger.start(intent["effect_id"], attempt_id="attempt:1", dispatch_id=first_dispatch, now_tick=3)
            ledger.record_outcome(
                intent["effect_id"], attempt_id="attempt:1", dispatch_id=first_dispatch,
                outcome="COMPLETED", evidence_sha256=E, now_tick=4,
            )
            second_dispatch = canonical_sha256({"dispatch": 2, "claim": "new-after-local-rollback"})
            blocked = ledger.reserve(intent, attempt_id="attempt:2", dispatch_id=second_dispatch, now_tick=5)
            self.assertEqual(blocked["status"], "BLOCK")
            self.assertEqual(blocked["current_state"], "COMPLETED")
            self.assertEqual(ledger.get_effect(intent["effect_id"])["generation"], 1)
        finally:
            ledger.close()

    def test_unknown_blocks_until_authoritative_no_effect_reconciliation(self):
        keys, _ = identities()
        ledger = open_ledger(":memory:", keys)
        try:
            intent = make_intent()
            first_dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=first_dispatch, now_tick=2)
            ledger.start(intent["effect_id"], attempt_id="attempt:1", dispatch_id=first_dispatch, now_tick=3)
            ledger.record_outcome(
                intent["effect_id"], attempt_id="attempt:1", dispatch_id=first_dispatch,
                outcome="UNKNOWN", evidence_sha256=E, now_tick=4,
            )
            blocked = ledger.reserve(
                intent, attempt_id="attempt:2", dispatch_id=canonical_sha256({"dispatch": 2}), now_tick=5,
            )
            self.assertEqual(blocked["current_state"], "UNKNOWN")
            reconciled = ledger.reconcile_unknown(
                intent["effect_id"], attempt_id="attempt:1", dispatch_id=first_dispatch,
                outcome="NO_EFFECT", evidence_sha256=F, now_tick=6,
            )
            self.assertEqual(reconciled["effect"]["state"], "NO_EFFECT")
            second_dispatch = canonical_sha256({"dispatch": 3})
            second = ledger.reserve(intent, attempt_id="attempt:3", dispatch_id=second_dispatch, now_tick=7)
            self.assertEqual(second["status"], "PASS")
            self.assertEqual(second["effect"]["generation"], 2)
        finally:
            ledger.close()

    def test_exact_transport_retries_are_idempotent_and_conflicts_block(self):
        keys, _ = identities()
        ledger = open_ledger(":memory:", keys)
        try:
            intent = make_intent()
            dispatch_id = canonical_sha256({"dispatch": 1})
            one = ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch_id, now_tick=2)
            two = ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch_id, now_tick=9)
            self.assertFalse(one["idempotent_replay"])
            self.assertTrue(two["idempotent_replay"])
            self.assertEqual(one["signed_receipt"], two["signed_receipt"])
            with self.assertRaises(ExecutionLedgerError) as ctx:
                ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=canonical_sha256({"dispatch": 2}), now_tick=10)
            self.assertEqual(ctx.exception.code, "attempt_id_replay_conflict")
        finally:
            ledger.close()

    def test_same_effect_id_with_changed_nonsemantic_metadata_is_fail_closed(self):
        keys, _ = identities()
        ledger = open_ledger(":memory:", keys)
        try:
            first = make_intent(metadata={"source": "one"})
            second = make_intent(metadata={"source": "two"})
            self.assertEqual(first["effect_id"], second["effect_id"])
            self.assertNotEqual(first["intent_sha256"], second["intent_sha256"])
            first_dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(first, attempt_id="attempt:1", dispatch_id=first_dispatch, now_tick=2)
            blocked = ledger.reserve(second, attempt_id="attempt:2", dispatch_id=canonical_sha256({"dispatch": 2}), now_tick=3)
            self.assertEqual(blocked["status"], "BLOCK")
            self.assertEqual(blocked["current_state"], "RESERVED")
            self.assertFalse(blocked["binding_match"])
            ledger.release_before_effect(
                first["effect_id"], attempt_id="attempt:1", dispatch_id=first_dispatch,
                evidence_sha256=E, now_tick=4,
            )
            with self.assertRaises(ExecutionLedgerError) as ctx:
                ledger.reserve(second, attempt_id="attempt:3", dispatch_id=canonical_sha256({"dispatch": 3}), now_tick=5)
            self.assertEqual(ctx.exception.code, "effect_binding_conflict")
        finally:
            ledger.close()

    def test_restart_preserves_monotonic_chain_and_signed_head(self):
        keys, registry = identities()
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "ledger.sqlite")
            intent = make_intent()
            dispatch_id = canonical_sha256({"dispatch": 1})
            ledger = open_ledger(path, keys)
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch_id, now_tick=2)
            ledger.start(intent["effect_id"], attempt_id="attempt:1", dispatch_id=dispatch_id, now_tick=3)
            before = ledger.head(now_tick=4)
            ledger.close()

            reopened = open_ledger(path, keys)
            events = reopened.events(intent["effect_id"])
            self.assertEqual([row["inner_contract"]["sequence"] for row in events], [1, 2])
            self.assertEqual(events[1]["inner_contract"]["previous_event_sha256"], events[0]["inner_contract"]["event_sha256"])
            after = reopened.head(now_tick=5)
            self.assertEqual(before["inner_contract"]["sequence"], after["inner_contract"]["sequence"])
            verified = verify_execution_ledger_receipt(
                events[-1], registry=registry, evaluation_tick=5,
                expected_ledger_id="ledger:primary", expected_authority_id="authority:ledger:primary",
                expected_signer_id="signer:ledger:1", expected_trust_domain="triaxis:execution-ledger",
                expected_effect_id=intent["effect_id"], allowed_to_states=("IN_FLIGHT",),
            )
            self.assertEqual(verified["status"], "PASS")
            reopened.close()

    def test_two_connections_cannot_reserve_same_effect_concurrently(self):
        keys, _ = identities()
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "ledger.sqlite")
            one = open_ledger(path, keys)
            two = open_ledger(path, keys)
            try:
                intent = make_intent()
                first = one.reserve(intent, attempt_id="attempt:1", dispatch_id=canonical_sha256({"dispatch": 1}), now_tick=2)
                second = two.reserve(intent, attempt_id="attempt:2", dispatch_id=canonical_sha256({"dispatch": 2}), now_tick=3)
                self.assertEqual(first["status"], "PASS")
                self.assertEqual(second["status"], "BLOCK")
                self.assertEqual(second["current_state"], "RESERVED")
            finally:
                one.close()
                two.close()

    def test_http_boundary_authenticates_mutations_and_minimizes_health(self):
        keys, _ = identities()
        ledger = open_ledger(":memory:", keys)
        try:
            token = "transport-secret"
            app = ExecutionLedgerHTTPApplication(
                ledger,
                clock=lambda: 2,
                client_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            )
            health_status, health = app.handle("GET", "/healthz")
            self.assertEqual(health_status, 200)
            self.assertNotIn("private_key", str(health))
            denied_status, denied = app.handle("POST", "/v1/effects/reserve", {"intent": make_intent()})
            self.assertEqual(denied_status, 403)
            denied_read_status, _ = app.handle("GET", f"/v1/effects/{make_intent()['effect_id']}")
            self.assertEqual(denied_read_status, 403)
            dispatch_id = canonical_sha256({"dispatch": 1})
            status, result = app.handle(
                "POST", "/v1/effects/reserve",
                {"intent": make_intent(), "attempt_id": "attempt:1", "dispatch_id": dispatch_id},
                {"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(result["status"], "PASS")
        finally:
            ledger.close()

    def test_queue_database_rollback_is_blocked_by_fresh_external_ledger(self):
        keys, registry = identities()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            queue_path = root / "queue.sqlite"
            queue_snapshot = root / "queue.pre_dispatch.sqlite"
            ledger_path = root / "ledger.sqlite"

            queued = seal_queued_input({
                "queue_id": "queue:rollback:1",
                "thread_id": "thread:rollback",
                "content_ref": "content:rollback:1",
                "content_sha256": A,
                "risk_class": "MUTATING",
                "created_at_tick": 1,
                "attachments": [],
                "metadata": {"fixture": "v3.27_queue_rollback"},
            })
            queue = SQLiteDurableDispatchQueue(str(queue_path))
            queue.enqueue(queued)
            queue.close()
            shutil.copy2(queue_path, queue_snapshot)

            ledger = open_ledger(str(ledger_path), keys)
            queue = SQLiteDurableDispatchQueue(str(queue_path))
            first_claim = queue.claim_next(
                thread_id="thread:rollback", thread_idle=True, claim_id="claim:first", now_tick=2
            )["claim"]
            intent = seal_execution_intent({
                "queue_id": queued["queue_id"],
                "queued_input_sha256": queued["queued_input_sha256"],
                "action_envelope_sha256": B,
                "authorization_token_sha256": C,
                "canonical_target_sha256": D,
                "risk_class": "MUTATING",
                "created_at_tick": 2,
                "metadata": {"fixture": "v3.27_queue_rollback"},
            })
            ledger.reserve(intent, attempt_id="attempt:first", dispatch_id=first_claim["dispatch_id"], now_tick=2)
            started = ledger.start(
                intent["effect_id"], attempt_id="attempt:first", dispatch_id=first_claim["dispatch_id"], now_tick=3
            )
            guard = verify_external_effect_guard(
                intent, started["signed_receipt"], registry=registry, evaluation_tick=3,
                expected_ledger_id="ledger:primary", expected_authority_id="authority:ledger:primary",
                expected_signer_id="signer:ledger:1", expected_trust_domain="triaxis:execution-ledger",
                expected_attempt_id="attempt:first", expected_dispatch_id=first_claim["dispatch_id"],
            )
            self.assertEqual(guard["status"], "PASS")
            queue.begin_dispatch(
                queued["queue_id"], claim_id="claim:first", dispatch_id=first_claim["dispatch_id"], now_tick=3
            )
            completed = ledger.record_outcome(
                intent["effect_id"], attempt_id="attempt:first", dispatch_id=first_claim["dispatch_id"],
                outcome="COMPLETED", evidence_sha256=E, now_tick=4,
            )
            queue.acknowledge_persisted(
                queued["queue_id"], claim_id="claim:first", dispatch_id=first_claim["dispatch_id"],
                persisted_receipt_sha256=completed["signed_receipt"]["inner_contract"]["event_sha256"], now_tick=4,
            )
            queue.close()

            for suffix in ("-wal", "-shm"):
                Path(str(queue_path) + suffix).unlink(missing_ok=True)
            shutil.copy2(queue_snapshot, queue_path)

            restored = SQLiteDurableDispatchQueue(str(queue_path))
            second_claim = restored.claim_next(
                thread_id="thread:rollback", thread_idle=True, claim_id="claim:revived", now_tick=5
            )["claim"]
            self.assertNotEqual(first_claim["dispatch_id"], second_claim["dispatch_id"])
            blocked = ledger.reserve(
                intent, attempt_id="attempt:revived", dispatch_id=second_claim["dispatch_id"], now_tick=5
            )
            self.assertEqual(blocked["status"], "BLOCK")
            self.assertEqual(blocked["current_state"], "COMPLETED")
            restored.close()
            ledger.close()

    def test_ledger_id_cannot_be_rebound_to_existing_database(self):
        keys, _ = identities()
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "ledger.sqlite")
            first = open_ledger(path, keys)
            first.close()
            with self.assertRaises(ExecutionLedgerError) as ctx:
                SQLiteExternalExecutionLedger(
                    path,
                    ledger_id="ledger:substituted",
                    authority_id="authority:ledger:primary",
                    key_id="key:ledger:1",
                    signer_id="signer:ledger:1",
                    trust_domain="triaxis:execution-ledger",
                    private_key_b64=keys["private_key_b64"],
                )
            self.assertEqual(ctx.exception.code, "ledger_id_conflict")


if __name__ == "__main__":
    unittest.main()
