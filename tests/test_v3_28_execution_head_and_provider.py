from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from triaxis.crypto_trust import (
    PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
    PURPOSE_EXECUTION_RECEIPT,
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.execution_ledger_head_authority import (
    EXECUTION_LEDGER_HEAD_RESPONSE_CONTRACT_ID,
    ExecutionLedgerHeadError,
    SQLiteExecutionLedgerHeadAuthority,
    reserve_with_external_head_guard,
    verify_external_execution_ledger_head,
    verify_external_effect_guard_with_monotonic_head,
)
from triaxis.execution_ledger_head_http import ExecutionLedgerHeadHTTPApplication
from triaxis.external_execution_ledger import (
    EXECUTION_LEDGER_HEAD_CONTRACT_ID,
    SQLiteExternalExecutionLedger,
    seal_execution_intent,
)
from triaxis.idempotent_effect_provider import (
    PROVIDER_EFFECT_STATUS_CONTRACT_ID,
    ProviderEffectError,
    SQLiteIdempotentEffectProvider,
    verify_provider_effect_status,
)
from triaxis.idempotent_effect_provider_http import IdempotentEffectProviderHTTPApplication
from triaxis.integrity import canonical_sha256, seal_mapping
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
E = "e" * 64
F = "f" * 64

LEDGER_ID = "ledger:primary"
LEDGER_AUTHORITY_ID = "authority:ledger:primary"
LEDGER_SIGNER_ID = "signer:ledger:1"
LEDGER_DOMAIN = "triaxis:execution-ledger"
HEAD_AUTHORITY_ID = "authority:execution-head:1"
HEAD_SIGNER_ID = "signer:execution-head:1"
HEAD_DOMAIN = "triaxis:execution-ledger-head"
PROVIDER_ID = "provider:reference:1"
PROVIDER_SERVICE_ID = "service:effects:1"
PROVIDER_SIGNER_ID = "signer:provider:1"
PROVIDER_DOMAIN = "triaxis:provider-effect"


def make_intent(queue_id: str = "queue:v328:1", *, payload: str = B) -> dict:
    return seal_execution_intent(
        {
            "queue_id": queue_id,
            "queued_input_sha256": A,
            "action_envelope_sha256": payload,
            "authorization_token_sha256": C,
            "canonical_target_sha256": D,
            "risk_class": "MUTATING",
            "created_at_tick": 1,
            "metadata": {"fixture": "v3.28"},
        }
    )


def make_identities() -> dict:
    ledger_keys = generate_ed25519_keypair()
    head_keys = generate_ed25519_keypair()
    provider_keys = generate_ed25519_keypair()
    ledger_registry = TrustKeyRegistry(
        [
            make_trust_key_record(
                key_id="key:ledger:1",
                signer_id=LEDGER_SIGNER_ID,
                trust_domain=LEDGER_DOMAIN,
                public_key_b64=ledger_keys["public_key_b64"],
                purposes=[PURPOSE_EXECUTION_RECEIPT],
                valid_from=0,
                valid_until=100_000,
            )
        ]
    )
    head_registry = TrustKeyRegistry(
        [
            make_trust_key_record(
                key_id="key:execution-head:1",
                signer_id=HEAD_SIGNER_ID,
                trust_domain=HEAD_DOMAIN,
                public_key_b64=head_keys["public_key_b64"],
                purposes=[PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY],
                valid_from=0,
                valid_until=100_000,
            )
        ]
    )
    provider_registry = TrustKeyRegistry(
        [
            make_trust_key_record(
                key_id="key:provider:1",
                signer_id=PROVIDER_SIGNER_ID,
                trust_domain=PROVIDER_DOMAIN,
                public_key_b64=provider_keys["public_key_b64"],
                purposes=[PURPOSE_PROVIDER_EFFECT_RECEIPT],
                valid_from=0,
                valid_until=100_000,
            )
        ]
    )
    return {
        "ledger_keys": ledger_keys,
        "head_keys": head_keys,
        "provider_keys": provider_keys,
        "ledger_registry": ledger_registry,
        "head_registry": head_registry,
        "provider_registry": provider_registry,
    }


def open_ledger(path: str, ids: dict) -> SQLiteExternalExecutionLedger:
    return SQLiteExternalExecutionLedger(
        path,
        ledger_id=LEDGER_ID,
        authority_id=LEDGER_AUTHORITY_ID,
        key_id="key:ledger:1",
        signer_id=LEDGER_SIGNER_ID,
        trust_domain=LEDGER_DOMAIN,
        private_key_b64=ids["ledger_keys"]["private_key_b64"],
        receipt_ttl=10_000,
    )


def open_head_authority(path: str, ids: dict) -> SQLiteExecutionLedgerHeadAuthority:
    return SQLiteExecutionLedgerHeadAuthority(
        path,
        authority_id=HEAD_AUTHORITY_ID,
        service_id="service:execution-head:1",
        ledger_registry=ids["ledger_registry"],
        expected_ledger_signer_id=LEDGER_SIGNER_ID,
        expected_ledger_trust_domain=LEDGER_DOMAIN,
        key_id="key:execution-head:1",
        signer_id=HEAD_SIGNER_ID,
        trust_domain=HEAD_DOMAIN,
        private_key_b64=ids["head_keys"]["private_key_b64"],
        response_ttl=100,
    )


def open_provider(path: str, ids: dict) -> SQLiteIdempotentEffectProvider:
    return SQLiteIdempotentEffectProvider(
        path,
        provider_id=PROVIDER_ID,
        service_id=PROVIDER_SERVICE_ID,
        key_id="key:provider:1",
        signer_id=PROVIDER_SIGNER_ID,
        trust_domain=PROVIDER_DOMAIN,
        private_key_b64=ids["provider_keys"]["private_key_b64"],
        response_ttl=100,
    )


def anchor(authority: SQLiteExecutionLedgerHeadAuthority, ledger: SQLiteExternalExecutionLedger, now: int) -> dict:
    current = authority.current(LEDGER_ID)
    base = 0 if current is None else current["inner_contract"]["sequence"]
    head = ledger.head(now_tick=now)
    return authority.install_advance(head, ledger.events_since(base), evaluation_tick=now)


def issue_head_challenge(
    authority: SQLiteExecutionLedgerHeadAuthority,
    *,
    issued_at: int,
    response_at: int,
) -> tuple[SQLiteEpochChallengeLedger, str, dict]:
    session = VerifierFreshnessSession.create("verifier:v328", started_at=0)
    challenges = SQLiteEpochChallengeLedger(":memory:", session)
    challenge = challenges.issue(issued_at=issued_at, expires_at=issued_at + 50)
    response = authority.issue_head(
        ledger_id=LEDGER_ID,
        challenge=challenge,
        verifier_id=session.verifier_id,
        verifier_epoch_sha256=session.epoch_sha256,
        requested_at=issued_at,
        issued_at=response_at,
        valid_until=response_at + 20,
    )
    return challenges, challenge, response


def verify_head(
    ledger: SQLiteExternalExecutionLedger,
    authority: SQLiteExecutionLedgerHeadAuthority,
    ids: dict,
    *,
    tick: int,
) -> dict:
    challenges, challenge, response = issue_head_challenge(authority, issued_at=tick, response_at=tick)
    try:
        return verify_external_execution_ledger_head(
            ledger.head(now_tick=tick),
            response,
            ledger_registry=ids["ledger_registry"],
            authority_registry=ids["head_registry"],
            expected_ledger_id=LEDGER_ID,
            expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
            expected_ledger_signer_id=LEDGER_SIGNER_ID,
            expected_ledger_trust_domain=LEDGER_DOMAIN,
            expected_head_authority_id=HEAD_AUTHORITY_ID,
            expected_head_authority_signer_id=HEAD_SIGNER_ID,
            expected_head_authority_trust_domain=HEAD_DOMAIN,
            challenge_ledger=challenges,
            expected_challenge=challenge,
            evaluation_tick=tick,
        )
    finally:
        challenges.close()


def _copy_sqlite(src: Path, dst: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(src) + suffix).unlink(missing_ok=True)
    shutil.copy2(src, dst)


def _restore_sqlite(snapshot: Path, target: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(target) + suffix).unlink(missing_ok=True)
    shutil.copy2(snapshot, target)


class ExecutionLedgerHeadAuthorityTests(unittest.TestCase):
    def test_genesis_and_contiguous_advance_are_accepted(self):
        ids = make_identities()
        ledger = open_ledger(":memory:", ids)
        authority = open_head_authority(":memory:", ids)
        try:
            genesis = anchor(authority, ledger, 1)
            self.assertEqual(genesis["accepted_event_count"], 0)
            intent = make_intent()
            dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch, now_tick=2)
            ledger.start(intent["effect_id"], attempt_id="attempt:1", dispatch_id=dispatch, now_tick=3)
            advanced = anchor(authority, ledger, 3)
            self.assertEqual(advanced["accepted_event_count"], 2)
            self.assertEqual(authority.current(LEDGER_ID)["inner_contract"]["sequence"], 2)
        finally:
            authority.close()
            ledger.close()

    def test_exact_head_replay_is_idempotent(self):
        ids = make_identities()
        ledger = open_ledger(":memory:", ids)
        authority = open_head_authority(":memory:", ids)
        try:
            signed = ledger.head(now_tick=1)
            first = authority.install_advance(signed, [], evaluation_tick=1)
            second = authority.install_advance(signed, [], evaluation_tick=1)
            self.assertFalse(first["idempotent_replay"])
            self.assertTrue(second["idempotent_replay"])
        finally:
            authority.close()
            ledger.close()

    def test_stale_head_is_rejected(self):
        ids = make_identities()
        ledger = open_ledger(":memory:", ids)
        authority = open_head_authority(":memory:", ids)
        try:
            stale = ledger.head(now_tick=1)
            anchor(authority, ledger, 1)
            intent = make_intent()
            dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch, now_tick=2)
            anchor(authority, ledger, 2)
            with self.assertRaises(ExecutionLedgerHeadError) as ctx:
                authority.install_advance(stale, [], evaluation_tick=2)
            self.assertEqual(ctx.exception.code, "execution_ledger_head_rollback")
        finally:
            authority.close()
            ledger.close()

    def test_same_sequence_fork_is_rejected(self):
        ids = make_identities()
        ledger = open_ledger(":memory:", ids)
        authority = open_head_authority(":memory:", ids)
        try:
            anchor(authority, ledger, 1)
            original = ledger.head(now_tick=2)
            inner = copy.deepcopy(original["inner_contract"])
            inner["state_root_sha256"] = E
            inner["head_sha256"] = ""
            inner = seal_mapping(inner, "head_sha256")
            fork = sign_contract_envelope(
                inner,
                digest_field="head_sha256",
                purpose=PURPOSE_EXECUTION_RECEIPT,
                key_id="key:ledger:1",
                signer_id=LEDGER_SIGNER_ID,
                trust_domain=LEDGER_DOMAIN,
                private_key_b64=ids["ledger_keys"]["private_key_b64"],
                issued_at=2,
                valid_until=100,
            )
            with self.assertRaises(ExecutionLedgerHeadError) as ctx:
                authority.install_advance(fork, [], evaluation_tick=2)
            self.assertEqual(ctx.exception.code, "execution_ledger_same_sequence_fork")
        finally:
            authority.close()
            ledger.close()

    def test_rolled_back_ledger_cannot_overtake_with_a_fork(self):
        ids = make_identities()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.sqlite"
            snapshot = Path(td) / "ledger.genesis.sqlite"
            ledger = open_ledger(str(path), ids)
            authority = open_head_authority(":memory:", ids)
            anchor(authority, ledger, 1)
            ledger.close()
            _copy_sqlite(path, snapshot)
            ledger = open_ledger(str(path), ids)
            first = make_intent("queue:first")
            first_dispatch = canonical_sha256({"dispatch": "first"})
            ledger.reserve(first, attempt_id="attempt:first", dispatch_id=first_dispatch, now_tick=2)
            ledger.start(first["effect_id"], attempt_id="attempt:first", dispatch_id=first_dispatch, now_tick=3)
            ledger.record_outcome(
                first["effect_id"], attempt_id="attempt:first", dispatch_id=first_dispatch,
                outcome="COMPLETED", evidence_sha256=E, now_tick=4,
            )
            anchor(authority, ledger, 4)
            stored_event = authority.current(LEDGER_ID)["inner_contract"]["head_event_sha256"]
            ledger.close()

            _restore_sqlite(snapshot, path)
            forked = open_ledger(str(path), ids)
            same = make_intent("queue:first")
            same_dispatch = canonical_sha256({"dispatch": "fork-first"})
            forked.reserve(same, attempt_id="attempt:fork:first", dispatch_id=same_dispatch, now_tick=5)
            forked.start(same["effect_id"], attempt_id="attempt:fork:first", dispatch_id=same_dispatch, now_tick=6)
            forked.record_outcome(
                same["effect_id"], attempt_id="attempt:fork:first", dispatch_id=same_dispatch,
                outcome="COMPLETED", evidence_sha256=F, now_tick=7,
            )
            second = make_intent("queue:second", payload=E)
            second_dispatch = canonical_sha256({"dispatch": "fork-second"})
            forked.reserve(second, attempt_id="attempt:fork:second", dispatch_id=second_dispatch, now_tick=8)
            incoming = forked.head(now_tick=8)
            only_new_sequence_four = forked.events_since(3)
            self.assertEqual(len(only_new_sequence_four), 1)
            self.assertNotEqual(
                only_new_sequence_four[0]["inner_contract"]["previous_event_sha256"], stored_event
            )
            with self.assertRaises(ExecutionLedgerHeadError) as ctx:
                authority.install_advance(incoming, only_new_sequence_four, evaluation_tick=8)
            self.assertEqual(ctx.exception.code, "execution_ledger_event_parent_mismatch")
            forked.close()
            authority.close()

    def test_fresh_challenge_bound_head_verifies_once(self):
        ids = make_identities()
        ledger = open_ledger(":memory:", ids)
        authority = open_head_authority(":memory:", ids)
        try:
            anchor(authority, ledger, 1)
            challenges, challenge, response = issue_head_challenge(authority, issued_at=2, response_at=2)
            local = ledger.head(now_tick=2)
            verified = verify_external_execution_ledger_head(
                local, response,
                ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                expected_head_authority_id=HEAD_AUTHORITY_ID,
                expected_head_authority_signer_id=HEAD_SIGNER_ID,
                expected_head_authority_trust_domain=HEAD_DOMAIN,
                challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
            )
            self.assertEqual(verified["status"], "PASS")
            self.assertFalse(verified["authority_granted"])
            with self.assertRaises(Exception):
                verify_external_execution_ledger_head(
                    local, response,
                    ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                    expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                    expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                    expected_head_authority_id=HEAD_AUTHORITY_ID,
                    expected_head_authority_signer_id=HEAD_SIGNER_ID,
                    expected_head_authority_trust_domain=HEAD_DOMAIN,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
                )
            challenges.close()
        finally:
            authority.close()
            ledger.close()

    def test_external_head_detects_local_rollback(self):
        ids = make_identities()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.sqlite"
            snapshot = Path(td) / "ledger.zero.sqlite"
            ledger = open_ledger(str(path), ids)
            authority = open_head_authority(":memory:", ids)
            anchor(authority, ledger, 1)
            ledger.close()
            _copy_sqlite(path, snapshot)
            ledger = open_ledger(str(path), ids)
            intent = make_intent()
            dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch, now_tick=2)
            anchor(authority, ledger, 2)
            ledger.close()
            _restore_sqlite(snapshot, path)
            restored = open_ledger(str(path), ids)
            with self.assertRaises(ExecutionLedgerHeadError) as ctx:
                verify_head(restored, authority, ids, tick=3)
            self.assertEqual(ctx.exception.code, "execution_ledger_rollback_or_fork_detected")
            restored.close()
            authority.close()

    def test_guarded_reserve_blocks_before_recreating_rolled_back_effect(self):
        ids = make_identities()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.sqlite"
            snapshot = Path(td) / "ledger.zero.sqlite"
            ledger = open_ledger(str(path), ids)
            authority = open_head_authority(":memory:", ids)
            anchor(authority, ledger, 1)
            ledger.close()
            _copy_sqlite(path, snapshot)
            ledger = open_ledger(str(path), ids)
            intent = make_intent()
            dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch, now_tick=2)
            ledger.start(intent["effect_id"], attempt_id="attempt:1", dispatch_id=dispatch, now_tick=3)
            ledger.record_outcome(
                intent["effect_id"], attempt_id="attempt:1", dispatch_id=dispatch,
                outcome="COMPLETED", evidence_sha256=E, now_tick=4,
            )
            anchor(authority, ledger, 4)
            ledger.close()
            _restore_sqlite(snapshot, path)
            restored = open_ledger(str(path), ids)
            challenges, challenge, response = issue_head_challenge(authority, issued_at=5, response_at=5)
            with self.assertRaises(ExecutionLedgerHeadError):
                reserve_with_external_head_guard(
                    restored, intent,
                    attempt_id="attempt:revived", dispatch_id=canonical_sha256({"dispatch": 2}), now_tick=5,
                    signed_local_head=restored.head(now_tick=5), signed_head_response=response,
                    ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                    expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                    expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                    expected_head_authority_id=HEAD_AUTHORITY_ID,
                    expected_head_authority_signer_id=HEAD_SIGNER_ID,
                    expected_head_authority_trust_domain=HEAD_DOMAIN,
                    challenge_ledger=challenges, expected_challenge=challenge,
                )
            self.assertIsNone(restored.get_effect(intent["effect_id"]))
            challenges.close()
            restored.close()
            authority.close()

    def test_in_flight_effect_requires_current_anchored_head(self):
        ids = make_identities()
        ledger = open_ledger(":memory:", ids)
        authority = open_head_authority(":memory:", ids)
        try:
            anchor(authority, ledger, 1)
            intent = make_intent()
            dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch, now_tick=2)
            started = ledger.start(intent["effect_id"], attempt_id="attempt:1", dispatch_id=dispatch, now_tick=3)
            anchor(authority, ledger, 3)
            challenges, challenge, response = issue_head_challenge(authority, issued_at=3, response_at=3)
            result = verify_external_effect_guard_with_monotonic_head(
                intent, started["signed_receipt"], ledger.head(now_tick=3), response,
                ledger_registry=ids["ledger_registry"], head_authority_registry=ids["head_registry"],
                evaluation_tick=3, expected_ledger_id=LEDGER_ID,
                expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID,
                expected_ledger_trust_domain=LEDGER_DOMAIN,
                expected_head_authority_id=HEAD_AUTHORITY_ID,
                expected_head_authority_signer_id=HEAD_SIGNER_ID,
                expected_head_authority_trust_domain=HEAD_DOMAIN,
                expected_attempt_id="attempt:1", expected_dispatch_id=dispatch,
                challenge_ledger=challenges, expected_challenge=challenge,
            )
            self.assertEqual(result["status"], "PASS")
            self.assertFalse(result["authority_granted"])
            challenges.close()
        finally:
            authority.close()
            ledger.close()

    def test_authority_restart_preserves_monotonic_head(self):
        ids = make_identities()
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "head.sqlite")
            ledger = open_ledger(":memory:", ids)
            authority = open_head_authority(path, ids)
            anchor(authority, ledger, 1)
            authority.close()
            reopened = open_head_authority(path, ids)
            try:
                self.assertEqual(reopened.current(LEDGER_ID)["inner_contract"]["sequence"], 0)
                verify_head(ledger, reopened, ids, tick=2)
            finally:
                reopened.close()
                ledger.close()

    def test_head_http_authenticates_install_and_minimizes_health(self):
        ids = make_identities()
        ledger = open_ledger(":memory:", ids)
        authority = open_head_authority(":memory:", ids)
        token = "head-admin-secret"
        app = ExecutionLedgerHeadHTTPApplication(
            authority,
            clock=lambda: 1,
            admin_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
        )
        try:
            signed = ledger.head(now_tick=1)
            status, denied = app.handle("POST", "/v1/heads/install", {"signed_head": signed, "signed_events": []})
            self.assertEqual(status, 403)
            status, installed = app.handle(
                "POST", "/v1/heads/install", {"signed_head": signed, "signed_events": []},
                {"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(installed["head"]["sequence"], 0)
            status, health = app.handle("GET", "/healthz")
            self.assertEqual(status, 200)
            self.assertNotIn("private_key", json.dumps(health))
            self.assertNotIn(token, json.dumps(health))
        finally:
            authority.close()
            ledger.close()


class IdempotentProviderTests(unittest.TestCase):
    def test_absent_signed_status_allows_first_attempt_once(self):
        ids = make_identities()
        provider = open_provider(":memory:", ids)
        intent = make_intent()
        session = VerifierFreshnessSession.create("verifier:provider", 0)
        challenges = SQLiteEpochChallengeLedger(":memory:", session)
        try:
            challenge = challenges.issue(1, 20)
            signed = provider.issue_status(
                effect_id=intent["effect_id"], expected_payload_sha256=B,
                challenge=challenge, verifier_id=session.verifier_id,
                verifier_epoch_sha256=session.epoch_sha256,
                requested_at=1, issued_at=1,
            )
            result = verify_provider_effect_status(
                signed, registry=ids["provider_registry"],
                expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID,
                expected_signer_id=PROVIDER_SIGNER_ID, expected_trust_domain=PROVIDER_DOMAIN,
                expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
            )
            self.assertEqual(result["provider_status"]["state"], "ABSENT")
            self.assertTrue(result["external_effect_permitted"])
            with self.assertRaises(Exception):
                verify_provider_effect_status(
                    signed, registry=ids["provider_registry"],
                    expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID,
                    expected_signer_id=PROVIDER_SIGNER_ID, expected_trust_domain=PROVIDER_DOMAIN,
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
                )
        finally:
            challenges.close()
            provider.close()

    def test_completed_effect_is_idempotent_and_not_reexecuted(self):
        ids = make_identities()
        provider = open_provider(":memory:", ids)
        intent = make_intent()
        try:
            first = provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:1", now_tick=1,
            )
            self.assertTrue(first["external_effect_permitted"])
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:1",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            duplicate = provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:retry", now_tick=3,
            )
            self.assertTrue(duplicate["idempotent_replay"])
            self.assertFalse(duplicate["external_effect_permitted"])
            self.assertEqual(duplicate["effect"]["state"], "COMPLETED")
            self.assertEqual(len([e for e in provider.events(intent["effect_id"]) if e["to_state"] == "IN_FLIGHT"]), 1)
        finally:
            provider.close()

    def test_same_effect_with_different_payload_fails_closed(self):
        ids = make_identities()
        provider = open_provider(":memory:", ids)
        intent = make_intent()
        try:
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:1", now_tick=1,
            )
            with self.assertRaises(ProviderEffectError) as ctx:
                provider.begin(
                    effect_id=intent["effect_id"], payload_sha256=E,
                    provider_request_id="provider-request:2", now_tick=2,
                )
            self.assertEqual(ctx.exception.code, "provider_idempotency_payload_conflict")
        finally:
            provider.close()

    def test_unknown_blocks_until_authoritative_no_effect_reconciliation(self):
        ids = make_identities()
        provider = open_provider(":memory:", ids)
        intent = make_intent()
        try:
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:1", now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:1",
                outcome="UNKNOWN", provider_response_sha256=None, evidence_sha256=E, now_tick=2,
            )
            blocked = provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:retry", now_tick=3,
            )
            self.assertFalse(blocked["external_effect_permitted"])
            self.assertEqual(blocked["effect"]["state"], "UNKNOWN")
            provider.reconcile_unknown(
                effect_id=intent["effect_id"], provider_request_id="provider-request:1",
                outcome="NO_EFFECT", provider_response_sha256=None, evidence_sha256=F, now_tick=4,
            )
            retry = provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:2", now_tick=5,
            )
            self.assertTrue(retry["external_effect_permitted"])
            self.assertEqual(retry["effect"]["generation"], 2)
        finally:
            provider.close()

    def test_completed_signed_status_blocks_retry(self):
        ids = make_identities()
        provider = open_provider(":memory:", ids)
        intent = make_intent()
        session = VerifierFreshnessSession.create("verifier:provider", 0)
        challenges = SQLiteEpochChallengeLedger(":memory:", session)
        try:
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:1", now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:1",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            challenge = challenges.issue(3, 20)
            signed = provider.issue_status(
                effect_id=intent["effect_id"], expected_payload_sha256=B,
                challenge=challenge, verifier_id=session.verifier_id,
                verifier_epoch_sha256=session.epoch_sha256,
                requested_at=3, issued_at=3,
            )
            with self.assertRaises(ProviderEffectError) as ctx:
                verify_provider_effect_status(
                    signed, registry=ids["provider_registry"],
                    expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID,
                    expected_signer_id=PROVIDER_SIGNER_ID, expected_trust_domain=PROVIDER_DOMAIN,
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=3,
                )
            self.assertEqual(ctx.exception.code, "provider_effect_state_blocks_retry")
        finally:
            challenges.close()
            provider.close()

    def test_provider_restart_preserves_completed_state(self):
        ids = make_identities()
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "provider.sqlite")
            provider = open_provider(path, ids)
            intent = make_intent()
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:1", now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:1",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            provider.close()
            reopened = open_provider(path, ids)
            try:
                self.assertEqual(reopened.get(intent["effect_id"])["state"], "COMPLETED")
            finally:
                reopened.close()

    def test_provider_http_authenticates_mutations_but_status_is_challenge_bound(self):
        ids = make_identities()
        provider = open_provider(":memory:", ids)
        token = "provider-client-secret"
        app = IdempotentEffectProviderHTTPApplication(
            provider,
            clock=lambda: 1,
            client_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
        )
        intent = make_intent()
        try:
            status, _ = app.handle(
                "POST", "/v1/effects/begin",
                {"effect_id": intent["effect_id"], "payload_sha256": B, "provider_request_id": "request:1"},
            )
            self.assertEqual(status, 403)
            status, result = app.handle(
                "POST", "/v1/effects/begin",
                {"effect_id": intent["effect_id"], "payload_sha256": B, "provider_request_id": "request:1"},
                {"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(status, 200)
            self.assertTrue(result["external_effect_permitted"])
            health_status, health = app.handle("GET", "/healthz")
            self.assertEqual(health_status, 200)
            self.assertNotIn("private_key", json.dumps(health))
            self.assertNotIn(token, json.dumps(health))
        finally:
            provider.close()

    def test_provider_still_blocks_after_ledger_and_head_authority_rollback(self):
        ids = make_identities()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ledger_path = root / "ledger.sqlite"
            head_path = root / "head.sqlite"
            provider_path = root / "provider.sqlite"
            ledger_snapshot = root / "ledger.snapshot.sqlite"
            head_snapshot = root / "head.snapshot.sqlite"

            ledger = open_ledger(str(ledger_path), ids)
            head = open_head_authority(str(head_path), ids)
            provider = open_provider(str(provider_path), ids)
            anchor(head, ledger, 1)
            ledger.close(); head.close()
            _copy_sqlite(ledger_path, ledger_snapshot)
            _copy_sqlite(head_path, head_snapshot)

            ledger = open_ledger(str(ledger_path), ids)
            head = open_head_authority(str(head_path), ids)
            intent = make_intent()
            dispatch = canonical_sha256({"dispatch": 1})
            ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch, now_tick=2)
            ledger.start(intent["effect_id"], attempt_id="attempt:1", dispatch_id=dispatch, now_tick=3)
            anchor(head, ledger, 3)
            begun = provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:1", now_tick=3,
            )
            self.assertTrue(begun["external_effect_permitted"])
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:1",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=4,
            )
            ledger.record_outcome(
                intent["effect_id"], attempt_id="attempt:1", dispatch_id=dispatch,
                outcome="COMPLETED", evidence_sha256=F, now_tick=4,
            )
            anchor(head, ledger, 4)
            ledger.close(); head.close()

            _restore_sqlite(ledger_snapshot, ledger_path)
            _restore_sqlite(head_snapshot, head_path)
            restored_ledger = open_ledger(str(ledger_path), ids)
            restored_head = open_head_authority(str(head_path), ids)
            self.assertEqual(verify_head(restored_ledger, restored_head, ids, tick=5)["status"], "PASS")
            duplicate = provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:duplicate", now_tick=5,
            )
            self.assertTrue(duplicate["idempotent_replay"])
            self.assertFalse(duplicate["external_effect_permitted"])
            self.assertEqual(duplicate["effect"]["state"], "COMPLETED")
            restored_ledger.close(); restored_head.close(); provider.close()


class ContractIdentityTests(unittest.TestCase):
    def test_contract_ids_are_frozen(self):
        self.assertEqual(
            EXECUTION_LEDGER_HEAD_RESPONSE_CONTRACT_ID,
            "TRIAXIS_EXECUTION_LEDGER_HEAD_RESPONSE_v1",
        )
        self.assertEqual(PROVIDER_EFFECT_STATUS_CONTRACT_ID, "TRIAXIS_PROVIDER_EFFECT_STATUS_v1")
        self.assertEqual(EXECUTION_LEDGER_HEAD_CONTRACT_ID, "TRIAXIS_EXECUTION_LEDGER_HEAD_v1")


if __name__ == "__main__":
    unittest.main()
