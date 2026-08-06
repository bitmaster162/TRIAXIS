from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
from typing import Any

from triaxis.crypto_trust import (
    PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
    PURPOSE_EXECUTION_RECEIPT,
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.execution_ledger_head_authority import (
    SQLiteExecutionLedgerHeadAuthority,
    verify_external_execution_ledger_head,
)
from triaxis.external_execution_ledger import SQLiteExternalExecutionLedger, seal_execution_intent
from triaxis.harness_durability_v3 import SQLiteDurableDispatchQueue, seal_queued_input
from triaxis.idempotent_effect_provider import SQLiteIdempotentEffectProvider
from triaxis.integrity import canonical_sha256
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
E = "e" * 64
F = "f" * 64

LEDGER_ID = "ledger:v328:rollback-boundary"
LEDGER_AUTHORITY_ID = "authority:ledger:v328:rollback-boundary"
LEDGER_SIGNER_ID = "signer:ledger:v328:rollback-boundary"
LEDGER_DOMAIN = "triaxis:execution-ledger:v328-boundary"
HEAD_AUTHORITY_ID = "authority:execution-head:v328:rollback-boundary"
HEAD_SIGNER_ID = "signer:execution-head:v328:rollback-boundary"
HEAD_DOMAIN = "triaxis:execution-head:v328-boundary"
PROVIDER_ID = "provider:v328:rollback-boundary"
PROVIDER_SERVICE_ID = "service:effect:v328:rollback-boundary"
PROVIDER_SIGNER_ID = "signer:provider:v328:rollback-boundary"
PROVIDER_DOMAIN = "triaxis:provider:v328-boundary"
PAYLOAD_SHA256 = F


def queued_item() -> dict[str, Any]:
    return seal_queued_input(
        {
            "queue_id": "queue:v328:rollback-boundary",
            "thread_id": "thread:v328:rollback-boundary",
            "content_ref": "content:v328:rollback-boundary",
            "content_sha256": A,
            "risk_class": "MUTATING",
            "created_at_tick": 1,
            "attachments": [],
            "metadata": {"fixture": "v3.28_full_effect_state_rollback"},
        }
    )


def execution_intent(item: dict[str, Any]) -> dict[str, Any]:
    return seal_execution_intent(
        {
            "queue_id": item["queue_id"],
            "queued_input_sha256": item["queued_input_sha256"],
            "action_envelope_sha256": B,
            "authorization_token_sha256": C,
            "canonical_target_sha256": D,
            "risk_class": "MUTATING",
            "created_at_tick": 2,
            "metadata": {"fixture": "v3.28_full_effect_state_rollback"},
        }
    )


def identities() -> dict[str, Any]:
    ledger_keys = generate_ed25519_keypair()
    head_keys = generate_ed25519_keypair()
    provider_keys = generate_ed25519_keypair()
    ledger_registry = TrustKeyRegistry(
        [
            make_trust_key_record(
                key_id="key:ledger:v328:boundary",
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
                key_id="key:head:v328:boundary",
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
                key_id="key:provider:v328:boundary",
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


def open_ledger(path: Path, ids: dict[str, Any]) -> SQLiteExternalExecutionLedger:
    return SQLiteExternalExecutionLedger(
        path,
        ledger_id=LEDGER_ID,
        authority_id=LEDGER_AUTHORITY_ID,
        key_id="key:ledger:v328:boundary",
        signer_id=LEDGER_SIGNER_ID,
        trust_domain=LEDGER_DOMAIN,
        private_key_b64=ids["ledger_keys"]["private_key_b64"],
        receipt_ttl=10_000,
    )


def open_head(path: Path, ids: dict[str, Any]) -> SQLiteExecutionLedgerHeadAuthority:
    return SQLiteExecutionLedgerHeadAuthority(
        path,
        authority_id=HEAD_AUTHORITY_ID,
        service_id="service:execution-head:v328:boundary",
        ledger_registry=ids["ledger_registry"],
        expected_ledger_signer_id=LEDGER_SIGNER_ID,
        expected_ledger_trust_domain=LEDGER_DOMAIN,
        key_id="key:head:v328:boundary",
        signer_id=HEAD_SIGNER_ID,
        trust_domain=HEAD_DOMAIN,
        private_key_b64=ids["head_keys"]["private_key_b64"],
        response_ttl=100,
    )


def open_provider(path: Path, ids: dict[str, Any]) -> SQLiteIdempotentEffectProvider:
    return SQLiteIdempotentEffectProvider(
        path,
        provider_id=PROVIDER_ID,
        service_id=PROVIDER_SERVICE_ID,
        key_id="key:provider:v328:boundary",
        signer_id=PROVIDER_SIGNER_ID,
        trust_domain=PROVIDER_DOMAIN,
        private_key_b64=ids["provider_keys"]["private_key_b64"],
        response_ttl=100,
    )


def anchor(
    authority: SQLiteExecutionLedgerHeadAuthority,
    ledger: SQLiteExternalExecutionLedger,
    now_tick: int,
) -> dict[str, Any]:
    current = authority.current(LEDGER_ID)
    base = 0 if current is None else int(current["inner_contract"]["sequence"])
    return authority.install_advance(
        ledger.head(now_tick=now_tick),
        ledger.events_since(base),
        evaluation_tick=now_tick,
    )


def verify_head(
    authority: SQLiteExecutionLedgerHeadAuthority,
    ledger: SQLiteExternalExecutionLedger,
    ids: dict[str, Any],
    now_tick: int,
) -> dict[str, Any]:
    session = VerifierFreshnessSession.create("verifier:v328:rollback-boundary", started_at=0)
    with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
        challenge = challenges.issue(issued_at=now_tick, expires_at=now_tick + 50)
        response = authority.issue_head(
            ledger_id=LEDGER_ID,
            challenge=challenge,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            requested_at=now_tick,
            issued_at=now_tick,
            valid_until=now_tick + 20,
        )
        return verify_external_execution_ledger_head(
            ledger.head(now_tick=now_tick),
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
            evaluation_tick=now_tick,
        )


def snapshot_file(source: Path, snapshot: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(source) + suffix).unlink(missing_ok=True)
    shutil.copy2(source, snapshot)


def restore_file(snapshot: Path, target: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(target) + suffix).unlink(missing_ok=True)
    shutil.copy2(snapshot, target)


def begin_local_attempt(
    *,
    queue: SQLiteDurableDispatchQueue,
    ledger: SQLiteExternalExecutionLedger,
    head: SQLiteExecutionLedgerHeadAuthority,
    ids: dict[str, Any],
    item: dict[str, Any],
    intent: dict[str, Any],
    label: str,
    tick: int,
) -> dict[str, Any]:
    verify_head(head, ledger, ids, tick)
    claim = queue.claim_next(
        thread_id=item["thread_id"],
        thread_idle=True,
        claim_id=f"claim:{label}",
        now_tick=tick,
    )["claim"]
    reservation = ledger.reserve(
        intent,
        attempt_id=f"attempt:{label}",
        dispatch_id=claim["dispatch_id"],
        now_tick=tick,
    )
    started = ledger.start(
        intent["effect_id"],
        attempt_id=f"attempt:{label}",
        dispatch_id=claim["dispatch_id"],
        now_tick=tick + 1,
    )
    queue.begin_dispatch(
        item["queue_id"],
        claim_id=f"claim:{label}",
        dispatch_id=claim["dispatch_id"],
        now_tick=tick + 1,
    )
    anchor(head, ledger, tick + 1)
    verified = verify_head(head, ledger, ids, tick + 1)
    return {
        "claim": claim,
        "reservation": reservation,
        "started": started,
        "head_guard": verified,
    }


def run() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    ids = identities()
    item = queued_item()
    intent = execution_intent(item)

    with tempfile.TemporaryDirectory(prefix="triaxis-v328-full-rollback-") as td:
        root = Path(td)
        queue_db = root / "queue.sqlite"
        ledger_db = root / "ledger.sqlite"
        head_db = root / "head.sqlite"
        provider_db = root / "provider.sqlite"
        queue_snapshot = root / "queue.pre_effect.sqlite"
        ledger_snapshot = root / "ledger.pre_effect.sqlite"
        head_snapshot = root / "head.pre_effect.sqlite"
        provider_snapshot = root / "provider.pre_effect.sqlite"

        queue = SQLiteDurableDispatchQueue(queue_db)
        queue.enqueue(item)
        queue.close()

        ledger = open_ledger(ledger_db, ids)
        head = open_head(head_db, ids)
        provider = open_provider(provider_db, ids)
        anchor(head, ledger, 1)
        verify_head(head, ledger, ids, 1)
        ledger.close()
        head.close()
        provider.close()

        snapshot_file(queue_db, queue_snapshot)
        snapshot_file(ledger_db, ledger_snapshot)
        snapshot_file(head_db, head_snapshot)
        snapshot_file(provider_db, provider_snapshot)

        # Complete one effect with all state domains current.
        queue = SQLiteDurableDispatchQueue(queue_db)
        ledger = open_ledger(ledger_db, ids)
        head = open_head(head_db, ids)
        provider = open_provider(provider_db, ids)
        first = begin_local_attempt(
            queue=queue,
            ledger=ledger,
            head=head,
            ids=ids,
            item=item,
            intent=intent,
            label="first",
            tick=2,
        )
        provider_first = provider.begin(
            effect_id=intent["effect_id"],
            payload_sha256=PAYLOAD_SHA256,
            provider_request_id="provider-request:first",
            now_tick=4,
        )
        provider_completed = provider.record_outcome(
            effect_id=intent["effect_id"],
            provider_request_id="provider-request:first",
            outcome="COMPLETED",
            provider_response_sha256=E,
            evidence_sha256=F,
            now_tick=5,
        )
        ledger_completed = ledger.record_outcome(
            intent["effect_id"],
            attempt_id="attempt:first",
            dispatch_id=first["claim"]["dispatch_id"],
            outcome="COMPLETED",
            evidence_sha256=F,
            now_tick=5,
        )
        anchor(head, ledger, 5)
        verify_head(head, ledger, ids, 5)
        queue.acknowledge_persisted(
            item["queue_id"],
            claim_id="claim:first",
            dispatch_id=first["claim"]["dispatch_id"],
            persisted_receipt_sha256=ledger_completed["signed_receipt"]["inner_contract"]["event_sha256"],
            now_tick=5,
        )
        ledger_block = ledger.reserve(
            intent,
            attempt_id="attempt:control",
            dispatch_id=canonical_sha256({"dispatch": "control"}),
            now_tick=6,
        )
        provider_block = provider.begin(
            effect_id=intent["effect_id"],
            payload_sha256=PAYLOAD_SHA256,
            provider_request_id="provider-request:control",
            now_tick=6,
        )
        rows.append(
            {
                "case_id": "V328RB01_CURRENT_LEDGER_HEAD_AND_PROVIDER_BLOCK_DUPLICATE",
                "same_effect_id": provider_completed["effect"]["effect_id"] == intent["effect_id"],
                "ledger_observed": ledger_block["status"],
                "ledger_state": ledger_block.get("current_state"),
                "provider_idempotent_replay": provider_block["idempotent_replay"],
                "provider_external_effect_permitted": provider_block["external_effect_permitted"],
                "expected": "LEDGER_BLOCK_COMPLETED_AND_PROVIDER_DENY",
                "status": (
                    "PASS"
                    if ledger_block["status"] == "BLOCK"
                    and ledger_block.get("current_state") == "COMPLETED"
                    and provider_block["idempotent_replay"] is True
                    and provider_block["external_effect_permitted"] is False
                    else "FAIL"
                ),
            }
        )
        queue.close()
        ledger.close()
        head.close()
        provider.close()

        # Restore queue, ledger, and head, but retain provider completion state.
        restore_file(queue_snapshot, queue_db)
        restore_file(ledger_snapshot, ledger_db)
        restore_file(head_snapshot, head_db)

        queue = SQLiteDurableDispatchQueue(queue_db)
        ledger = open_ledger(ledger_db, ids)
        head = open_head(head_db, ids)
        provider = open_provider(provider_db, ids)
        second = begin_local_attempt(
            queue=queue,
            ledger=ledger,
            head=head,
            ids=ids,
            item=item,
            intent=intent,
            label="ledger-head-rolled-back",
            tick=10,
        )
        provider_after_local_rollback = provider.begin(
            effect_id=intent["effect_id"],
            payload_sha256=PAYLOAD_SHA256,
            provider_request_id="provider-request:after-local-rollback",
            now_tick=12,
        )
        rows.append(
            {
                "case_id": "V328RB02_CURRENT_PROVIDER_BLOCKS_LEDGER_AND_HEAD_ROLLBACK",
                "same_effect_id": second["reservation"]["effect"]["effect_id"] == intent["effect_id"],
                "new_dispatch_id": second["claim"]["dispatch_id"] != first["claim"]["dispatch_id"],
                "rolled_back_head_guard": second["head_guard"]["status"],
                "rolled_back_ledger_reservation": second["reservation"]["status"],
                "provider_state": provider_after_local_rollback["effect"]["state"],
                "provider_idempotent_replay": provider_after_local_rollback["idempotent_replay"],
                "provider_external_effect_permitted": provider_after_local_rollback["external_effect_permitted"],
                "expected": "PROVIDER_COMPLETED_DENIES_DUPLICATE",
                "status": (
                    "PASS"
                    if second["reservation"]["status"] == "PASS"
                    and provider_after_local_rollback["effect"]["state"] == "COMPLETED"
                    and provider_after_local_rollback["idempotent_replay"] is True
                    and provider_after_local_rollback["external_effect_permitted"] is False
                    else "FAIL"
                ),
            }
        )
        queue.close()
        ledger.close()
        head.close()
        provider.close()

        # Restore every persistence domain to the pre-effect snapshot.
        restore_file(queue_snapshot, queue_db)
        restore_file(ledger_snapshot, ledger_db)
        restore_file(head_snapshot, head_db)
        restore_file(provider_snapshot, provider_db)

        queue = SQLiteDurableDispatchQueue(queue_db)
        ledger = open_ledger(ledger_db, ids)
        head = open_head(head_db, ids)
        provider = open_provider(provider_db, ids)
        third = begin_local_attempt(
            queue=queue,
            ledger=ledger,
            head=head,
            ids=ids,
            item=item,
            intent=intent,
            label="all-state-rolled-back",
            tick=20,
        )
        provider_after_full_rollback = provider.begin(
            effect_id=intent["effect_id"],
            payload_sha256=PAYLOAD_SHA256,
            provider_request_id="provider-request:after-full-rollback",
            now_tick=22,
        )
        duplicate_permitted = (
            third["reservation"]["status"] == "PASS"
            and provider_after_full_rollback["external_effect_permitted"] is True
        )
        rows.append(
            {
                "case_id": "V328RB03_FULL_EFFECT_STATE_ROLLBACK_REVIVES_COMPLETED_EFFECT",
                "same_effect_id": third["reservation"]["effect"]["effect_id"] == intent["effect_id"],
                "new_dispatch_id": third["claim"]["dispatch_id"] != first["claim"]["dispatch_id"],
                "rolled_back_head_guard": third["head_guard"]["status"],
                "rolled_back_ledger_reservation": third["reservation"]["status"],
                "rolled_back_provider_state": provider_after_full_rollback["effect"]["state"],
                "provider_external_effect_permitted": provider_after_full_rollback["external_effect_permitted"],
                "expected_secure_result": "BLOCK_OR_INDEPENDENT_PROVIDER_PROOF",
                "status": "FAIL_EXPECTED" if duplicate_permitted else "PASS",
                "duplicate_effect_risk": duplicate_permitted,
            }
        )
        queue.close()
        ledger.close()
        head.close()
        provider.close()

    boundary_confirmed = (
        rows[0]["status"] == "PASS"
        and rows[1]["status"] == "PASS"
        and rows[2]["status"] == "FAIL_EXPECTED"
    )
    return {
        "protocol_id": "TRIAXIS_v3.28_POSTCOMMIT_FULL_EFFECT_STATE_ROLLBACK_BOUNDARY",
        "exact_subject_tag": "TRIAXIS-v3.28-RC1-MONOTONIC-EXECUTION-HEAD",
        "exact_subject_commit": "7d7e488185410d0cdadc2476c147ead062be0706",
        "status": "BOUNDARY_CONFIRMED" if boundary_confirmed else "UNEXPECTED",
        "claim": (
            "A current external head detects execution-ledger rollback and a current provider idempotency "
            "record blocks rollback of the queue, ledger, and head authority; coordinated rollback of all "
            "effect-state domains revives the completed effect."
        ),
        "required_next_control": [
            "independently administered execution-head quorum across separate rollback and failure domains",
            "real provider-native immutable idempotency keyed by stable effect_id",
            "external append-only or WORM completion receipts",
            "monotonic KMS/HSM or hardware-backed anti-rollback state",
            "authoritative provider reconciliation that is not stored in the same rollback domain",
        ],
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    result = run()
    path = Path("evidence/TRIAXIS_v3.28_POSTCOMMIT_FULL_EFFECT_STATE_ROLLBACK_BOUNDARY.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
