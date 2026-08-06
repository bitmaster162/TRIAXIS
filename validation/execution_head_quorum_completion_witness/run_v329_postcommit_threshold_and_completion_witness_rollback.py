from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any

from triaxis.crypto_trust import (
    PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
    PURPOSE_EXECUTION_RECEIPT,
    PURPOSE_EXTERNAL_COMPLETION_WITNESS,
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.execution_ledger_head_authority import (
    ExecutionLedgerHeadError,
    SQLiteExecutionLedgerHeadAuthority,
)
from triaxis.execution_ledger_head_quorum import (
    ExecutionLedgerHeadQuorumError,
    make_execution_ledger_head_quorum_config,
    verify_execution_ledger_head_quorum,
)
from triaxis.external_completion_witness import SQLiteExternalCompletionWitness
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

LEDGER_ID = "ledger:v329:rollback-boundary"
LEDGER_AUTHORITY_ID = "authority:ledger:v329:rollback-boundary"
LEDGER_SIGNER_ID = "signer:ledger:v329:rollback-boundary"
LEDGER_DOMAIN = "triaxis:execution-ledger:v329-boundary"
PROVIDER_ID = "provider:v329:rollback-boundary"
PROVIDER_SERVICE_ID = "service:provider:v329:rollback-boundary"
PROVIDER_SIGNER_ID = "signer:provider:v329:rollback-boundary"
PROVIDER_DOMAIN = "triaxis:provider:v329-boundary"
WITNESS_ID = "completion-witness:v329:rollback-boundary"
WITNESS_AUTHORITY_ID = "authority:completion-witness:v329:rollback-boundary"
WITNESS_SERVICE_ID = "service:completion-witness:v329:rollback-boundary"
WITNESS_SIGNER_ID = "signer:completion-witness:v329:rollback-boundary"
WITNESS_DOMAIN = "triaxis:completion-witness:v329-boundary"
PAYLOAD_SHA256 = F
SUBJECT_TAG = "TRIAXIS-v3.29-RC1-EXECUTION-HEAD-QUORUM-COMPLETION-WITNESS"


def queued_item() -> dict[str, Any]:
    return seal_queued_input(
        {
            "queue_id": "queue:v329:rollback-boundary",
            "thread_id": "thread:v329:rollback-boundary",
            "content_ref": "content:v329:rollback-boundary",
            "content_sha256": A,
            "risk_class": "MUTATING",
            "created_at_tick": 1,
            "attachments": [],
            "metadata": {"fixture": "v3.29_threshold_and_completion_witness_rollback"},
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
            "metadata": {"fixture": "v3.29_threshold_and_completion_witness_rollback"},
        }
    )


def identities() -> dict[str, Any]:
    ledger_keys = generate_ed25519_keypair()
    provider_keys = generate_ed25519_keypair()
    witness_keys = generate_ed25519_keypair()
    head_rows: list[dict[str, Any]] = []
    head_records: list[dict[str, Any]] = []
    for suffix in ("a", "b", "c"):
        pair = generate_ed25519_keypair()
        row = {
            "authority_id": f"authority:execution-head:v329:boundary:{suffix}",
            "service_id": f"service:execution-head:v329:boundary:{suffix}",
            "key_id": f"key:execution-head:v329:boundary:{suffix}",
            "signer_id": f"signer:execution-head:v329:boundary:{suffix}",
            "trust_domain": f"triaxis:execution-head:v329-boundary:{suffix}",
            "pair": pair,
        }
        head_rows.append(row)
        head_records.append(
            make_trust_key_record(
                key_id=row["key_id"],
                signer_id=row["signer_id"],
                trust_domain=row["trust_domain"],
                public_key_b64=pair["public_key_b64"],
                purposes=[PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY],
                valid_from=0,
                valid_until=100_000,
            )
        )
    return {
        "ledger_keys": ledger_keys,
        "provider_keys": provider_keys,
        "witness_keys": witness_keys,
        "head_rows": head_rows,
        "ledger_registry": TrustKeyRegistry(
            [
                make_trust_key_record(
                    key_id="key:ledger:v329:boundary",
                    signer_id=LEDGER_SIGNER_ID,
                    trust_domain=LEDGER_DOMAIN,
                    public_key_b64=ledger_keys["public_key_b64"],
                    purposes=[PURPOSE_EXECUTION_RECEIPT],
                    valid_from=0,
                    valid_until=100_000,
                )
            ]
        ),
        "head_registry": TrustKeyRegistry(head_records),
        "provider_registry": TrustKeyRegistry(
            [
                make_trust_key_record(
                    key_id="key:provider:v329:boundary",
                    signer_id=PROVIDER_SIGNER_ID,
                    trust_domain=PROVIDER_DOMAIN,
                    public_key_b64=provider_keys["public_key_b64"],
                    purposes=[PURPOSE_PROVIDER_EFFECT_RECEIPT],
                    valid_from=0,
                    valid_until=100_000,
                )
            ]
        ),
        "witness_registry": TrustKeyRegistry(
            [
                make_trust_key_record(
                    key_id="key:completion-witness:v329:boundary",
                    signer_id=WITNESS_SIGNER_ID,
                    trust_domain=WITNESS_DOMAIN,
                    public_key_b64=witness_keys["public_key_b64"],
                    purposes=[PURPOSE_EXTERNAL_COMPLETION_WITNESS],
                    valid_from=0,
                    valid_until=100_000,
                )
            ]
        ),
    }


def open_ledger(path: Path, ids: dict[str, Any]) -> SQLiteExternalExecutionLedger:
    return SQLiteExternalExecutionLedger(
        path,
        ledger_id=LEDGER_ID,
        authority_id=LEDGER_AUTHORITY_ID,
        key_id="key:ledger:v329:boundary",
        signer_id=LEDGER_SIGNER_ID,
        trust_domain=LEDGER_DOMAIN,
        private_key_b64=ids["ledger_keys"]["private_key_b64"],
        receipt_ttl=10_000,
    )


def open_head(path: Path, ids: dict[str, Any], index: int) -> SQLiteExecutionLedgerHeadAuthority:
    row = ids["head_rows"][index]
    return SQLiteExecutionLedgerHeadAuthority(
        path,
        authority_id=row["authority_id"],
        service_id=row["service_id"],
        ledger_registry=ids["ledger_registry"],
        expected_ledger_signer_id=LEDGER_SIGNER_ID,
        expected_ledger_trust_domain=LEDGER_DOMAIN,
        key_id=row["key_id"],
        signer_id=row["signer_id"],
        trust_domain=row["trust_domain"],
        private_key_b64=row["pair"]["private_key_b64"],
        response_ttl=100,
    )


def open_provider(path: Path, ids: dict[str, Any]) -> SQLiteIdempotentEffectProvider:
    return SQLiteIdempotentEffectProvider(
        path,
        provider_id=PROVIDER_ID,
        service_id=PROVIDER_SERVICE_ID,
        key_id="key:provider:v329:boundary",
        signer_id=PROVIDER_SIGNER_ID,
        trust_domain=PROVIDER_DOMAIN,
        private_key_b64=ids["provider_keys"]["private_key_b64"],
        response_ttl=100,
    )


def open_witness(path: Path, ids: dict[str, Any]) -> SQLiteExternalCompletionWitness:
    return SQLiteExternalCompletionWitness(
        path,
        witness_id=WITNESS_ID,
        authority_id=WITNESS_AUTHORITY_ID,
        service_id=WITNESS_SERVICE_ID,
        key_id="key:completion-witness:v329:boundary",
        signer_id=WITNESS_SIGNER_ID,
        trust_domain=WITNESS_DOMAIN,
        private_key_b64=ids["witness_keys"]["private_key_b64"],
        receipt_ttl=100,
    )


def quorum_config(ids: dict[str, Any]) -> dict[str, Any]:
    rows = [
        {
            key: row[key]
            for key in ("authority_id", "service_id", "signer_id", "key_id", "trust_domain")
        }
        for row in ids["head_rows"]
    ]
    return make_execution_ledger_head_quorum_config(
        config_id="execution-head-quorum:v329:rollback-boundary",
        authority_set_id="execution-head-authorities:v329:rollback-boundary",
        ledger_id=LEDGER_ID,
        threshold=2,
        authorities=rows,
        valid_from=0,
        valid_until=100_000,
    )


def snapshot_file(source: Path, snapshot: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(source) + suffix).unlink(missing_ok=True)
    shutil.copy2(source, snapshot)


def restore_file(snapshot: Path, target: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(target) + suffix).unlink(missing_ok=True)
    shutil.copy2(snapshot, target)


def anchor_heads(
    heads: list[SQLiteExecutionLedgerHeadAuthority],
    ledger: SQLiteExternalExecutionLedger,
    now_tick: int,
) -> list[dict[str, Any]]:
    signed_head = ledger.head(now_tick=now_tick)
    rows: list[dict[str, Any]] = []
    for index, head in enumerate(heads):
        current = head.current(LEDGER_ID)
        base = 0 if current is None else int(current["inner_contract"]["sequence"])
        try:
            result = head.install_advance(
                signed_head,
                ledger.events_since(base),
                evaluation_tick=now_tick,
            )
            rows.append(
                {
                    "index": index,
                    "status": "PASS",
                    "accepted_sequence": result["signed_head"]["inner_contract"]["sequence"],
                    "error": None,
                }
            )
        except ExecutionLedgerHeadError as exc:
            rows.append(
                {"index": index, "status": "BLOCK", "accepted_sequence": None, "error": exc.code}
            )
    return rows


def verify_quorum(
    heads: list[SQLiteExecutionLedgerHeadAuthority],
    ledger: SQLiteExternalExecutionLedger,
    ids: dict[str, Any],
    now_tick: int,
    verifier_suffix: str,
) -> dict[str, Any]:
    session = VerifierFreshnessSession.create(
        f"verifier:v329:rollback-boundary:{verifier_suffix}", started_at=0
    )
    with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
        challenge = challenges.issue(issued_at=now_tick, expires_at=now_tick + 50)
        responses = [
            head.issue_head(
                ledger_id=LEDGER_ID,
                challenge=challenge,
                verifier_id=session.verifier_id,
                verifier_epoch_sha256=session.epoch_sha256,
                requested_at=now_tick,
                issued_at=now_tick,
                valid_until=now_tick + 20,
            )
            for head in heads
        ]
        config = quorum_config(ids)
        return verify_execution_ledger_head_quorum(
            ledger.head(now_tick=now_tick),
            responses,
            ledger_registry=ids["ledger_registry"],
            authority_registry=ids["head_registry"],
            expected_ledger_id=LEDGER_ID,
            expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
            expected_ledger_signer_id=LEDGER_SIGNER_ID,
            expected_ledger_trust_domain=LEDGER_DOMAIN,
            quorum_config=config,
            expected_quorum_config_sha256=config["config_sha256"],
            challenge_ledger=challenges,
            expected_challenge=challenge,
            evaluation_tick=now_tick,
        )


def claim_and_start(
    *,
    queue: SQLiteDurableDispatchQueue,
    ledger: SQLiteExternalExecutionLedger,
    heads: list[SQLiteExecutionLedgerHeadAuthority],
    ids: dict[str, Any],
    item: dict[str, Any],
    intent: dict[str, Any],
    label: str,
    tick: int,
) -> dict[str, Any]:
    before = verify_quorum(heads, ledger, ids, tick, f"{label}:before")
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
    anchor_rows = anchor_heads(heads, ledger, tick + 1)
    after = verify_quorum(heads, ledger, ids, tick + 1, f"{label}:after")
    return {
        "claim": claim,
        "reservation": reservation,
        "started": started,
        "quorum_before": before,
        "anchor_rows": anchor_rows,
        "quorum_after": after,
    }


def git_subject_commit() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def run() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    ids = identities()
    item = queued_item()
    intent = execution_intent(item)

    with tempfile.TemporaryDirectory(prefix="triaxis-v329-threshold-rollback-") as td:
        root = Path(td)
        queue_db = root / "queue.sqlite"
        ledger_db = root / "ledger.sqlite"
        head_dbs = [root / f"head-{suffix}.sqlite" for suffix in ("a", "b", "c")]
        provider_db = root / "provider.sqlite"
        witness_db = root / "completion-witness.sqlite"

        queue_snapshot = root / "queue.pre_effect.sqlite"
        ledger_snapshot = root / "ledger.pre_effect.sqlite"
        head_snapshots = [root / f"head-{suffix}.pre_effect.sqlite" for suffix in ("a", "b", "c")]
        provider_snapshot = root / "provider.pre_effect.sqlite"
        witness_snapshot = root / "completion-witness.pre_effect.sqlite"

        queue = SQLiteDurableDispatchQueue(queue_db)
        queue.enqueue(item)
        queue.close()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(ledger_db, ids))
            heads = [stack.enter_context(open_head(path, ids, index)) for index, path in enumerate(head_dbs)]
            stack.enter_context(open_provider(provider_db, ids))
            stack.enter_context(open_witness(witness_db, ids))
            anchor_heads(heads, ledger, 1)
            verify_quorum(heads, ledger, ids, 1, "initial")

        snapshot_file(queue_db, queue_snapshot)
        snapshot_file(ledger_db, ledger_snapshot)
        for source, snapshot in zip(head_dbs, head_snapshots, strict=True):
            snapshot_file(source, snapshot)
        snapshot_file(provider_db, provider_snapshot)
        snapshot_file(witness_db, witness_snapshot)

        # Complete one stable effect across every v3.29 state domain.
        with ExitStack() as stack:
            queue = SQLiteDurableDispatchQueue(queue_db)
            stack.callback(queue.close)
            ledger = stack.enter_context(open_ledger(ledger_db, ids))
            heads = [stack.enter_context(open_head(path, ids, index)) for index, path in enumerate(head_dbs)]
            provider = stack.enter_context(open_provider(provider_db, ids))
            witness = stack.enter_context(open_witness(witness_db, ids))
            first = claim_and_start(
                queue=queue,
                ledger=ledger,
                heads=heads,
                ids=ids,
                item=item,
                intent=intent,
                label="first",
                tick=2,
            )
            request_id = "provider-request:v329:first"
            witness_reservation = witness.reserve(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id=request_id,
                now_tick=4,
            )
            provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id=request_id,
                now_tick=4,
            )
            provider_completed = provider.record_outcome(
                effect_id=intent["effect_id"],
                provider_request_id=request_id,
                outcome="COMPLETED",
                provider_response_sha256=E,
                evidence_sha256=F,
                now_tick=5,
            )
            provider_receipt = provider.issue_outcome_receipt(
                effect_id=intent["effect_id"], issued_at=5, valid_until=50
            )
            witness_completed = witness.record_provider_outcome(
                provider_receipt,
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                evaluation_tick=5,
            )
            ledger_completed = ledger.record_outcome(
                intent["effect_id"],
                attempt_id="attempt:first",
                dispatch_id=first["claim"]["dispatch_id"],
                outcome="COMPLETED",
                evidence_sha256=F,
                now_tick=5,
            )
            anchor_heads(heads, ledger, 5)
            verify_quorum(heads, ledger, ids, 5, "first:completed")
            queue.acknowledge_persisted(
                item["queue_id"],
                claim_id="claim:first",
                dispatch_id=first["claim"]["dispatch_id"],
                persisted_receipt_sha256=ledger_completed["signed_receipt"]["inner_contract"]["event_sha256"],
                now_tick=5,
            )

            ledger_block = ledger.reserve(
                intent,
                attempt_id="attempt:current-control",
                dispatch_id=canonical_sha256({"dispatch": "current-control"}),
                now_tick=6,
            )
            provider_block = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v329:current-control",
                now_tick=6,
            )
            witness_block = witness.reserve(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id="provider-request:v329:current-control",
                now_tick=6,
            )
            current_quorum = verify_quorum(heads, ledger, ids, 6, "current-control")
            row1_pass = (
                ledger_block["status"] == "BLOCK"
                and ledger_block.get("current_state") == "COMPLETED"
                and provider_block["external_effect_permitted"] is False
                and witness_block["external_effect_permitted"] is False
                and current_quorum["status"] == "PASS"
            )
            rows.append(
                {
                    "case_id": "V329RB01_CURRENT_ALL_DOMAINS_BLOCK_COMPLETED_EFFECT",
                    "same_effect_id": provider_completed["effect"]["effect_id"] == intent["effect_id"],
                    "witness_reserved_before_provider": witness_reservation["effect"]["state"] == "RESERVED",
                    "witness_final_state": witness_completed["effect"]["state"],
                    "ledger_state": ledger_block.get("current_state"),
                    "provider_external_effect_permitted": provider_block["external_effect_permitted"],
                    "witness_external_effect_permitted": witness_block["external_effect_permitted"],
                    "head_quorum_status": current_quorum["status"],
                    "status": "PASS" if row1_pass else "FAIL",
                }
            )
            first_dispatch_id = first["claim"]["dispatch_id"]

        # Roll back queue, ledger and provider only. Current head quorum and
        # current completion witness must independently retain the block.
        restore_file(queue_snapshot, queue_db)
        restore_file(ledger_snapshot, ledger_db)
        restore_file(provider_snapshot, provider_db)
        with ExitStack() as stack:
            queue = SQLiteDurableDispatchQueue(queue_db)
            stack.callback(queue.close)
            ledger = stack.enter_context(open_ledger(ledger_db, ids))
            heads = [stack.enter_context(open_head(path, ids, index)) for index, path in enumerate(head_dbs)]
            provider = stack.enter_context(open_provider(provider_db, ids))
            witness = stack.enter_context(open_witness(witness_db, ids))
            claim = queue.claim_next(
                thread_id=item["thread_id"],
                thread_idle=True,
                claim_id="claim:partial-rollback",
                now_tick=10,
            )["claim"]
            quorum_block_code = None
            try:
                verify_quorum(heads, ledger, ids, 10, "partial-rollback")
            except ExecutionLedgerHeadQuorumError as exc:
                quorum_block_code = exc.code
            provider_after_rollback = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v329:partial-rollback",
                now_tick=10,
            )
            witness_after_rollback = witness.reserve(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id="provider-request:v329:partial-rollback",
                now_tick=10,
            )
            row2_pass = (
                claim["dispatch_id"] != first_dispatch_id
                and quorum_block_code == "execution_ledger_rollback_or_fork_detected"
                and provider_after_rollback["external_effect_permitted"] is True
                and witness_after_rollback["external_effect_permitted"] is False
                and witness_after_rollback["effect"]["state"] == "COMPLETED"
            )
            rows.append(
                {
                    "case_id": "V329RB02_CURRENT_QUORUM_AND_WITNESS_BLOCK_LOCAL_PROVIDER_ROLLBACK",
                    "new_dispatch_id": claim["dispatch_id"] != first_dispatch_id,
                    "head_quorum_block_code": quorum_block_code,
                    "rolled_back_provider_external_effect_permitted": provider_after_rollback[
                        "external_effect_permitted"
                    ],
                    "current_completion_witness_state": witness_after_rollback["effect"]["state"],
                    "completion_witness_external_effect_permitted": witness_after_rollback[
                        "external_effect_permitted"
                    ],
                    "status": "PASS" if row2_pass else "FAIL",
                }
            )

        # Roll back every local effect-state domain plus a threshold (A/B) of
        # head authorities. Leave C current. The rolled-back 2-of-3 majority can
        # now attest the old chain and the rolled-back completion memory permits.
        restore_file(queue_snapshot, queue_db)
        restore_file(ledger_snapshot, ledger_db)
        restore_file(provider_snapshot, provider_db)
        restore_file(witness_snapshot, witness_db)
        restore_file(head_snapshots[0], head_dbs[0])
        restore_file(head_snapshots[1], head_dbs[1])

        with ExitStack() as stack:
            queue = SQLiteDurableDispatchQueue(queue_db)
            stack.callback(queue.close)
            ledger = stack.enter_context(open_ledger(ledger_db, ids))
            heads = [stack.enter_context(open_head(path, ids, index)) for index, path in enumerate(head_dbs)]
            provider = stack.enter_context(open_provider(provider_db, ids))
            witness = stack.enter_context(open_witness(witness_db, ids))
            compromised = claim_and_start(
                queue=queue,
                ledger=ledger,
                heads=heads,
                ids=ids,
                item=item,
                intent=intent,
                label="threshold-rollback",
                tick=20,
            )
            provider_after_threshold_rollback = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v329:threshold-rollback",
                now_tick=22,
            )
            witness_after_threshold_rollback = witness.reserve(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id="provider-request:v329:threshold-rollback",
                now_tick=22,
            )
            stale_current_authority_blocked = compromised["anchor_rows"][2]["status"] == "BLOCK"
            duplicate_permitted = (
                compromised["quorum_before"]["status"] == "PASS"
                and compromised["reservation"]["status"] == "PASS"
                and compromised["quorum_after"]["status"] == "PASS"
                and provider_after_threshold_rollback["external_effect_permitted"] is True
                and witness_after_threshold_rollback["external_effect_permitted"] is True
            )
            rows.append(
                {
                    "case_id": "V329RB03_THRESHOLD_AND_COMPLETION_WITNESS_ROLLBACK_REVIVES_EFFECT",
                    "same_effect_id": compromised["reservation"]["effect"]["effect_id"]
                    == intent["effect_id"],
                    "new_dispatch_id": compromised["claim"]["dispatch_id"] != first_dispatch_id,
                    "quorum_before_status": compromised["quorum_before"]["status"],
                    "quorum_after_status": compromised["quorum_after"]["status"],
                    "rolled_back_majority_anchor_pass_count": sum(
                        row["status"] == "PASS" for row in compromised["anchor_rows"]
                    ),
                    "current_minority_authority_rejected_fork": stale_current_authority_blocked,
                    "rolled_back_provider_external_effect_permitted": provider_after_threshold_rollback[
                        "external_effect_permitted"
                    ],
                    "rolled_back_completion_witness_external_effect_permitted": witness_after_threshold_rollback[
                        "external_effect_permitted"
                    ],
                    "expected_secure_result": "BLOCK_OR_INDEPENDENT_IMMUTABLE_COMPLETION_PROOF",
                    "duplicate_effect_risk": duplicate_permitted,
                    "status": "FAIL_EXPECTED" if duplicate_permitted else "PASS",
                }
            )

    boundary_confirmed = (
        rows[0]["status"] == "PASS"
        and rows[1]["status"] == "PASS"
        and rows[2]["status"] == "FAIL_EXPECTED"
    )
    return {
        "protocol_id": "TRIAXIS_v3.29_POSTCOMMIT_THRESHOLD_AND_COMPLETION_WITNESS_ROLLBACK_BOUNDARY",
        "exact_subject_tag": SUBJECT_TAG,
        "exact_subject_commit": git_subject_commit(),
        "status": "BOUNDARY_CONFIRMED" if boundary_confirmed else "UNEXPECTED",
        "claim": (
            "A current 2-of-3 execution-head quorum detects local ledger rollback and a current external "
            "completion witness blocks provider-state rollback. Coordinated rollback or compromise of a "
            "threshold of head authorities together with the completion witness and provider state can "
            "recreate a valid old quorum and revive the same completed stable effect."
        ),
        "required_next_control": [
            "independently administered completion-witness quorum across separate rollback domains",
            "provider-native immutable idempotency keyed by stable effect_id",
            "external append-only or WORM completion receipts anchored outside the quorum operators",
            "monotonic KMS/HSM or hardware-backed anti-rollback counters",
            "public transparency or independent auditor checkpoint for execution and completion heads",
        ],
        "authority_granted": False,
        "production_qualified": False,
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    result = run()
    path = Path(
        "evidence/TRIAXIS_v3.29_POSTCOMMIT_THRESHOLD_AND_COMPLETION_WITNESS_ROLLBACK_BOUNDARY.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
