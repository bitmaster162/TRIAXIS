from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from validation.execution_head_quorum_completion_witness.run_v329_postcommit_threshold_and_completion_witness_rollback import (
    E,
    F,
    PAYLOAD_SHA256,
    PROVIDER_DOMAIN,
    PROVIDER_ID,
    PROVIDER_SERVICE_ID,
    PROVIDER_SIGNER_ID,
    anchor_heads,
    claim_and_start,
    execution_intent,
    identities as base_identities,
    open_head,
    open_ledger,
    open_provider,
    queued_item,
    restore_file,
    snapshot_file,
    verify_quorum,
)
from triaxis.completion_witness_quorum import (
    CompletionWitnessQuorumError,
    make_completion_witness_quorum_config,
    verify_completion_witness_quorum,
)
from triaxis.completion_worm_anchor import (
    CompletionWORMAnchorError,
    SQLiteCompletionWORMAnchor,
    verify_completion_worm_anchor_status,
)
from triaxis.crypto_trust import (
    PURPOSE_COMPLETION_WORM_ANCHOR,
    PURPOSE_EXTERNAL_COMPLETION_WITNESS,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.external_completion_witness import SQLiteExternalCompletionWitness
from triaxis.harness_durability_v3 import SQLiteDurableDispatchQueue
from triaxis.integrity import canonical_sha256
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

SUBJECT_TAG = "TRIAXIS-v3.30-RC1-COMPLETION-WITNESS-QUORUM-WORM-ANCHOR"
ANCHOR_ID = "completion-worm-anchor:v330:rollback-boundary"
ANCHOR_AUTHORITY_ID = "authority:completion-worm-anchor:v330:rollback-boundary"
ANCHOR_SERVICE_ID = "service:completion-worm-anchor:v330:rollback-boundary"
ANCHOR_SIGNER_ID = "signer:completion-worm-anchor:v330:rollback-boundary"
ANCHOR_DOMAIN = "domain:completion-worm-anchor:v330:rollback-boundary"


def identities() -> dict[str, Any]:
    ids = base_identities()
    rows: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for suffix in ("a", "b", "c"):
        pair = generate_ed25519_keypair()
        row = {
            "witness_id": f"completion-witness:v330:rollback-boundary:{suffix}",
            "authority_id": f"authority:completion-witness:v330:rollback-boundary:{suffix}",
            "service_id": f"service:completion-witness:v330:rollback-boundary:{suffix}",
            "key_id": f"key:completion-witness:v330:rollback-boundary:{suffix}",
            "signer_id": f"signer:completion-witness:v330:rollback-boundary:{suffix}",
            "trust_domain": f"domain:completion-witness:v330:rollback-boundary:{suffix}",
            "pair": pair,
        }
        rows.append(row)
        records.append(
            make_trust_key_record(
                key_id=row["key_id"],
                signer_id=row["signer_id"],
                trust_domain=row["trust_domain"],
                public_key_b64=pair["public_key_b64"],
                purposes=[PURPOSE_EXTERNAL_COMPLETION_WITNESS],
                valid_from=0,
                valid_until=100_000,
            )
        )
    anchor_pair = generate_ed25519_keypair()
    anchor_record = make_trust_key_record(
        key_id="key:completion-worm-anchor:v330:rollback-boundary",
        signer_id=ANCHOR_SIGNER_ID,
        trust_domain=ANCHOR_DOMAIN,
        public_key_b64=anchor_pair["public_key_b64"],
        purposes=[PURPOSE_COMPLETION_WORM_ANCHOR],
        valid_from=0,
        valid_until=100_000,
    )
    ids.update(
        {
            "completion_rows": rows,
            "completion_registry": TrustKeyRegistry(records),
            "anchor_pair": anchor_pair,
            "anchor_registry": TrustKeyRegistry([anchor_record]),
        }
    )
    return ids


def open_witness(path: Path, ids: dict[str, Any], index: int) -> SQLiteExternalCompletionWitness:
    row = ids["completion_rows"][index]
    return SQLiteExternalCompletionWitness(
        path,
        witness_id=row["witness_id"],
        authority_id=row["authority_id"],
        service_id=row["service_id"],
        key_id=row["key_id"],
        signer_id=row["signer_id"],
        trust_domain=row["trust_domain"],
        private_key_b64=row["pair"]["private_key_b64"],
        receipt_ttl=100,
    )


def open_anchor(path: Path, ids: dict[str, Any]) -> SQLiteCompletionWORMAnchor:
    return SQLiteCompletionWORMAnchor(
        path,
        anchor_id=ANCHOR_ID,
        authority_id=ANCHOR_AUTHORITY_ID,
        service_id=ANCHOR_SERVICE_ID,
        provider_id=PROVIDER_ID,
        provider_service_id=PROVIDER_SERVICE_ID,
        key_id="key:completion-worm-anchor:v330:rollback-boundary",
        signer_id=ANCHOR_SIGNER_ID,
        trust_domain=ANCHOR_DOMAIN,
        private_key_b64=ids["anchor_pair"]["private_key_b64"],
        receipt_ttl=100,
    )


def completion_config(ids: dict[str, Any]) -> dict[str, Any]:
    rows = [
        {
            field: row[field]
            for field in (
                "witness_id",
                "authority_id",
                "service_id",
                "signer_id",
                "key_id",
                "trust_domain",
            )
        }
        for row in ids["completion_rows"]
    ]
    return make_completion_witness_quorum_config(
        config_id="completion-witness-quorum:v330:rollback-boundary",
        witness_set_id="completion-witness-set:v330:rollback-boundary",
        provider_id=PROVIDER_ID,
        provider_service_id=PROVIDER_SERVICE_ID,
        threshold=2,
        witnesses=rows,
        valid_from=0,
        valid_until=100_000,
    )


def completion_quorum(
    witnesses: list[SQLiteExternalCompletionWitness],
    indexes: list[int],
    ids: dict[str, Any],
    effect_id: str,
    now_tick: int,
    suffix: str,
) -> dict[str, Any]:
    session = VerifierFreshnessSession.create(
        f"verifier:v330:rollback-boundary:completion:{suffix}", 0
    )
    with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
        challenge = challenges.issue(now_tick, now_tick + 50)
        statuses = [
            witnesses[index].issue_status(
                effect_id=effect_id,
                expected_payload_sha256=PAYLOAD_SHA256,
                expected_provider_id=PROVIDER_ID,
                expected_provider_service_id=PROVIDER_SERVICE_ID,
                challenge=challenge,
                verifier_id=session.verifier_id,
                verifier_epoch_sha256=session.epoch_sha256,
                requested_at=now_tick,
                issued_at=now_tick,
                valid_until=now_tick + 20,
            )
            for index in indexes
        ]
        config = completion_config(ids)
        return verify_completion_witness_quorum(
            statuses,
            registry=ids["completion_registry"],
            quorum_config=config,
            expected_quorum_config_sha256=config["config_sha256"],
            expected_effect_id=effect_id,
            expected_payload_sha256=PAYLOAD_SHA256,
            expected_provider_id=PROVIDER_ID,
            expected_provider_service_id=PROVIDER_SERVICE_ID,
            challenge_ledger=challenges,
            expected_challenge=challenge,
            evaluation_tick=now_tick,
        )


def anchor_status(
    anchor: SQLiteCompletionWORMAnchor,
    ids: dict[str, Any],
    effect_id: str,
    now_tick: int,
    suffix: str,
) -> dict[str, Any]:
    session = VerifierFreshnessSession.create(
        f"verifier:v330:rollback-boundary:anchor:{suffix}", 0
    )
    with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
        challenge = challenges.issue(now_tick, now_tick + 50)
        signed = anchor.issue_status(
            effect_id=effect_id,
            expected_payload_sha256=PAYLOAD_SHA256,
            challenge=challenge,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            requested_at=now_tick,
            issued_at=now_tick,
            valid_until=now_tick + 20,
        )
        return verify_completion_worm_anchor_status(
            signed,
            registry=ids["anchor_registry"],
            expected_anchor_id=ANCHOR_ID,
            expected_authority_id=ANCHOR_AUTHORITY_ID,
            expected_service_id=ANCHOR_SERVICE_ID,
            expected_signer_id=ANCHOR_SIGNER_ID,
            expected_trust_domain=ANCHOR_DOMAIN,
            expected_effect_id=effect_id,
            expected_payload_sha256=PAYLOAD_SHA256,
            expected_provider_id=PROVIDER_ID,
            expected_provider_service_id=PROVIDER_SERVICE_ID,
            challenge_ledger=challenges,
            expected_challenge=challenge,
            evaluation_tick=now_tick,
        )


def exact_subject_commit() -> str:
    return subprocess.check_output(
        ["git", "rev-list", "-n", "1", SUBJECT_TAG], text=True
    ).strip()


def run() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    ids = identities()
    item = queued_item()
    intent = execution_intent(item)

    with tempfile.TemporaryDirectory(prefix="triaxis-v330-threshold-anchor-rollback-") as td:
        root = Path(td)
        queue_db = root / "queue.sqlite"
        ledger_db = root / "ledger.sqlite"
        head_dbs = [root / f"execution-head-{suffix}.sqlite" for suffix in ("a", "b", "c")]
        provider_db = root / "provider.sqlite"
        witness_dbs = [root / f"completion-witness-{suffix}.sqlite" for suffix in ("a", "b", "c")]
        anchor_db = root / "completion-worm-anchor.sqlite"

        queue_snapshot = root / "queue.pre_effect.sqlite"
        ledger_snapshot = root / "ledger.pre_effect.sqlite"
        head_snapshots = [root / f"execution-head-{suffix}.pre_effect.sqlite" for suffix in ("a", "b", "c")]
        provider_snapshot = root / "provider.pre_effect.sqlite"
        witness_snapshots = [root / f"completion-witness-{suffix}.pre_effect.sqlite" for suffix in ("a", "b", "c")]
        anchor_snapshot = root / "completion-worm-anchor.pre_effect.sqlite"

        queue = SQLiteDurableDispatchQueue(queue_db)
        queue.enqueue(item)
        queue.close()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(ledger_db, ids))
            heads = [
                stack.enter_context(open_head(path, ids, index))
                for index, path in enumerate(head_dbs)
            ]
            stack.enter_context(open_provider(provider_db, ids))
            for index, path in enumerate(witness_dbs):
                stack.enter_context(open_witness(path, ids, index))
            stack.enter_context(open_anchor(anchor_db, ids))
            anchor_heads(heads, ledger, 1)
            verify_quorum(heads, ledger, ids, 1, "v330:initial")

        snapshot_file(queue_db, queue_snapshot)
        snapshot_file(ledger_db, ledger_snapshot)
        for source, snapshot in zip(head_dbs, head_snapshots, strict=True):
            snapshot_file(source, snapshot)
        snapshot_file(provider_db, provider_snapshot)
        for source, snapshot in zip(witness_dbs, witness_snapshots, strict=True):
            snapshot_file(source, snapshot)
        snapshot_file(anchor_db, anchor_snapshot)

        # Complete one stable effect across all current v3.30 state domains.
        with ExitStack() as stack:
            queue = SQLiteDurableDispatchQueue(queue_db)
            stack.callback(queue.close)
            ledger = stack.enter_context(open_ledger(ledger_db, ids))
            heads = [
                stack.enter_context(open_head(path, ids, index))
                for index, path in enumerate(head_dbs)
            ]
            provider = stack.enter_context(open_provider(provider_db, ids))
            witnesses = [
                stack.enter_context(open_witness(path, ids, index))
                for index, path in enumerate(witness_dbs)
            ]
            anchor = stack.enter_context(open_anchor(anchor_db, ids))
            first = claim_and_start(
                queue=queue,
                ledger=ledger,
                heads=heads,
                ids=ids,
                item=item,
                intent=intent,
                label="v330:first",
                tick=2,
            )
            request_id = "provider-request:v330:first"
            for witness in witnesses:
                witness.reserve(
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
            provider.record_outcome(
                effect_id=intent["effect_id"],
                provider_request_id=request_id,
                outcome="COMPLETED",
                provider_response_sha256=E,
                evidence_sha256=F,
                now_tick=5,
            )
            receipt = provider.issue_outcome_receipt(
                effect_id=intent["effect_id"], issued_at=5, valid_until=50
            )
            for witness in witnesses:
                witness.record_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=5,
                )
            anchor.ingest_provider_outcome(
                receipt,
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                evaluation_tick=5,
            )
            ledger_completed = ledger.record_outcome(
                intent["effect_id"],
                attempt_id="attempt:v330:first",
                dispatch_id=first["claim"]["dispatch_id"],
                outcome="COMPLETED",
                evidence_sha256=F,
                now_tick=5,
            )
            anchor_heads(heads, ledger, 5)
            verify_quorum(heads, ledger, ids, 5, "v330:first:completed")
            queue.acknowledge_persisted(
                item["queue_id"],
                claim_id="claim:v330:first",
                dispatch_id=first["claim"]["dispatch_id"],
                persisted_receipt_sha256=ledger_completed["signed_receipt"]["inner_contract"]["event_sha256"],
                now_tick=5,
            )
            first_dispatch_id = first["claim"]["dispatch_id"]

            provider_block = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v330:current-control",
                now_tick=6,
            )
            completion_block_code = None
            try:
                completion_quorum(witnesses, [0, 1, 2], ids, intent["effect_id"], 6, "current")
            except CompletionWitnessQuorumError as exc:
                completion_block_code = exc.code
            anchor_block_code = None
            try:
                anchor_status(anchor, ids, intent["effect_id"], 6, "current")
            except CompletionWORMAnchorError as exc:
                anchor_block_code = exc.code
            current_execution_quorum = verify_quorum(heads, ledger, ids, 6, "v330:current")
            row1_pass = (
                provider_block["external_effect_permitted"] is False
                and completion_block_code == "blocking_completion_witness_minority"
                and anchor_block_code == "worm_anchor_state_blocks_retry"
                and current_execution_quorum["status"] == "PASS"
            )
            rows.append(
                {
                    "case_id": "V330RB01_CURRENT_PROVIDER_QUORUM_AND_ANCHOR_BLOCK_COMPLETED_EFFECT",
                    "same_effect_id": provider_block["effect"]["effect_id"] == intent["effect_id"],
                    "provider_external_effect_permitted": provider_block["external_effect_permitted"],
                    "completion_quorum_block_code": completion_block_code,
                    "anchor_block_code": anchor_block_code,
                    "execution_head_quorum_status": current_execution_quorum["status"],
                    "status": "PASS" if row1_pass else "FAIL",
                }
            )

        # Roll back provider plus threshold completion witnesses A/B. Omit the
        # current C witness: old A/B can form permissive quorum, but the current
        # anchor still preserves COMPLETED and blocks.
        restore_file(provider_snapshot, provider_db)
        restore_file(witness_snapshots[0], witness_dbs[0])
        restore_file(witness_snapshots[1], witness_dbs[1])
        with ExitStack() as stack:
            provider = stack.enter_context(open_provider(provider_db, ids))
            witnesses = [
                stack.enter_context(open_witness(path, ids, index))
                for index, path in enumerate(witness_dbs)
            ]
            anchor = stack.enter_context(open_anchor(anchor_db, ids))
            provider_after = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v330:partial-rollback",
                now_tick=10,
            )
            permissive_quorum = completion_quorum(
                witnesses, [0, 1], ids, intent["effect_id"], 10, "partial-rollback"
            )
            anchor_block_code = None
            try:
                anchor_status(anchor, ids, intent["effect_id"], 10, "partial-rollback")
            except CompletionWORMAnchorError as exc:
                anchor_block_code = exc.code
            row2_pass = (
                provider_after["external_effect_permitted"] is True
                and permissive_quorum["state"] == "ABSENT"
                and permissive_quorum["member_count"] == 2
                and anchor_block_code == "worm_anchor_state_blocks_retry"
            )
            rows.append(
                {
                    "case_id": "V330RB02_CURRENT_ANCHOR_BLOCKS_PROVIDER_AND_WITNESS_THRESHOLD_ROLLBACK",
                    "rolled_back_provider_external_effect_permitted": provider_after["external_effect_permitted"],
                    "rolled_back_threshold_quorum_state": permissive_quorum["state"],
                    "rolled_back_threshold_member_count": permissive_quorum["member_count"],
                    "current_anchor_block_code": anchor_block_code,
                    "current_completion_minority_omitted": True,
                    "status": "PASS" if row2_pass else "FAIL",
                }
            )

        # Roll back the anchor too, but include the still-current C witness. The
        # blocking-minority rule must prevent two rolled-back ABSENT witnesses
        # from laundering the current COMPLETED statement.
        restore_file(anchor_snapshot, anchor_db)
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_witness(path, ids, index))
                for index, path in enumerate(witness_dbs)
            ]
            anchor = stack.enter_context(open_anchor(anchor_db, ids))
            completion_block_code = None
            try:
                completion_quorum(witnesses, [0, 1, 2], ids, intent["effect_id"], 12, "minority-veto")
            except CompletionWitnessQuorumError as exc:
                completion_block_code = exc.code
            anchor_permit = anchor_status(anchor, ids, intent["effect_id"], 12, "rolled-back-anchor")
            row3_pass = (
                completion_block_code == "blocking_completion_witness_minority"
                and anchor_permit["external_effect_permitted"] is True
                and anchor_permit["worm_anchor_status"]["state"] == "ABSENT"
            )
            rows.append(
                {
                    "case_id": "V330RB03_CURRENT_COMPLETION_MINORITY_VETOES_ROLLED_BACK_ANCHOR",
                    "completion_quorum_block_code": completion_block_code,
                    "rolled_back_anchor_state": anchor_permit["worm_anchor_status"]["state"],
                    "rolled_back_anchor_external_effect_permitted": anchor_permit["external_effect_permitted"],
                    "status": "PASS" if row3_pass else "FAIL",
                }
            )

        # Coordinated rollback of queue, ledger, provider, head threshold A/B,
        # completion-witness threshold A/B and the anchor. Current execution-head
        # C rejects the fork. Current completion witness C would veto, but is
        # omitted as unavailable. The rolled-back threshold plus anchor recreates
        # a complete permissive old view for the same stable effect.
        restore_file(queue_snapshot, queue_db)
        restore_file(ledger_snapshot, ledger_db)
        restore_file(provider_snapshot, provider_db)
        restore_file(head_snapshots[0], head_dbs[0])
        restore_file(head_snapshots[1], head_dbs[1])
        restore_file(witness_snapshots[0], witness_dbs[0])
        restore_file(witness_snapshots[1], witness_dbs[1])
        restore_file(anchor_snapshot, anchor_db)

        with ExitStack() as stack:
            queue = SQLiteDurableDispatchQueue(queue_db)
            stack.callback(queue.close)
            ledger = stack.enter_context(open_ledger(ledger_db, ids))
            heads = [
                stack.enter_context(open_head(path, ids, index))
                for index, path in enumerate(head_dbs)
            ]
            provider = stack.enter_context(open_provider(provider_db, ids))
            witnesses = [
                stack.enter_context(open_witness(path, ids, index))
                for index, path in enumerate(witness_dbs)
            ]
            anchor = stack.enter_context(open_anchor(anchor_db, ids))
            compromised = claim_and_start(
                queue=queue,
                ledger=ledger,
                heads=heads,
                ids=ids,
                item=item,
                intent=intent,
                label="v330:coordinated-rollback",
                tick=20,
            )
            provider_after = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v330:coordinated-rollback",
                now_tick=22,
            )
            completion_after = completion_quorum(
                witnesses, [0, 1], ids, intent["effect_id"], 22, "coordinated-rollback"
            )
            anchor_after = anchor_status(
                anchor, ids, intent["effect_id"], 22, "coordinated-rollback"
            )
            current_minority_block_code = None
            try:
                completion_quorum(
                    witnesses, [2], ids, intent["effect_id"], 23, "current-minority-only"
                )
            except CompletionWitnessQuorumError as exc:
                current_minority_block_code = exc.code
            current_execution_minority_rejected = compromised["anchor_rows"][2]["status"] == "BLOCK"
            duplicate_permitted = (
                compromised["quorum_before"]["status"] == "PASS"
                and compromised["reservation"]["status"] == "PASS"
                and compromised["quorum_after"]["status"] == "PASS"
                and provider_after["external_effect_permitted"] is True
                and completion_after["state"] == "ABSENT"
                and completion_after["member_count"] == 2
                and anchor_after["external_effect_permitted"] is True
                and anchor_after["worm_anchor_status"]["state"] == "ABSENT"
            )
            rows.append(
                {
                    "case_id": "V330RB04_THRESHOLD_AND_ANCHOR_ROLLBACK_WITH_OMITTED_MINORITIES_REVIVES_EFFECT",
                    "same_effect_id": compromised["reservation"]["effect"]["effect_id"] == intent["effect_id"],
                    "new_dispatch_id": compromised["claim"]["dispatch_id"] != first_dispatch_id,
                    "execution_quorum_before_status": compromised["quorum_before"]["status"],
                    "execution_quorum_after_status": compromised["quorum_after"]["status"],
                    "current_execution_minority_rejected_fork": current_execution_minority_rejected,
                    "rolled_back_provider_external_effect_permitted": provider_after["external_effect_permitted"],
                    "rolled_back_completion_quorum_state": completion_after["state"],
                    "rolled_back_completion_quorum_member_count": completion_after["member_count"],
                    "current_completion_minority_omitted": True,
                    "current_completion_minority_if_queried_block_code": current_minority_block_code,
                    "rolled_back_anchor_state": anchor_after["worm_anchor_status"]["state"],
                    "rolled_back_anchor_external_effect_permitted": anchor_after["external_effect_permitted"],
                    "expected_secure_result": "BLOCK_OR_INDEPENDENT_IMMUTABLE_EXTERNAL_COMPLETION_PROOF",
                    "duplicate_effect_risk": duplicate_permitted,
                    "status": "FAIL_EXPECTED" if duplicate_permitted else "PASS",
                }
            )

    boundary_confirmed = (
        len(rows) == 4
        and rows[0]["status"] == "PASS"
        and rows[1]["status"] == "PASS"
        and rows[2]["status"] == "PASS"
        and rows[3]["status"] == "FAIL_EXPECTED"
    )
    return {
        "protocol_id": "TRIAXIS_v3.30_POSTCOMMIT_COMPLETION_THRESHOLD_AND_WORM_ANCHOR_ROLLBACK_BOUNDARY",
        "exact_subject_tag": SUBJECT_TAG,
        "exact_subject_commit": exact_subject_commit(),
        "status": "BOUNDARY_CONFIRMED" if boundary_confirmed else "UNEXPECTED",
        "claim": (
            "A current logical completion anchor blocks rollback of provider and a completion-witness "
            "threshold. A valid current blocking minority blocks a rolled-back anchor when included. "
            "Coordinated rollback of provider, both quorum thresholds and the logical anchor, combined "
            "with omission of the current completion minority, can recreate a permissive old view and "
            "revive the same completed stable effect."
        ),
        "required_next_control": [
            "physical append-only or WORM completion receipts outside all quorum administrators",
            "provider-native immutable idempotency keyed by stable effect_id",
            "independently administered transparency checkpoint for completion heads",
            "KMS/HSM or hardware-backed monotonic anti-rollback state",
            "availability policy that treats omitted configured blocking witnesses as non-permissive",
            "real multi-host and multi-administrator rollback evidence",
        ],
        "authority_granted": False,
        "production_qualified": False,
        "physical_worm_established": False,
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    result = run()
    path = Path(
        "evidence/TRIAXIS_v3.30_POSTCOMMIT_COMPLETION_THRESHOLD_AND_WORM_ANCHOR_ROLLBACK_BOUNDARY.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
