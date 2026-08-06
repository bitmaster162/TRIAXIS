from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any

from validation.completion_witness_quorum_worm_anchor.run_v330_postcommit_threshold_and_worm_anchor_rollback import (
    ANCHOR_AUTHORITY_ID,
    ANCHOR_DOMAIN,
    ANCHOR_ID,
    ANCHOR_SERVICE_ID,
    ANCHOR_SIGNER_ID,
    E,
    F,
    PAYLOAD_SHA256,
    PROVIDER_DOMAIN,
    PROVIDER_ID,
    PROVIDER_SERVICE_ID,
    PROVIDER_SIGNER_ID,
    anchor_heads,
    anchor_status,
    claim_and_start,
    completion_config,
    completion_quorum,
    execution_intent,
    identities as v330_identities,
    open_anchor,
    open_head,
    open_ledger,
    open_provider,
    open_witness,
    queued_item,
    restore_file,
    snapshot_file,
    verify_quorum,
)
from triaxis.completion_availability_control import (
    CompletionAvailabilityError,
    make_completion_availability_policy,
    verify_availability_closed_completion_quorum,
)
from triaxis.completion_immutable_anchor import (
    CompletionImmutableAnchorError,
    FilesystemImmutableCompletionAnchor,
    SQLiteImmutableAnchorCheckpointLedger,
    verify_completion_immutable_anchor_head,
    verify_completion_immutable_anchor_status,
)
from triaxis.completion_worm_anchor import CompletionWORMAnchorError
from triaxis.crypto_trust import (
    PURPOSE_COMPLETION_AVAILABILITY_CONTROL,
    PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.harness_durability_v3 import SQLiteDurableDispatchQueue
from triaxis.integrity import canonical_sha256
from triaxis.trust_registry_quorum import (
    SQLiteEpochChallengeLedger,
    VerifierFreshnessSession,
)

SUBJECT_TAG = (
    "TRIAXIS-v3.31-RC1-AVAILABILITY-CLOSED-COMPLETION-IMMUTABLE-ANCHOR"
)
AVAILABILITY_SIGNER_ID = "signer:completion-availability:v331:rollback-boundary"
AVAILABILITY_DOMAIN = "domain:completion-availability:v331:rollback-boundary"
IMMUTABLE_ANCHOR_ID = "completion-immutable-anchor:v331:rollback-boundary"
IMMUTABLE_AUTHORITY_ID = "authority:completion-immutable-anchor:v331:rollback-boundary"
IMMUTABLE_SERVICE_ID = "service:completion-immutable-anchor:v331:rollback-boundary"
IMMUTABLE_SIGNER_ID = "signer:completion-immutable-anchor:v331:rollback-boundary"
IMMUTABLE_DOMAIN = "domain:completion-immutable-anchor:v331:rollback-boundary"
RETENTION_POLICY_ID = "retention:completion:v331:rollback-boundary"


def identities() -> dict[str, Any]:
    ids = v330_identities()
    availability_pair = generate_ed25519_keypair()
    immutable_pair = generate_ed25519_keypair()
    ids.update(
        {
            "availability_pair": availability_pair,
            "availability_registry": TrustKeyRegistry(
                [
                    make_trust_key_record(
                        key_id="key:completion-availability:v331:rollback-boundary",
                        signer_id=AVAILABILITY_SIGNER_ID,
                        trust_domain=AVAILABILITY_DOMAIN,
                        public_key_b64=availability_pair["public_key_b64"],
                        purposes=[PURPOSE_COMPLETION_AVAILABILITY_CONTROL],
                        valid_from=0,
                        valid_until=100_000,
                    )
                ]
            ),
            "immutable_pair": immutable_pair,
            "immutable_registry": TrustKeyRegistry(
                [
                    make_trust_key_record(
                        key_id="key:completion-immutable-anchor:v331:rollback-boundary",
                        signer_id=IMMUTABLE_SIGNER_ID,
                        trust_domain=IMMUTABLE_DOMAIN,
                        public_key_b64=immutable_pair["public_key_b64"],
                        purposes=[PURPOSE_COMPLETION_IMMUTABLE_ANCHOR],
                        valid_from=0,
                        valid_until=100_000,
                    )
                ]
            ),
        }
    )
    return ids


def availability_policy(ids: dict[str, Any]) -> dict[str, Any]:
    config = completion_config(ids)
    return make_completion_availability_policy(
        policy_id="completion-availability:v331:rollback-boundary",
        completion_quorum_config_sha256=config["config_sha256"],
        risk_class="CRITICAL",
        required_witness_count=len(config["witnesses"]),
        valid_from=0,
        valid_until=100_000,
    )


def open_immutable_anchor(
    root: Path, ids: dict[str, Any]
) -> FilesystemImmutableCompletionAnchor:
    return FilesystemImmutableCompletionAnchor(
        root,
        anchor_id=IMMUTABLE_ANCHOR_ID,
        authority_id=IMMUTABLE_AUTHORITY_ID,
        service_id=IMMUTABLE_SERVICE_ID,
        provider_id=PROVIDER_ID,
        provider_service_id=PROVIDER_SERVICE_ID,
        retention_policy_id=RETENTION_POLICY_ID,
        key_id="key:completion-immutable-anchor:v331:rollback-boundary",
        signer_id=IMMUTABLE_SIGNER_ID,
        trust_domain=IMMUTABLE_DOMAIN,
        private_key_b64=ids["immutable_pair"]["private_key_b64"],
        minimum_retention_ticks=100,
        receipt_ttl=100,
    )


def snapshot_tree(source: Path, snapshot: Path) -> None:
    if snapshot.exists():
        shutil.rmtree(snapshot)
    shutil.copytree(source, snapshot, copy_function=shutil.copy2)


def restore_tree(snapshot: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(snapshot, target, copy_function=shutil.copy2)


def availability_closed_status(
    witnesses: list[Any],
    indexes: list[int],
    ids: dict[str, Any],
    effect_id: str,
    now_tick: int,
    suffix: str,
) -> dict[str, Any]:
    session = VerifierFreshnessSession.create(
        f"verifier:v331:rollback-boundary:availability:{suffix}", 0
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
        policy = availability_policy(ids)
        return verify_availability_closed_completion_quorum(
            statuses,
            registry=ids["completion_registry"],
            quorum_config=config,
            expected_quorum_config_sha256=config["config_sha256"],
            availability_policy=policy,
            expected_availability_policy_sha256=policy["policy_sha256"],
            expected_effect_id=effect_id,
            expected_payload_sha256=PAYLOAD_SHA256,
            expected_provider_id=PROVIDER_ID,
            expected_provider_service_id=PROVIDER_SERVICE_ID,
            challenge_ledger=challenges,
            expected_challenge=challenge,
            evaluation_tick=now_tick,
        )


def immutable_status(
    anchor: FilesystemImmutableCompletionAnchor,
    ids: dict[str, Any],
    effect_id: str,
    now_tick: int,
    suffix: str,
    *,
    checkpoint: SQLiteImmutableAnchorCheckpointLedger | None,
) -> dict[str, Any]:
    session = VerifierFreshnessSession.create(
        f"verifier:v331:rollback-boundary:immutable:{suffix}", 0
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
        return verify_completion_immutable_anchor_status(
            signed,
            registry=ids["immutable_registry"],
            expected_anchor_id=IMMUTABLE_ANCHOR_ID,
            expected_authority_id=IMMUTABLE_AUTHORITY_ID,
            expected_service_id=IMMUTABLE_SERVICE_ID,
            expected_signer_id=IMMUTABLE_SIGNER_ID,
            expected_trust_domain=IMMUTABLE_DOMAIN,
            expected_provider_id=PROVIDER_ID,
            expected_provider_service_id=PROVIDER_SERVICE_ID,
            expected_retention_policy_id=RETENTION_POLICY_ID,
            expected_effect_id=effect_id,
            expected_payload_sha256=PAYLOAD_SHA256,
            challenge_ledger=challenges,
            expected_challenge=challenge,
            evaluation_tick=now_tick,
            checkpoint_ledger=checkpoint,
        )


def verify_immutable_head(
    anchor: FilesystemImmutableCompletionAnchor,
    ids: dict[str, Any],
    now_tick: int,
    checkpoint: SQLiteImmutableAnchorCheckpointLedger,
) -> dict[str, Any]:
    return verify_completion_immutable_anchor_head(
        anchor.head(now_tick=now_tick),
        registry=ids["immutable_registry"],
        expected_anchor_id=IMMUTABLE_ANCHOR_ID,
        expected_authority_id=IMMUTABLE_AUTHORITY_ID,
        expected_service_id=IMMUTABLE_SERVICE_ID,
        expected_signer_id=IMMUTABLE_SIGNER_ID,
        expected_trust_domain=IMMUTABLE_DOMAIN,
        expected_provider_id=PROVIDER_ID,
        expected_provider_service_id=PROVIDER_SERVICE_ID,
        expected_retention_policy_id=RETENTION_POLICY_ID,
        evaluation_tick=now_tick,
        checkpoint_ledger=checkpoint,
        max_head_age=10,
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

    with tempfile.TemporaryDirectory(prefix="triaxis-v331-coordinated-rollback-") as td:
        root = Path(td)
        queue_db = root / "queue.sqlite"
        ledger_db = root / "ledger.sqlite"
        head_dbs = [root / f"execution-head-{suffix}.sqlite" for suffix in ("a", "b", "c")]
        provider_db = root / "provider.sqlite"
        witness_dbs = [root / f"completion-witness-{suffix}.sqlite" for suffix in ("a", "b", "c")]
        logical_anchor_db = root / "completion-worm-anchor.sqlite"
        immutable_root = root / "immutable-anchor"
        checkpoint_db = root / "immutable-anchor-checkpoint.sqlite"

        queue_snapshot = root / "queue.pre-effect.sqlite"
        ledger_snapshot = root / "ledger.pre-effect.sqlite"
        head_snapshots = [root / f"execution-head-{suffix}.pre-effect.sqlite" for suffix in ("a", "b", "c")]
        provider_snapshot = root / "provider.pre-effect.sqlite"
        witness_snapshots = [root / f"completion-witness-{suffix}.pre-effect.sqlite" for suffix in ("a", "b", "c")]
        logical_anchor_snapshot = root / "completion-worm-anchor.pre-effect.sqlite"
        immutable_snapshot = root / "immutable-anchor.pre-effect"
        checkpoint_snapshot = root / "immutable-anchor-checkpoint.pre-effect.sqlite"

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
            stack.enter_context(open_anchor(logical_anchor_db, ids))
            immutable = open_immutable_anchor(immutable_root, ids)
            checkpoint = stack.enter_context(
                SQLiteImmutableAnchorCheckpointLedger(
                    checkpoint_db, anchor_id=IMMUTABLE_ANCHOR_ID
                )
            )
            anchor_heads(heads, ledger, 1)
            verify_quorum(heads, ledger, ids, 1, "v331:initial")
            verify_immutable_head(immutable, ids, 1, checkpoint)

        snapshot_file(queue_db, queue_snapshot)
        snapshot_file(ledger_db, ledger_snapshot)
        for source, snapshot in zip(head_dbs, head_snapshots, strict=True):
            snapshot_file(source, snapshot)
        snapshot_file(provider_db, provider_snapshot)
        for source, snapshot in zip(witness_dbs, witness_snapshots, strict=True):
            snapshot_file(source, snapshot)
        snapshot_file(logical_anchor_db, logical_anchor_snapshot)
        snapshot_tree(immutable_root, immutable_snapshot)
        snapshot_file(checkpoint_db, checkpoint_snapshot)

        # Complete one stable effect across every current v3.31 evidence domain.
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
            logical_anchor = stack.enter_context(open_anchor(logical_anchor_db, ids))
            immutable = open_immutable_anchor(immutable_root, ids)
            checkpoint = stack.enter_context(
                SQLiteImmutableAnchorCheckpointLedger(
                    checkpoint_db, anchor_id=IMMUTABLE_ANCHOR_ID
                )
            )
            first = claim_and_start(
                queue=queue,
                ledger=ledger,
                heads=heads,
                ids=ids,
                item=item,
                intent=intent,
                label="v331:first",
                tick=2,
            )
            request_id = "provider-request:v331:first"
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
                effect_id=intent["effect_id"], issued_at=5, valid_until=500
            )
            for witness in witnesses:
                witness.record_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=5,
                )
            logical_anchor.ingest_provider_outcome(
                receipt,
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                evaluation_tick=5,
            )
            immutable.store_provider_outcome(
                receipt,
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                evaluation_tick=5,
                retention_until_tick=500,
            )
            verify_immutable_head(immutable, ids, 5, checkpoint)
            ledger_completed = ledger.record_outcome(
                intent["effect_id"],
                attempt_id="attempt:v331:first",
                dispatch_id=first["claim"]["dispatch_id"],
                outcome="COMPLETED",
                evidence_sha256=F,
                now_tick=5,
            )
            anchor_heads(heads, ledger, 5)
            verify_quorum(heads, ledger, ids, 5, "v331:first:completed")
            queue.acknowledge_persisted(
                item["queue_id"],
                claim_id="claim:v331:first",
                dispatch_id=first["claim"]["dispatch_id"],
                persisted_receipt_sha256=ledger_completed["signed_receipt"]["inner_contract"]["event_sha256"],
                now_tick=5,
            )
            first_dispatch_id = first["claim"]["dispatch_id"]

            provider_block = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v331:current-control",
                now_tick=6,
            )
            availability_block_code = None
            try:
                availability_closed_status(
                    witnesses, [0, 1, 2], ids, intent["effect_id"], 6, "current"
                )
            except CompletionAvailabilityError as exc:
                availability_block_code = exc.code
            logical_block_code = None
            try:
                anchor_status(logical_anchor, ids, intent["effect_id"], 6, "current")
            except CompletionWORMAnchorError as exc:
                logical_block_code = exc.code
            immutable_block_code = None
            try:
                immutable_status(
                    immutable,
                    ids,
                    intent["effect_id"],
                    6,
                    "current",
                    checkpoint=checkpoint,
                )
            except CompletionImmutableAnchorError as exc:
                immutable_block_code = exc.code
            current_execution_quorum = verify_quorum(
                heads, ledger, ids, 6, "v331:current"
            )
            row1_pass = (
                provider_block["external_effect_permitted"] is False
                and availability_block_code == "blocking_completion_witness_minority"
                and logical_block_code == "worm_anchor_state_blocks_retry"
                and immutable_block_code == "immutable_anchor_state_blocks_retry"
                and current_execution_quorum["status"] == "PASS"
                and checkpoint.snapshot()["sequence"] == 1
            )
            rows.append(
                {
                    "case_id": "V331RB01_CURRENT_PROVIDER_FULL_AVAILABILITY_AND_BOTH_ANCHORS_BLOCK",
                    "same_effect_id": provider_block["effect"]["effect_id"] == intent["effect_id"],
                    "provider_external_effect_permitted": provider_block["external_effect_permitted"],
                    "availability_block_code": availability_block_code,
                    "logical_anchor_block_code": logical_block_code,
                    "immutable_anchor_block_code": immutable_block_code,
                    "immutable_checkpoint_sequence": checkpoint.snapshot()["sequence"],
                    "execution_head_quorum_status": current_execution_quorum["status"],
                    "status": "PASS" if row1_pass else "FAIL",
                }
            )

        # Restore provider plus A/B completion witnesses. The legacy threshold
        # can report ABSENT, but v3.31 refuses the missing configured C witness.
        restore_file(provider_snapshot, provider_db)
        restore_file(witness_snapshots[0], witness_dbs[0])
        restore_file(witness_snapshots[1], witness_dbs[1])
        with ExitStack() as stack:
            provider = stack.enter_context(open_provider(provider_db, ids))
            witnesses = [
                stack.enter_context(open_witness(path, ids, index))
                for index, path in enumerate(witness_dbs)
            ]
            logical_anchor = stack.enter_context(open_anchor(logical_anchor_db, ids))
            immutable = open_immutable_anchor(immutable_root, ids)
            checkpoint = stack.enter_context(
                SQLiteImmutableAnchorCheckpointLedger(
                    checkpoint_db, anchor_id=IMMUTABLE_ANCHOR_ID
                )
            )
            provider_after = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v331:partial-rollback",
                now_tick=10,
            )
            old_threshold = completion_quorum(
                witnesses, [0, 1], ids, intent["effect_id"], 10, "partial-rollback"
            )
            availability_block_code = None
            try:
                availability_closed_status(
                    witnesses, [0, 1], ids, intent["effect_id"], 10, "partial-rollback"
                )
            except CompletionAvailabilityError as exc:
                availability_block_code = exc.code
            immutable_block_code = None
            try:
                immutable_status(
                    immutable,
                    ids,
                    intent["effect_id"],
                    10,
                    "partial-rollback",
                    checkpoint=checkpoint,
                )
            except CompletionImmutableAnchorError as exc:
                immutable_block_code = exc.code
            row2_pass = (
                provider_after["external_effect_permitted"] is True
                and old_threshold["state"] == "ABSENT"
                and old_threshold["member_count"] == 2
                and availability_block_code
                == "completion_availability_witness_set_incomplete"
                and immutable_block_code == "immutable_anchor_state_blocks_retry"
                and logical_anchor.get(intent["effect_id"])["state"] == "COMPLETED"
            )
            rows.append(
                {
                    "case_id": "V331RB02_AVAILABILITY_CLOSED_AND_CURRENT_IMMUTABLE_ANCHOR_BLOCK_PARTIAL_ROLLBACK",
                    "rolled_back_provider_external_effect_permitted": provider_after["external_effect_permitted"],
                    "legacy_threshold_state": old_threshold["state"],
                    "legacy_threshold_member_count": old_threshold["member_count"],
                    "current_required_witness_omitted": True,
                    "availability_block_code": availability_block_code,
                    "immutable_anchor_block_code": immutable_block_code,
                    "current_logical_anchor_state": logical_anchor.get(intent["effect_id"])["state"],
                    "status": "PASS" if row2_pass else "FAIL",
                }
            )

        # Restore the immutable filesystem only. The separately retained
        # verifier checkpoint must reject its lower signed head.
        restore_tree(immutable_snapshot, immutable_root)
        with SQLiteImmutableAnchorCheckpointLedger(
            checkpoint_db, anchor_id=IMMUTABLE_ANCHOR_ID
        ) as checkpoint:
            immutable = open_immutable_anchor(immutable_root, ids)
            checkpoint_block_code = None
            observed_sequence = None
            try:
                observed = verify_immutable_head(immutable, ids, 12, checkpoint)
                observed_sequence = observed["head"]["sequence"]
            except CompletionImmutableAnchorError as exc:
                checkpoint_block_code = exc.code
                observed_sequence = immutable.head(now_tick=12)["inner_contract"]["sequence"]
            row3_pass = (
                checkpoint.snapshot()["sequence"] == 1
                and observed_sequence == 0
                and checkpoint_block_code == "immutable_anchor_checkpoint_rollback"
            )
            rows.append(
                {
                    "case_id": "V331RB03_CURRENT_CHECKPOINT_BLOCKS_IMMUTABLE_ANCHOR_ROLLBACK",
                    "pinned_checkpoint_sequence": checkpoint.snapshot()["sequence"],
                    "rolled_back_anchor_sequence": observed_sequence,
                    "checkpoint_block_code": checkpoint_block_code,
                    "status": "PASS" if row3_pass else "FAIL",
                }
            )

        # Coordinated rollback of every completion-evidence domain and verifier
        # checkpoint. A/B execution-head authorities are also rolled back so the
        # existing 2-of-3 execution quorum can recreate the old view while the
        # current C authority rejects the fork. All completion witnesses are
        # rolled back, so the new all-configured policy has no current minority
        # left to reveal the prior COMPLETED outcome.
        restore_file(queue_snapshot, queue_db)
        restore_file(ledger_snapshot, ledger_db)
        restore_file(provider_snapshot, provider_db)
        restore_file(head_snapshots[0], head_dbs[0])
        restore_file(head_snapshots[1], head_dbs[1])
        for snapshot, target in zip(witness_snapshots, witness_dbs, strict=True):
            restore_file(snapshot, target)
        restore_file(logical_anchor_snapshot, logical_anchor_db)
        restore_tree(immutable_snapshot, immutable_root)
        restore_file(checkpoint_snapshot, checkpoint_db)

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
            logical_anchor = stack.enter_context(open_anchor(logical_anchor_db, ids))
            immutable = open_immutable_anchor(immutable_root, ids)
            checkpoint = stack.enter_context(
                SQLiteImmutableAnchorCheckpointLedger(
                    checkpoint_db, anchor_id=IMMUTABLE_ANCHOR_ID
                )
            )
            compromised = claim_and_start(
                queue=queue,
                ledger=ledger,
                heads=heads,
                ids=ids,
                item=item,
                intent=intent,
                label="v331:coordinated-rollback",
                tick=20,
            )
            provider_after = provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=PAYLOAD_SHA256,
                provider_request_id="provider-request:v331:coordinated-rollback",
                now_tick=22,
            )
            availability_after = availability_closed_status(
                witnesses,
                [0, 1, 2],
                ids,
                intent["effect_id"],
                22,
                "coordinated-rollback",
            )
            logical_after = anchor_status(
                logical_anchor,
                ids,
                intent["effect_id"],
                22,
                "coordinated-rollback",
            )
            immutable_after = immutable_status(
                immutable,
                ids,
                intent["effect_id"],
                22,
                "coordinated-rollback",
                checkpoint=checkpoint,
            )
            duplicate_permitted = (
                compromised["quorum_before"]["status"] == "PASS"
                and compromised["reservation"]["status"] == "PASS"
                and compromised["quorum_after"]["status"] == "PASS"
                and provider_after["external_effect_permitted"] is True
                and availability_after["status"] == "PASS"
                and availability_after["availability_witness"]["state"] == "ABSENT"
                and availability_after["responding_witness_count"] == 3
                and logical_after["external_effect_permitted"] is True
                and logical_after["worm_anchor_status"]["state"] == "ABSENT"
                and immutable_after["external_effect_permitted"] is True
                and immutable_after["immutable_anchor_status"]["state"] == "ABSENT"
                and checkpoint.snapshot()["sequence"] == 0
            )
            rows.append(
                {
                    "case_id": "V331RB04_COORDINATED_COMPLETION_EVIDENCE_AND_CHECKPOINT_ROLLBACK_REVIVES_EFFECT",
                    "same_effect_id": compromised["reservation"]["effect"]["effect_id"] == intent["effect_id"],
                    "new_dispatch_id": compromised["claim"]["dispatch_id"] != first_dispatch_id,
                    "execution_quorum_before_status": compromised["quorum_before"]["status"],
                    "execution_quorum_after_status": compromised["quorum_after"]["status"],
                    "current_execution_minority_rejected_fork": compromised["anchor_rows"][2]["status"] == "BLOCK",
                    "rolled_back_provider_external_effect_permitted": provider_after["external_effect_permitted"],
                    "rolled_back_full_availability_state": availability_after["availability_witness"]["state"],
                    "rolled_back_full_availability_member_count": availability_after["responding_witness_count"],
                    "rolled_back_logical_anchor_state": logical_after["worm_anchor_status"]["state"],
                    "rolled_back_immutable_anchor_state": immutable_after["immutable_anchor_status"]["state"],
                    "rolled_back_checkpoint_sequence": checkpoint.snapshot()["sequence"],
                    "expected_secure_result": "BLOCK_OR_EXTERNAL_NON_ROLLBACKABLE_COMPLETION_PROOF",
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
        "protocol_id": "TRIAXIS_v3.31_POSTCOMMIT_COORDINATED_COMPLETION_EVIDENCE_ROLLBACK_BOUNDARY",
        "exact_subject_tag": SUBJECT_TAG,
        "exact_subject_commit": exact_subject_commit(),
        "status": "BOUNDARY_CONFIRMED" if boundary_confirmed else "UNEXPECTED",
        "claim": (
            "Availability-closed verification prevents omission of one current configured completion witness, "
            "and a current verifier checkpoint detects rollback of the logical immutable-anchor filesystem. "
            "Coordinated rollback of provider state, every completion witness, both completion anchors and the "
            "verifier checkpoint can still recreate a complete permissive old view and revive the same stable effect."
        ),
        "required_next_control": [
            "provider-native durable idempotency keyed by stable effect_id",
            "externally administered physical WORM or append-only completion receipts",
            "checkpoint transparency quorum outside completion-evidence administrators",
            "KMS/HSM or hardware-backed monotonic anti-rollback state",
            "independent multi-host and multi-administrator fault domains",
            "evidence that configured witness unavailability cannot be forged by the executor",
        ],
        "authority_granted": False,
        "production_qualified": False,
        "physical_worm_established": False,
        "hardware_monotonicity": False,
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    result = run()
    path = Path(
        "evidence/TRIAXIS_v3.31_POSTCOMMIT_COORDINATED_COMPLETION_EVIDENCE_ROLLBACK_BOUNDARY.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
