from __future__ import annotations

from contextlib import ExitStack
import copy
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest

from triaxis.crypto_trust import (
    PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
    PURPOSE_EXECUTION_LEDGER_HEAD_QUORUM,
    PURPOSE_EXECUTION_RECEIPT,
    PURPOSE_EXTERNAL_COMPLETION_WITNESS,
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    verify_contract_envelope,
)
from triaxis.execution_ledger_head_authority import SQLiteExecutionLedgerHeadAuthority
from triaxis.execution_ledger_head_quorum import (
    EXECUTION_LEDGER_HEAD_QUORUM_WITNESS_CONTRACT_ID,
    ExecutionLedgerHeadQuorumError,
    make_execution_ledger_head_quorum_config,
    sign_execution_ledger_head_quorum_witness,
    validate_execution_ledger_head_quorum_config,
    verify_execution_ledger_head_quorum,
    verify_execution_ledger_head_quorum_witness,
    verify_external_effect_guard_with_head_quorum_and_completion_witness,
)
from triaxis.external_completion_witness import (
    CompletionWitnessError,
    SQLiteExternalCompletionWitness,
    verify_completion_witness_event,
    verify_completion_witness_event_chain,
    verify_completion_witness_head,
    verify_external_completion_witness_status,
)
from triaxis.external_completion_witness_http import ExternalCompletionWitnessHTTPApplication
from triaxis.external_execution_ledger import SQLiteExternalExecutionLedger, seal_execution_intent
from triaxis.idempotent_effect_provider import (
    ProviderEffectError,
    SQLiteIdempotentEffectProvider,
    verify_provider_outcome_receipt,
)
from triaxis.idempotent_effect_provider_http import IdempotentEffectProviderHTTPApplication
from triaxis.integrity import canonical_sha256
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
E = "e" * 64
F = "f" * 64

LEDGER_ID = "ledger:v329:primary"
LEDGER_AUTHORITY_ID = "authority:ledger:v329"
LEDGER_SIGNER_ID = "signer:ledger:v329"
LEDGER_DOMAIN = "domain:ledger:v329"
PROVIDER_ID = "provider:v329:reference"
PROVIDER_SERVICE_ID = "service:provider:v329"
PROVIDER_SIGNER_ID = "signer:provider:v329"
PROVIDER_DOMAIN = "domain:provider:v329"
WITNESS_ID = "completion-witness:v329"
WITNESS_AUTHORITY_ID = "authority:completion-witness:v329"
WITNESS_SERVICE_ID = "service:completion-witness:v329"
WITNESS_SIGNER_ID = "signer:completion-witness:v329"
WITNESS_DOMAIN = "domain:completion-witness:v329"
QUORUM_SIGNER_ID = "signer:execution-head-quorum:v329"
QUORUM_DOMAIN = "domain:execution-head-quorum:v329"


def make_intent(queue_id: str = "queue:v329:1", payload: str = B) -> dict:
    return seal_execution_intent(
        {
            "queue_id": queue_id,
            "queued_input_sha256": A,
            "action_envelope_sha256": payload,
            "authorization_token_sha256": C,
            "canonical_target_sha256": D,
            "risk_class": "MUTATING",
            "created_at_tick": 1,
            "metadata": {"fixture": "v3.29"},
        }
    )


def identities() -> dict:
    ledger_pair = generate_ed25519_keypair()
    provider_pair = generate_ed25519_keypair()
    witness_pair = generate_ed25519_keypair()
    quorum_pair = generate_ed25519_keypair()
    head_rows = []
    head_records = []
    for suffix in ("a", "b", "c"):
        pair = generate_ed25519_keypair()
        row = {
            "authority_id": f"authority:execution-head:v329:{suffix}",
            "service_id": f"service:execution-head:v329:{suffix}",
            "key_id": f"key:execution-head:v329:{suffix}",
            "signer_id": f"signer:execution-head:v329:{suffix}",
            "trust_domain": f"domain:execution-head:v329:{suffix}",
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
    ledger_registry = TrustKeyRegistry(
        [
            make_trust_key_record(
                key_id="key:ledger:v329",
                signer_id=LEDGER_SIGNER_ID,
                trust_domain=LEDGER_DOMAIN,
                public_key_b64=ledger_pair["public_key_b64"],
                purposes=[PURPOSE_EXECUTION_RECEIPT],
                valid_from=0,
                valid_until=100_000,
            )
        ]
    )
    provider_registry = TrustKeyRegistry(
        [
            make_trust_key_record(
                key_id="key:provider:v329",
                signer_id=PROVIDER_SIGNER_ID,
                trust_domain=PROVIDER_DOMAIN,
                public_key_b64=provider_pair["public_key_b64"],
                purposes=[PURPOSE_PROVIDER_EFFECT_RECEIPT],
                valid_from=0,
                valid_until=100_000,
            )
        ]
    )
    witness_registry = TrustKeyRegistry(
        [
            make_trust_key_record(
                key_id="key:completion-witness:v329",
                signer_id=WITNESS_SIGNER_ID,
                trust_domain=WITNESS_DOMAIN,
                public_key_b64=witness_pair["public_key_b64"],
                purposes=[PURPOSE_EXTERNAL_COMPLETION_WITNESS],
                valid_from=0,
                valid_until=100_000,
            )
        ]
    )
    quorum_registry = TrustKeyRegistry(
        [
            make_trust_key_record(
                key_id="key:execution-head-quorum:v329",
                signer_id=QUORUM_SIGNER_ID,
                trust_domain=QUORUM_DOMAIN,
                public_key_b64=quorum_pair["public_key_b64"],
                purposes=[PURPOSE_EXECUTION_LEDGER_HEAD_QUORUM],
                valid_from=0,
                valid_until=100_000,
            )
        ]
    )
    return {
        "ledger_pair": ledger_pair,
        "provider_pair": provider_pair,
        "witness_pair": witness_pair,
        "quorum_pair": quorum_pair,
        "head_rows": head_rows,
        "ledger_registry": ledger_registry,
        "head_registry": TrustKeyRegistry(head_records),
        "provider_registry": provider_registry,
        "witness_registry": witness_registry,
        "quorum_registry": quorum_registry,
    }


def open_ledger(path: str | Path, ids: dict) -> SQLiteExternalExecutionLedger:
    return SQLiteExternalExecutionLedger(
        path,
        ledger_id=LEDGER_ID,
        authority_id=LEDGER_AUTHORITY_ID,
        key_id="key:ledger:v329",
        signer_id=LEDGER_SIGNER_ID,
        trust_domain=LEDGER_DOMAIN,
        private_key_b64=ids["ledger_pair"]["private_key_b64"],
        receipt_ttl=10_000,
    )


def open_head(path: str | Path, ids: dict, index: int) -> SQLiteExecutionLedgerHeadAuthority:
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


def open_provider(path: str | Path, ids: dict) -> SQLiteIdempotentEffectProvider:
    return SQLiteIdempotentEffectProvider(
        path,
        provider_id=PROVIDER_ID,
        service_id=PROVIDER_SERVICE_ID,
        key_id="key:provider:v329",
        signer_id=PROVIDER_SIGNER_ID,
        trust_domain=PROVIDER_DOMAIN,
        private_key_b64=ids["provider_pair"]["private_key_b64"],
        response_ttl=100,
    )


def open_witness(path: str | Path, ids: dict) -> SQLiteExternalCompletionWitness:
    return SQLiteExternalCompletionWitness(
        path,
        witness_id=WITNESS_ID,
        authority_id=WITNESS_AUTHORITY_ID,
        service_id=WITNESS_SERVICE_ID,
        key_id="key:completion-witness:v329",
        signer_id=WITNESS_SIGNER_ID,
        trust_domain=WITNESS_DOMAIN,
        private_key_b64=ids["witness_pair"]["private_key_b64"],
        receipt_ttl=100,
    )


def config_rows(ids: dict) -> list[dict]:
    return [
        {key: row[key] for key in ("authority_id", "service_id", "signer_id", "key_id", "trust_domain")}
        for row in ids["head_rows"]
    ]


def quorum_config(ids: dict, threshold: int = 2) -> dict:
    return make_execution_ledger_head_quorum_config(
        config_id="execution-head-quorum:v329:primary",
        authority_set_id="execution-head-authorities:v329:primary",
        ledger_id=LEDGER_ID,
        threshold=threshold,
        authorities=config_rows(ids),
        valid_from=0,
        valid_until=10_000,
    )


def anchor(authorities: list[SQLiteExecutionLedgerHeadAuthority], ledger: SQLiteExternalExecutionLedger, tick: int) -> dict:
    signed_head = ledger.head(now_tick=tick)
    results = []
    for authority in authorities:
        current = authority.current(LEDGER_ID)
        base = 0 if current is None else current["inner_contract"]["sequence"]
        results.append(
            authority.install_advance(
                signed_head,
                ledger.events_since(base),
                evaluation_tick=tick,
            )
        )
    return {"signed_head": signed_head, "results": results}


def issue_head_responses(
    authorities: list[SQLiteExecutionLedgerHeadAuthority],
    *,
    session: VerifierFreshnessSession,
    challenge: str,
    requested_at: int,
    issued_at: int,
) -> list[dict]:
    return [
        authority.issue_head(
            ledger_id=LEDGER_ID,
            challenge=challenge,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            requested_at=requested_at,
            issued_at=issued_at,
            valid_until=issued_at + 20,
        )
        for authority in authorities
    ]


def snapshot_sqlite(source: Path, snapshot: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(source) + suffix).unlink(missing_ok=True)
    shutil.copy2(source, snapshot)


def restore_sqlite(snapshot: Path, target: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(str(target) + suffix).unlink(missing_ok=True)
    shutil.copy2(snapshot, target)


class ExecutionHeadQuorumTests(unittest.TestCase):
    def test_two_of_three_matching_authorities_accept(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(3)]
            anchor(heads, ledger, 1)
            session = VerifierFreshnessSession.create("verifier:v329:q1", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(2, 20)
            responses = issue_head_responses(heads[:2], session=session, challenge=challenge, requested_at=2, issued_at=2)
            result = verify_execution_ledger_head_quorum(
                ledger.head(now_tick=2), responses,
                ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                quorum_config=quorum_config(ids), expected_quorum_config_sha256=quorum_config(ids)["config_sha256"],
                challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
            )
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["quorum_witness"]["member_count"], 2)
            self.assertTrue(
                all(
                    len(member["response_sha256"]) == 64
                    and member["response_valid_until"] > member["response_issued_at"]
                    for member in result["quorum_witness"]["members"]
                )
            )
            self.assertFalse(result["authority_granted"])

    def test_one_stale_authority_cannot_override_two_current(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(3)]
            anchor(heads, ledger, 1)
            intent = make_intent()
            dispatch = canonical_sha256({"dispatch": "high"})
            ledger.reserve(intent, attempt_id="attempt:high", dispatch_id=dispatch, now_tick=2)
            anchor(heads[1:], ledger, 2)
            session = VerifierFreshnessSession.create("verifier:v329:q2", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(3, 20)
            responses = issue_head_responses(heads, session=session, challenge=challenge, requested_at=3, issued_at=3)
            result = verify_execution_ledger_head_quorum(
                ledger.head(now_tick=3), responses,
                ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                quorum_config=quorum_config(ids), expected_quorum_config_sha256=quorum_config(ids)["config_sha256"],
                challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=3,
            )
            self.assertEqual(result["quorum_witness"]["ledger_sequence"], 1)
            self.assertEqual(result["quorum_witness"]["member_count"], 2)

    def test_one_current_one_stale_one_unavailable_blocks(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(3)]
            anchor(heads, ledger, 1)
            intent = make_intent()
            dispatch = canonical_sha256({"dispatch": "split"})
            ledger.reserve(intent, attempt_id="attempt:split", dispatch_id=dispatch, now_tick=2)
            anchor([heads[1]], ledger, 2)
            session = VerifierFreshnessSession.create("verifier:v329:q3", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(3, 20)
            responses = issue_head_responses(heads[:2], session=session, challenge=challenge, requested_at=3, issued_at=3)
            with self.assertRaises(ExecutionLedgerHeadQuorumError) as ctx:
                verify_execution_ledger_head_quorum(
                    ledger.head(now_tick=3), responses,
                    ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                    expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                    expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                    quorum_config=quorum_config(ids), expected_quorum_config_sha256=quorum_config(ids)["config_sha256"],
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=3,
                )
            self.assertEqual(ctx.exception.code, "execution_head_authority_quorum_not_met")

    def test_duplicate_authority_does_not_form_quorum(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            head = stack.enter_context(open_head(":memory:", ids, 0))
            anchor([head], ledger, 1)
            session = VerifierFreshnessSession.create("verifier:v329:q4", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(2, 20)
            response = issue_head_responses([head], session=session, challenge=challenge, requested_at=2, issued_at=2)[0]
            with self.assertRaises(ExecutionLedgerHeadQuorumError) as ctx:
                verify_execution_ledger_head_quorum(
                    ledger.head(now_tick=2), [response, copy.deepcopy(response)],
                    ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                    expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                    expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                    quorum_config=quorum_config(ids), expected_quorum_config_sha256=quorum_config(ids)["config_sha256"],
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
                )
            self.assertEqual(ctx.exception.code, "execution_head_authority_quorum_not_met")

    def test_same_signer_equivocation_is_blocked(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            head = stack.enter_context(open_head(":memory:", ids, 0))
            anchor([head], ledger, 1)
            session = VerifierFreshnessSession.create("verifier:v329:q5", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(2, 20)
            low = issue_head_responses([head], session=session, challenge=challenge, requested_at=2, issued_at=2)[0]
            intent = make_intent()
            ledger.reserve(intent, attempt_id="attempt:eq", dispatch_id=canonical_sha256({"d": 1}), now_tick=2)
            anchor([head], ledger, 2)
            high = issue_head_responses([head], session=session, challenge=challenge, requested_at=2, issued_at=2)[0]
            with self.assertRaises(ExecutionLedgerHeadQuorumError) as ctx:
                verify_execution_ledger_head_quorum(
                    ledger.head(now_tick=2), [low, high],
                    ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                    expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                    expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                    quorum_config=quorum_config(ids), expected_quorum_config_sha256=quorum_config(ids)["config_sha256"],
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
                )
            self.assertEqual(ctx.exception.code, "execution_head_authority_equivocation")

    def test_current_quorum_detects_rolled_back_local_head(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(3)]
            low = anchor(heads, ledger, 1)["signed_head"]
            intent = make_intent()
            ledger.reserve(intent, attempt_id="attempt:rollback", dispatch_id=canonical_sha256({"d": 2}), now_tick=2)
            anchor(heads, ledger, 2)
            session = VerifierFreshnessSession.create("verifier:v329:q6", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(3, 20)
            responses = issue_head_responses(heads, session=session, challenge=challenge, requested_at=3, issued_at=3)
            with self.assertRaises(ExecutionLedgerHeadQuorumError) as ctx:
                verify_execution_ledger_head_quorum(
                    low, responses,
                    ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                    expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                    expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                    quorum_config=quorum_config(ids), expected_quorum_config_sha256=quorum_config(ids)["config_sha256"],
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=3,
                )
            self.assertEqual(ctx.exception.code, "execution_ledger_rollback_or_fork_detected")

    def test_config_substitution_is_blocked(self):
        ids = identities()
        strict = quorum_config(ids, threshold=3)
        weak = quorum_config(ids, threshold=2)
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(3)]
            anchor(heads, ledger, 1)
            session = VerifierFreshnessSession.create("verifier:v329:q7", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(2, 20)
            responses = issue_head_responses(heads[:2], session=session, challenge=challenge, requested_at=2, issued_at=2)
            with self.assertRaises(ExecutionLedgerHeadQuorumError) as ctx:
                verify_execution_ledger_head_quorum(
                    ledger.head(now_tick=2), responses,
                    ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                    expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                    expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                    quorum_config=weak, expected_quorum_config_sha256=strict["config_sha256"],
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
                )
            self.assertEqual(ctx.exception.code, "execution_head_quorum_config_substitution")

    def test_threshold_requires_distinct_domains(self):
        ids = identities()
        rows = config_rows(ids)
        rows[1]["trust_domain"] = rows[0]["trust_domain"]
        config = make_execution_ledger_head_quorum_config(
            config_id="bad", authority_set_id="bad", ledger_id=LEDGER_ID,
            threshold=3, authorities=rows, valid_from=0, valid_until=100,
        )
        result = validate_execution_ledger_head_quorum_config(config, 1)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("insufficient_domain_diversity", {row["code"] for row in result["errors"]})

    def test_quorum_witness_can_be_signed_for_durable_handoff(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(2)]
            anchor(heads, ledger, 1)
            session = VerifierFreshnessSession.create("verifier:v329:q8", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(2, 20)
            responses = issue_head_responses(heads, session=session, challenge=challenge, requested_at=2, issued_at=2)
            result = verify_execution_ledger_head_quorum(
                ledger.head(now_tick=2), responses,
                ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                quorum_config=quorum_config(ids), expected_quorum_config_sha256=quorum_config(ids)["config_sha256"],
                challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
            )
            signed = sign_execution_ledger_head_quorum_witness(
                result["quorum_witness"], key_id="key:execution-head-quorum:v329",
                signer_id=QUORUM_SIGNER_ID, trust_domain=QUORUM_DOMAIN,
                private_key_b64=ids["quorum_pair"]["private_key_b64"], issued_at=2, valid_until=50,
            )
            verified = verify_execution_ledger_head_quorum_witness(
                signed, registry=ids["quorum_registry"],
                expected_signer_id=QUORUM_SIGNER_ID, expected_trust_domain=QUORUM_DOMAIN,
                quorum_config=quorum_config(ids),
                expected_quorum_config_sha256=quorum_config(ids)["config_sha256"],
                expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                evaluation_tick=2, expected_verifier_id=session.verifier_id,
                expected_verifier_epoch_sha256=session.epoch_sha256,
            )
            self.assertEqual(verified["status"], "PASS")
            self.assertEqual(verified["verified_member_count"], 2)

    def test_signed_quorum_witness_rejects_pinned_config_substitution(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(2)]
            anchor(heads, ledger, 1)
            session = VerifierFreshnessSession.create("verifier:v329:q9", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(2, 20)
            config = quorum_config(ids)
            result = verify_execution_ledger_head_quorum(
                ledger.head(now_tick=2),
                issue_head_responses(heads, session=session, challenge=challenge, requested_at=2, issued_at=2),
                ledger_registry=ids["ledger_registry"], authority_registry=ids["head_registry"],
                expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                quorum_config=config, expected_quorum_config_sha256=config["config_sha256"],
                challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
            )
            signed = sign_execution_ledger_head_quorum_witness(
                result["quorum_witness"], key_id="key:execution-head-quorum:v329",
                signer_id=QUORUM_SIGNER_ID, trust_domain=QUORUM_DOMAIN,
                private_key_b64=ids["quorum_pair"]["private_key_b64"], issued_at=2, valid_until=50,
            )
            alternate = make_execution_ledger_head_quorum_config(
                config_id="execution-head-quorum:v329:alternate",
                authority_set_id=config["authority_set_id"], ledger_id=LEDGER_ID, threshold=2,
                authorities=config_rows(ids), valid_from=0, valid_until=10_000,
            )
            with self.assertRaises(ExecutionLedgerHeadQuorumError) as ctx:
                verify_execution_ledger_head_quorum_witness(
                    signed, registry=ids["quorum_registry"],
                    expected_signer_id=QUORUM_SIGNER_ID, expected_trust_domain=QUORUM_DOMAIN,
                    quorum_config=alternate,
                    expected_quorum_config_sha256=alternate["config_sha256"],
                    expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                    evaluation_tick=2,
                )
            self.assertEqual(ctx.exception.code, "execution_head_quorum_config_substitution")


class ExternalCompletionWitnessTests(unittest.TestCase):
    def test_absent_reservation_permits_once_and_exact_replay_blocks(self):
        ids = identities()
        intent = make_intent()
        with open_witness(":memory:", ids) as witness:
            first = witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:1", now_tick=1,
            )
            replay = witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:2", now_tick=2,
            )
            self.assertTrue(first["external_effect_permitted"])
            self.assertTrue(replay["idempotent_replay"])
            self.assertFalse(replay["external_effect_permitted"])
            self.assertEqual(replay["current_state"], "RESERVED")

    def test_effect_id_payload_substitution_is_blocked(self):
        ids = identities()
        intent = make_intent()
        with open_witness(":memory:", ids) as witness:
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:1", now_tick=1,
            )
            with self.assertRaises(CompletionWitnessError) as ctx:
                witness.reserve(
                    effect_id=intent["effect_id"], payload_sha256=E, provider_id=PROVIDER_ID,
                    provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:2", now_tick=2,
                )
            self.assertEqual(ctx.exception.code, "completion_witness_payload_conflict")

    def test_signed_provider_completion_is_recorded_and_blocks_retry(self):
        ids = identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_witness(":memory:", ids) as witness:
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:complete", now_tick=1,
            )
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:complete", now_tick=2,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:complete",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=3,
            )
            receipt = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=3, valid_until=50)
            recorded = witness.record_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=3,
            )
            retry = witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:retry", now_tick=4,
            )
            self.assertEqual(recorded["effect"]["state"], "COMPLETED")
            self.assertFalse(retry["external_effect_permitted"])
            self.assertEqual(retry["current_state"], "COMPLETED")

    def test_provider_outcome_receipt_is_payload_and_request_bound(self):
        ids = identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider:
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:receipt", now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:receipt",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            signed = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=2, valid_until=50)
            verified = verify_provider_outcome_receipt(
                signed, registry=ids["provider_registry"], expected_provider_id=PROVIDER_ID,
                expected_service_id=PROVIDER_SERVICE_ID, expected_signer_id=PROVIDER_SIGNER_ID,
                expected_trust_domain=PROVIDER_DOMAIN, expected_effect_id=intent["effect_id"],
                expected_payload_sha256=B, evaluation_tick=2,
            )
            self.assertEqual(verified["provider_receipt"]["provider_request_id"], "provider-request:receipt")
            self.assertFalse(verified["authority_granted"])

    def test_tampered_provider_outcome_receipt_is_blocked(self):
        ids = identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_witness(":memory:", ids) as witness:
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:tamper", now_tick=1,
            )
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:tamper", now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:tamper",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            signed = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=2, valid_until=50)
            tampered = copy.deepcopy(signed)
            tampered["inner_contract"]["evidence_sha256"] = A
            with self.assertRaises(CompletionWitnessError) as ctx:
                witness.record_provider_outcome(
                    tampered, provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
                )
            self.assertEqual(ctx.exception.code, "invalid_provider_outcome_signature")

    def test_provider_request_mismatch_is_blocked(self):
        ids = identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_witness(":memory:", ids) as witness:
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:witness", now_tick=1,
            )
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:other", now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:other",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            signed = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=2, valid_until=50)
            with self.assertRaises(CompletionWitnessError) as ctx:
                witness.record_provider_outcome(
                    signed, provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
                )
            self.assertEqual(ctx.exception.code, "completion_witness_provider_request_mismatch")

    def test_unknown_can_be_reconciled_to_completed(self):
        ids = identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_witness(":memory:", ids) as witness:
            request_id = "provider-request:unknown"
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id=request_id, now_tick=1,
            )
            provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id=request_id, now_tick=1)
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id=request_id,
                outcome="UNKNOWN", provider_response_sha256=None, evidence_sha256=F, now_tick=2,
            )
            unknown = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=2, valid_until=50)
            witness.record_provider_outcome(
                unknown, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            provider.reconcile_unknown(
                effect_id=intent["effect_id"], provider_request_id=request_id,
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=A, now_tick=3,
            )
            completed = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=3, valid_until=50)
            result = witness.record_provider_outcome(
                completed, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=3,
            )
            self.assertEqual(result["effect"]["state"], "COMPLETED")

    def test_no_effect_allows_new_generation(self):
        ids = identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_witness(":memory:", ids) as witness:
            request_id = "provider-request:no-effect"
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id=request_id, now_tick=1,
            )
            provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id=request_id, now_tick=1)
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id=request_id,
                outcome="NO_EFFECT", provider_response_sha256=None, evidence_sha256=F, now_tick=2,
            )
            receipt = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=2, valid_until=50)
            witness.record_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            retry = witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:g2", now_tick=3,
            )
            self.assertTrue(retry["external_effect_permitted"])
            self.assertEqual(retry["effect"]["generation"], 2)

    def test_fresh_challenge_bound_absent_status_verifies_once(self):
        ids = identities()
        intent = make_intent()
        with open_witness(":memory:", ids) as witness:
            session = VerifierFreshnessSession.create("verifier:v329:w1", 0)
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                challenge = challenges.issue(1, 20)
                signed = witness.issue_status(
                    effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge=challenge, verifier_id=session.verifier_id,
                    verifier_epoch_sha256=session.epoch_sha256, requested_at=1, issued_at=1,
                )
                result = verify_external_completion_witness_status(
                    signed, registry=ids["witness_registry"], expected_witness_id=WITNESS_ID,
                    expected_authority_id=WITNESS_AUTHORITY_ID, expected_service_id=WITNESS_SERVICE_ID,
                    expected_signer_id=WITNESS_SIGNER_ID, expected_trust_domain=WITNESS_DOMAIN,
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
                )
                self.assertTrue(result["external_effect_permitted"])
                with self.assertRaises(Exception):
                    verify_external_completion_witness_status(
                        signed, registry=ids["witness_registry"], expected_witness_id=WITNESS_ID,
                        expected_authority_id=WITNESS_AUTHORITY_ID, expected_service_id=WITNESS_SERVICE_ID,
                        expected_signer_id=WITNESS_SIGNER_ID, expected_trust_domain=WITNESS_DOMAIN,
                        expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
                    )

    def test_completed_witness_status_blocks_retry(self):
        ids = identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_witness(":memory:", ids) as witness:
            request_id = "provider-request:status-complete"
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id=request_id, now_tick=1,
            )
            provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id=request_id, now_tick=1)
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id=request_id,
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            receipt = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=2, valid_until=50)
            witness.record_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            session = VerifierFreshnessSession.create("verifier:v329:w2", 0)
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                challenge = challenges.issue(3, 20)
                signed = witness.issue_status(
                    effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge=challenge, verifier_id=session.verifier_id,
                    verifier_epoch_sha256=session.epoch_sha256, requested_at=3, issued_at=3,
                )
                with self.assertRaises(CompletionWitnessError) as ctx:
                    verify_external_completion_witness_status(
                        signed, registry=ids["witness_registry"], expected_witness_id=WITNESS_ID,
                        expected_authority_id=WITNESS_AUTHORITY_ID, expected_service_id=WITNESS_SERVICE_ID,
                        expected_signer_id=WITNESS_SIGNER_ID, expected_trust_domain=WITNESS_DOMAIN,
                        expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=3,
                    )
                self.assertEqual(ctx.exception.code, "completion_witness_state_blocks_retry")

    def test_signed_witness_event_and_head_verify(self):
        ids = identities()
        intent = make_intent()
        with open_witness(":memory:", ids) as witness:
            result = witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:event", now_tick=1,
            )
            verified = verify_completion_witness_event(
                result["signed_witness_event"], registry=ids["witness_registry"],
                expected_witness_id=WITNESS_ID, expected_authority_id=WITNESS_AUTHORITY_ID,
                expected_service_id=WITNESS_SERVICE_ID, expected_signer_id=WITNESS_SIGNER_ID,
                expected_trust_domain=WITNESS_DOMAIN, evaluation_tick=1,
                expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
            )
            self.assertEqual(verified["event"]["sequence"], 1)
            chain = verify_completion_witness_event_chain(
                witness.events_since(0), registry=ids["witness_registry"],
                expected_witness_id=WITNESS_ID, expected_authority_id=WITNESS_AUTHORITY_ID,
                expected_service_id=WITNESS_SERVICE_ID, expected_signer_id=WITNESS_SIGNER_ID,
                expected_trust_domain=WITNESS_DOMAIN, evaluation_tick=1,
            )
            self.assertEqual(chain["event_count"], 1)
            signed_head = witness.head(now_tick=1)
            head = verify_completion_witness_head(
                signed_head, registry=ids["witness_registry"],
                expected_witness_id=WITNESS_ID, expected_authority_id=WITNESS_AUTHORITY_ID,
                expected_service_id=WITNESS_SERVICE_ID, expected_signer_id=WITNESS_SIGNER_ID,
                expected_trust_domain=WITNESS_DOMAIN, evaluation_tick=1,
                expected_sequence=chain["head_sequence"],
                expected_head_event_sha256=chain["head_event_sha256"],
            )
            self.assertEqual(head["status"], "PASS")
            self.assertEqual(head["head"]["sequence"], 1)

    def test_completion_witness_chain_rejects_parent_substitution(self):
        ids = identities()
        intent = make_intent()
        with open_witness(":memory:", ids) as witness:
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id="provider-request:chain", now_tick=1,
            )
            events = witness.events_since(0)
            tampered = copy.deepcopy(events)
            tampered[0]["inner_contract"]["previous_event_sha256"] = A
            with self.assertRaises(CompletionWitnessError) as ctx:
                verify_completion_witness_event_chain(
                    tampered, registry=ids["witness_registry"],
                    expected_witness_id=WITNESS_ID, expected_authority_id=WITNESS_AUTHORITY_ID,
                    expected_service_id=WITNESS_SERVICE_ID, expected_signer_id=WITNESS_SIGNER_ID,
                    expected_trust_domain=WITNESS_DOMAIN, evaluation_tick=1,
                )
            self.assertEqual(ctx.exception.code, "invalid_completion_witness_signature")

    def test_provider_rollback_is_still_blocked_by_current_witness(self):
        ids = identities()
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            provider_db = root / "provider.sqlite"
            provider_snapshot = root / "provider.pre.sqlite"
            witness_db = root / "witness.sqlite"
            provider = open_provider(provider_db, ids)
            provider.close()
            snapshot_sqlite(provider_db, provider_snapshot)
            provider = open_provider(provider_db, ids)
            witness = open_witness(witness_db, ids)
            request_id = "provider-request:rollback"
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID, provider_request_id=request_id, now_tick=1,
            )
            provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id=request_id, now_tick=1)
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id=request_id,
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            receipt = provider.issue_outcome_receipt(effect_id=intent["effect_id"], issued_at=2, valid_until=50)
            witness.record_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            provider.close()
            restore_sqlite(provider_snapshot, provider_db)
            provider = open_provider(provider_db, ids)
            provider_retry = provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:after-rollback", now_tick=3,
            )
            witness_retry = witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B, provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id="provider-request:after-rollback", now_tick=3,
            )
            self.assertTrue(provider_retry["external_effect_permitted"])
            self.assertFalse(witness_retry["external_effect_permitted"])
            provider.close()
            witness.close()


class V329ComposedGuardAndHTTPTests(unittest.TestCase):
    def test_full_preflight_passes_only_with_ledger_quorum_provider_and_witness(self):
        ids = identities()
        intent = make_intent()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(3)]
            provider = stack.enter_context(open_provider(":memory:", ids))
            witness = stack.enter_context(open_witness(":memory:", ids))
            anchor(heads, ledger, 1)
            dispatch = canonical_sha256({"dispatch": "guard"})
            ledger.reserve(intent, attempt_id="attempt:guard", dispatch_id=dispatch, now_tick=2)
            started = ledger.start(intent["effect_id"], attempt_id="attempt:guard", dispatch_id=dispatch, now_tick=3)
            anchor(heads, ledger, 3)

            head_session = VerifierFreshnessSession.create("verifier:v329:guard:head", 0)
            head_challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", head_session))
            head_challenge = head_challenges.issue(4, 20)
            head_responses = issue_head_responses(
                heads, session=head_session, challenge=head_challenge, requested_at=4, issued_at=4
            )

            provider_session = VerifierFreshnessSession.create("verifier:v329:guard:provider", 0)
            provider_challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", provider_session))
            provider_challenge = provider_challenges.issue(4, 20)
            provider_status = provider.issue_status(
                effect_id=intent["effect_id"], expected_payload_sha256=B,
                challenge=provider_challenge, verifier_id=provider_session.verifier_id,
                verifier_epoch_sha256=provider_session.epoch_sha256, requested_at=4, issued_at=4,
            )

            witness_session = VerifierFreshnessSession.create("verifier:v329:guard:witness", 0)
            witness_challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", witness_session))
            witness_challenge = witness_challenges.issue(4, 20)
            witness_status = witness.issue_status(
                effect_id=intent["effect_id"], expected_payload_sha256=B,
                expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                challenge=witness_challenge, verifier_id=witness_session.verifier_id,
                verifier_epoch_sha256=witness_session.epoch_sha256, requested_at=4, issued_at=4,
            )
            config = quorum_config(ids)
            result = verify_external_effect_guard_with_head_quorum_and_completion_witness(
                intent, started["signed_receipt"], expected_attempt_id="attempt:guard",
                expected_dispatch_id=dispatch, evaluation_tick=4,
                signed_local_head=ledger.head(now_tick=4), signed_head_responses=head_responses,
                ledger_registry=ids["ledger_registry"], head_authority_registry=ids["head_registry"],
                expected_ledger_id=LEDGER_ID, expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID, expected_ledger_trust_domain=LEDGER_DOMAIN,
                quorum_config=config, expected_quorum_config_sha256=config["config_sha256"],
                head_challenge_ledger=head_challenges, expected_head_challenge=head_challenge,
                signed_provider_status=provider_status, provider_registry=ids["provider_registry"],
                expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, expected_provider_payload_sha256=B,
                provider_challenge_ledger=provider_challenges,
                expected_provider_challenge=provider_challenge,
                signed_completion_witness_status=witness_status,
                completion_witness_registry=ids["witness_registry"],
                expected_completion_witness_id=WITNESS_ID,
                expected_completion_witness_authority_id=WITNESS_AUTHORITY_ID,
                expected_completion_witness_service_id=WITNESS_SERVICE_ID,
                expected_completion_witness_signer_id=WITNESS_SIGNER_ID,
                expected_completion_witness_trust_domain=WITNESS_DOMAIN,
                completion_witness_challenge_ledger=witness_challenges,
                expected_completion_witness_challenge=witness_challenge,
            )
            self.assertEqual(result["status"], "PASS")
            self.assertFalse(result["authority_granted"])

    def test_completion_witness_http_requires_auth_for_mutation(self):
        ids = identities()
        intent = make_intent()
        token = "client-secret-v329"
        with open_witness(":memory:", ids) as witness:
            app = ExternalCompletionWitnessHTTPApplication(
                witness, clock=lambda: 5,
                client_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
            )
            body = {
                "effect_id": intent["effect_id"], "payload_sha256": B,
                "provider_id": PROVIDER_ID, "provider_service_id": PROVIDER_SERVICE_ID,
                "provider_request_id": "provider-request:http",
            }
            denied, _ = app.handle("POST", "/v1/effects/reserve", body)
            accepted, payload = app.handle(
                "POST", "/v1/effects/reserve", body, {"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(denied, 403)
            self.assertEqual(accepted, 200)
            self.assertTrue(payload["external_effect_permitted"])

    def test_completion_witness_health_minimizes_secrets(self):
        ids = identities()
        with open_witness(":memory:", ids) as witness:
            app = ExternalCompletionWitnessHTTPApplication(
                witness, clock=lambda: 1, client_token_sha256=None,
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
            )
            status, payload = app.handle("GET", "/healthz")
            encoded = str(payload).lower()
            self.assertEqual(status, 200)
            self.assertNotIn("private", encoded)
            self.assertNotIn("token", encoded)

    def test_provider_http_exposes_authenticated_signed_outcome_receipt(self):
        ids = identities()
        intent = make_intent()
        token = "provider-client-secret-v329"
        with open_provider(":memory:", ids) as provider:
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:http-receipt", now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:http-receipt",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=F, now_tick=2,
            )
            app = IdempotentEffectProviderHTTPApplication(
                provider, clock=lambda: 3,
                client_token_sha256=hashlib.sha256(token.encode()).hexdigest(), response_ttl=10,
            )
            denied, _ = app.handle(
                "POST", "/v1/effects/outcome-receipt", {"effect_id": intent["effect_id"]}
            )
            accepted, payload = app.handle(
                "POST", "/v1/effects/outcome-receipt", {"effect_id": intent["effect_id"]},
                {"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(denied, 403)
            self.assertEqual(accepted, 200)
            self.assertEqual(
                payload["signed_provider_outcome_receipt"]["inner_contract"]["state"], "COMPLETED"
            )


if __name__ == "__main__":
    unittest.main()
