from __future__ import annotations

from contextlib import ExitStack
import copy
import hashlib
import unittest

from tests.test_v3_29_execution_head_quorum_and_completion_witness import (
    B,
    C,
    D,
    E,
    F,
    LEDGER_AUTHORITY_ID,
    LEDGER_DOMAIN,
    LEDGER_ID,
    LEDGER_SIGNER_ID,
    PROVIDER_DOMAIN,
    PROVIDER_ID,
    PROVIDER_SERVICE_ID,
    PROVIDER_SIGNER_ID,
    anchor,
    identities,
    issue_head_responses,
    make_intent,
    open_head,
    open_ledger,
    open_provider,
    quorum_config,
)
from triaxis.completion_witness_quorum import (
    CompletionWitnessQuorumError,
    make_completion_witness_quorum_config,
    sign_completion_witness_quorum_witness,
    validate_completion_witness_quorum_config,
    verify_completion_witness_quorum,
    verify_completion_witness_quorum_witness,
    verify_external_effect_guard_with_completion_quorum_and_worm_anchor,
)
from triaxis.completion_worm_anchor import (
    CompletionWORMAnchorError,
    SQLiteCompletionWORMAnchor,
    verify_completion_worm_anchor_event_chain,
    verify_completion_worm_anchor_head,
    verify_completion_worm_anchor_status,
)
from triaxis.completion_worm_anchor_http import CompletionWORMAnchorHTTPApplication
from triaxis.crypto_trust import (
    PURPOSE_COMPLETION_WITNESS_QUORUM,
    PURPOSE_COMPLETION_WORM_ANCHOR,
    PURPOSE_EXTERNAL_COMPLETION_WITNESS,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.external_completion_witness import SQLiteExternalCompletionWitness
from triaxis.integrity import canonical_sha256, seal_mapping
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

ANCHOR_ID = "completion-worm-anchor:v330"
ANCHOR_AUTHORITY_ID = "authority:completion-worm-anchor:v330"
ANCHOR_SERVICE_ID = "service:completion-worm-anchor:v330"
ANCHOR_SIGNER_ID = "signer:completion-worm-anchor:v330"
ANCHOR_DOMAIN = "domain:completion-worm-anchor:v330"
QUORUM_SIGNER_ID = "signer:completion-witness-quorum:v330"
QUORUM_DOMAIN = "domain:completion-witness-quorum:v330"


def v330_identities() -> dict:
    result = identities()
    witness_rows: list[dict] = []
    witness_records: list[dict] = []
    for suffix in ("a", "b", "c"):
        pair = generate_ed25519_keypair()
        row = {
            "witness_id": f"completion-witness:v330:{suffix}",
            "authority_id": f"authority:completion-witness:v330:{suffix}",
            "service_id": f"service:completion-witness:v330:{suffix}",
            "key_id": f"key:completion-witness:v330:{suffix}",
            "signer_id": f"signer:completion-witness:v330:{suffix}",
            "trust_domain": f"domain:completion-witness:v330:{suffix}",
            "pair": pair,
        }
        witness_rows.append(row)
        witness_records.append(
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
    quorum_pair = generate_ed25519_keypair()
    worm_pair = generate_ed25519_keypair()
    result.update(
        {
            "completion_witness_rows": witness_rows,
            "completion_witness_registry": TrustKeyRegistry(witness_records),
            "completion_quorum_pair": quorum_pair,
            "completion_quorum_registry": TrustKeyRegistry(
                [
                    make_trust_key_record(
                        key_id="key:completion-witness-quorum:v330",
                        signer_id=QUORUM_SIGNER_ID,
                        trust_domain=QUORUM_DOMAIN,
                        public_key_b64=quorum_pair["public_key_b64"],
                        purposes=[PURPOSE_COMPLETION_WITNESS_QUORUM],
                        valid_from=0,
                        valid_until=100_000,
                    )
                ]
            ),
            "worm_pair": worm_pair,
            "worm_registry": TrustKeyRegistry(
                [
                    make_trust_key_record(
                        key_id="key:completion-worm-anchor:v330",
                        signer_id=ANCHOR_SIGNER_ID,
                        trust_domain=ANCHOR_DOMAIN,
                        public_key_b64=worm_pair["public_key_b64"],
                        purposes=[PURPOSE_COMPLETION_WORM_ANCHOR],
                        valid_from=0,
                        valid_until=100_000,
                    )
                ]
            ),
        }
    )
    return result


def open_completion_witness(path: str, ids: dict, index: int) -> SQLiteExternalCompletionWitness:
    row = ids["completion_witness_rows"][index]
    return SQLiteExternalCompletionWitness(
        path,
        witness_id=row["witness_id"],
        authority_id=row["authority_id"],
        service_id=row["service_id"],
        key_id=row["key_id"],
        signer_id=row["signer_id"],
        trust_domain=row["trust_domain"],
        private_key_b64=row["pair"]["private_key_b64"],
        receipt_ttl=1_000,
    )


def open_worm(path: str, ids: dict) -> SQLiteCompletionWORMAnchor:
    return SQLiteCompletionWORMAnchor(
        path,
        anchor_id=ANCHOR_ID,
        authority_id=ANCHOR_AUTHORITY_ID,
        service_id=ANCHOR_SERVICE_ID,
        provider_id=PROVIDER_ID,
        provider_service_id=PROVIDER_SERVICE_ID,
        key_id="key:completion-worm-anchor:v330",
        signer_id=ANCHOR_SIGNER_ID,
        trust_domain=ANCHOR_DOMAIN,
        private_key_b64=ids["worm_pair"]["private_key_b64"],
        receipt_ttl=1_000,
    )


def completion_quorum_config(ids: dict, *, threshold: int = 2) -> dict:
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
        for row in ids["completion_witness_rows"]
    ]
    return make_completion_witness_quorum_config(
        config_id="completion-witness-quorum:v330:primary",
        witness_set_id="completion-witness-set:v330:primary",
        provider_id=PROVIDER_ID,
        provider_service_id=PROVIDER_SERVICE_ID,
        threshold=threshold,
        witnesses=rows,
        valid_from=0,
        valid_until=10_000,
    )


def issue_completion_statuses(
    witnesses: list[SQLiteExternalCompletionWitness],
    *,
    session: VerifierFreshnessSession,
    challenge: str,
    effect_id: str,
    requested_at: int,
    issued_at: int,
) -> list[dict]:
    return [
        witness.issue_status(
            effect_id=effect_id,
            expected_payload_sha256=B,
            expected_provider_id=PROVIDER_ID,
            expected_provider_service_id=PROVIDER_SERVICE_ID,
            challenge=challenge,
            verifier_id=session.verifier_id,
            verifier_epoch_sha256=session.epoch_sha256,
            requested_at=requested_at,
            issued_at=issued_at,
            valid_until=issued_at + 100,
        )
        for witness in witnesses
    ]


def provider_outcome(
    provider,
    *,
    effect_id: str,
    request_id: str,
    outcome: str,
    begin_tick: int,
    outcome_tick: int,
    evidence_sha256: str = F,
) -> dict:
    provider.begin(
        effect_id=effect_id,
        payload_sha256=B,
        provider_request_id=request_id,
        now_tick=begin_tick,
    )
    provider.record_outcome(
        effect_id=effect_id,
        provider_request_id=request_id,
        outcome=outcome,
        provider_response_sha256=E if outcome == "COMPLETED" else None,
        evidence_sha256=evidence_sha256,
        now_tick=outcome_tick,
    )
    return provider.issue_outcome_receipt(
        effect_id=effect_id,
        issued_at=outcome_tick,
        valid_until=outcome_tick + 500,
    )


def ingest_witnesses(witnesses: list[SQLiteExternalCompletionWitness], receipt: dict, ids: dict, tick: int) -> None:
    effect_id = receipt["inner_contract"]["effect_id"]
    request_id = receipt["inner_contract"]["provider_request_id"]
    for witness in witnesses:
        current = witness.get(effect_id)
        if current is None or current["state"] == "NO_EFFECT":
            witness.reserve(
                effect_id=effect_id,
                payload_sha256=B,
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id=request_id,
                now_tick=max(0, tick - 1),
            )
        witness.record_provider_outcome(
            receipt,
            provider_registry=ids["provider_registry"],
            expected_provider_signer_id=PROVIDER_SIGNER_ID,
            expected_provider_trust_domain=PROVIDER_DOMAIN,
            evaluation_tick=tick,
            max_provider_receipt_age=500,
        )


class V330CompletionWitnessQuorumTests(unittest.TestCase):
    def test_two_of_three_absent_witnesses_accept(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            witnesses = [stack.enter_context(open_completion_witness(":memory:", ids, i)) for i in range(2)]
            session = VerifierFreshnessSession.create("verifier:v330:q1", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(1, 20)
            statuses = issue_completion_statuses(
                witnesses, session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=1,
            )
            config = completion_quorum_config(ids)
            result = verify_completion_witness_quorum(
                statuses,
                registry=ids["completion_witness_registry"],
                quorum_config=config,
                expected_quorum_config_sha256=config["config_sha256"],
                expected_effect_id=intent["effect_id"],
                expected_payload_sha256=B,
                expected_provider_id=PROVIDER_ID,
                expected_provider_service_id=PROVIDER_SERVICE_ID,
                challenge_ledger=challenges,
                expected_challenge=challenge,
                evaluation_tick=1,
            )
            self.assertEqual(result["state"], "ABSENT")
            self.assertEqual(result["member_count"], 2)
            self.assertFalse(result["authority_granted"])

    def test_blocking_minority_vetoes_two_absent_votes(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            witnesses = [stack.enter_context(open_completion_witness(":memory:", ids, i)) for i in range(3)]
            provider = stack.enter_context(open_provider(":memory:", ids))
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:veto",
                outcome="COMPLETED", begin_tick=1, outcome_tick=2,
            )
            ingest_witnesses([witnesses[2]], receipt, ids, 2)
            session = VerifierFreshnessSession.create("verifier:v330:q2", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(3, 20)
            statuses = issue_completion_statuses(
                witnesses, session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=3, issued_at=3,
            )
            config = completion_quorum_config(ids)
            with self.assertRaisesRegex(CompletionWitnessQuorumError, "blocking_completion_witness_minority"):
                verify_completion_witness_quorum(
                    statuses,
                    registry=ids["completion_witness_registry"],
                    quorum_config=config,
                    expected_quorum_config_sha256=config["config_sha256"],
                    expected_effect_id=intent["effect_id"],
                    expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges,
                    expected_challenge=challenge,
                    evaluation_tick=3,
                )

    def test_one_stale_response_is_ignored_when_two_current_match(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            witnesses = [stack.enter_context(open_completion_witness(":memory:", ids, i)) for i in range(3)]
            session = VerifierFreshnessSession.create("verifier:v330:q3", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(1, 30)
            stale = issue_completion_statuses(
                [witnesses[0]], session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=1,
            )
            current = issue_completion_statuses(
                witnesses[1:], session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=10,
            )
            config = completion_quorum_config(ids)
            result = verify_completion_witness_quorum(
                stale + current,
                registry=ids["completion_witness_registry"],
                quorum_config=config,
                expected_quorum_config_sha256=config["config_sha256"],
                expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                challenge_ledger=challenges, expected_challenge=challenge,
                evaluation_tick=10, max_response_age=5,
            )
            self.assertEqual(result["member_count"], 2)

    def test_absent_and_no_effect_do_not_launder_into_one_quorum(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            witnesses = [stack.enter_context(open_completion_witness(":memory:", ids, i)) for i in range(2)]
            provider = stack.enter_context(open_provider(":memory:", ids))
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:no-effect",
                outcome="NO_EFFECT", begin_tick=1, outcome_tick=2,
            )
            ingest_witnesses([witnesses[1]], receipt, ids, 2)
            session = VerifierFreshnessSession.create("verifier:v330:q4", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(3, 20)
            statuses = issue_completion_statuses(
                witnesses, session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=3, issued_at=3,
            )
            config = completion_quorum_config(ids)
            with self.assertRaisesRegex(CompletionWitnessQuorumError, "quorum_not_met"):
                verify_completion_witness_quorum(
                    statuses,
                    registry=ids["completion_witness_registry"], quorum_config=config,
                    expected_quorum_config_sha256=config["config_sha256"],
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=3,
                )

    def test_duplicate_response_does_not_add_vote(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            witness = stack.enter_context(open_completion_witness(":memory:", ids, 0))
            session = VerifierFreshnessSession.create("verifier:v330:q5", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(1, 20)
            signed = issue_completion_statuses(
                [witness], session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=1,
            )[0]
            config = completion_quorum_config(ids)
            with self.assertRaisesRegex(CompletionWitnessQuorumError, "quorum_not_met"):
                verify_completion_witness_quorum(
                    [signed, signed], registry=ids["completion_witness_registry"],
                    quorum_config=config, expected_quorum_config_sha256=config["config_sha256"],
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
                )

    def test_signer_equivocation_is_blocked(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            witness = stack.enter_context(open_completion_witness(":memory:", ids, 0))
            session = VerifierFreshnessSession.create("verifier:v330:q6", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(1, 20)
            absent = issue_completion_statuses(
                [witness], session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=1,
            )[0]
            witness.reserve(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_id=PROVIDER_ID, provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id="req:v330:equivocation", now_tick=2,
            )
            reserved = issue_completion_statuses(
                [witness], session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=2,
            )[0]
            config = completion_quorum_config(ids)
            with self.assertRaisesRegex(CompletionWitnessQuorumError, "equivocation"):
                verify_completion_witness_quorum(
                    [absent, reserved], registry=ids["completion_witness_registry"],
                    quorum_config=config, expected_quorum_config_sha256=config["config_sha256"],
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=2,
                )

    def test_unpinned_identity_cannot_form_quorum(self):
        ids = v330_identities()
        intent = make_intent()
        rogue_pair = generate_ed25519_keypair()
        rogue_record = make_trust_key_record(
            key_id="key:completion-witness:v330:rogue", signer_id="signer:completion-witness:v330:rogue",
            trust_domain="domain:completion-witness:v330:rogue",
            public_key_b64=rogue_pair["public_key_b64"], purposes=[PURPOSE_EXTERNAL_COMPLETION_WITNESS],
            valid_from=0, valid_until=100_000,
        )
        registry = TrustKeyRegistry(ids["completion_witness_registry"].as_records() + [rogue_record])
        with ExitStack() as stack:
            pinned = stack.enter_context(open_completion_witness(":memory:", ids, 0))
            rogue = stack.enter_context(
                SQLiteExternalCompletionWitness(
                    ":memory:", witness_id="completion-witness:v330:rogue",
                    authority_id="authority:completion-witness:v330:rogue",
                    service_id="service:completion-witness:v330:rogue",
                    key_id="key:completion-witness:v330:rogue",
                    signer_id="signer:completion-witness:v330:rogue",
                    trust_domain="domain:completion-witness:v330:rogue",
                    private_key_b64=rogue_pair["private_key_b64"], receipt_ttl=100,
                )
            )
            session = VerifierFreshnessSession.create("verifier:v330:q7", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(1, 20)
            statuses = issue_completion_statuses(
                [pinned, rogue], session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=1,
            )
            config = completion_quorum_config(ids)
            with self.assertRaisesRegex(CompletionWitnessQuorumError, "quorum_not_met"):
                verify_completion_witness_quorum(
                    statuses, registry=registry, quorum_config=config,
                    expected_quorum_config_sha256=config["config_sha256"],
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
                )

    def test_config_substitution_is_blocked(self):
        ids = v330_identities()
        config = completion_quorum_config(ids)
        substituted = copy.deepcopy(config)
        substituted["config_id"] = "completion-witness-quorum:v330:substituted"
        substituted = seal_mapping(substituted, "config_sha256")
        result = validate_completion_witness_quorum_config(substituted, 1)
        self.assertEqual(result["status"], "PASS")
        intent = make_intent()
        with ExitStack() as stack:
            witnesses = [stack.enter_context(open_completion_witness(":memory:", ids, i)) for i in range(2)]
            session = VerifierFreshnessSession.create("verifier:v330:q8", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(1, 20)
            statuses = issue_completion_statuses(
                witnesses, session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=1,
            )
            with self.assertRaisesRegex(CompletionWitnessQuorumError, "config_substitution"):
                verify_completion_witness_quorum(
                    statuses, registry=ids["completion_witness_registry"],
                    quorum_config=substituted, expected_quorum_config_sha256=config["config_sha256"],
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
                )

    def test_threshold_requires_distinct_domains(self):
        ids = v330_identities()
        rows = copy.deepcopy(ids["completion_witness_rows"])
        rows[1]["trust_domain"] = rows[0]["trust_domain"]
        config = make_completion_witness_quorum_config(
            config_id="cfg", witness_set_id="set", provider_id=PROVIDER_ID,
            provider_service_id=PROVIDER_SERVICE_ID, threshold=3, witnesses=rows,
            valid_from=0, valid_until=100,
        )
        result = validate_completion_witness_quorum_config(config, 1)
        self.assertEqual(result["status"], "BLOCK")
        self.assertTrue(any(row["code"] == "insufficient_domain_diversity" for row in result["errors"]))

    def test_signed_quorum_witness_verifies_against_pinned_config(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            witnesses = [stack.enter_context(open_completion_witness(":memory:", ids, i)) for i in range(2)]
            session = VerifierFreshnessSession.create("verifier:v330:q9", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(1, 20)
            statuses = issue_completion_statuses(
                witnesses, session=session, challenge=challenge,
                effect_id=intent["effect_id"], requested_at=1, issued_at=1,
            )
            config = completion_quorum_config(ids)
            result = verify_completion_witness_quorum(
                statuses, registry=ids["completion_witness_registry"], quorum_config=config,
                expected_quorum_config_sha256=config["config_sha256"],
                expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
            )
            signed = sign_completion_witness_quorum_witness(
                result["quorum_witness"], key_id="key:completion-witness-quorum:v330",
                signer_id=QUORUM_SIGNER_ID, trust_domain=QUORUM_DOMAIN,
                private_key_b64=ids["completion_quorum_pair"]["private_key_b64"],
                issued_at=1, valid_until=20,
            )
            verified = verify_completion_witness_quorum_witness(
                signed, registry=ids["completion_quorum_registry"],
                expected_signer_id=QUORUM_SIGNER_ID, expected_trust_domain=QUORUM_DOMAIN,
                quorum_config=config, expected_quorum_config_sha256=config["config_sha256"],
                expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                evaluation_tick=1,
            )
            self.assertEqual(verified["verified_member_count"], 2)
            self.assertFalse(verified["authority_granted"])


class V330CompletionWORMAnchorTests(unittest.TestCase):
    def test_completed_receipt_is_anchored_and_blocks_retry(self):
        ids = v330_identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as worm:
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:worm:1",
                outcome="COMPLETED", begin_tick=1, outcome_tick=2,
            )
            result = worm.ingest_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            self.assertEqual(result["effect"]["state"], "COMPLETED")
            session = VerifierFreshnessSession.create("verifier:v330:worm:1", 0)
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                challenge = challenges.issue(3, 20)
                status = worm.issue_status(
                    effect_id=intent["effect_id"], expected_payload_sha256=B,
                    challenge=challenge, verifier_id=session.verifier_id,
                    verifier_epoch_sha256=session.epoch_sha256, requested_at=3, issued_at=3,
                )
                with self.assertRaisesRegex(CompletionWORMAnchorError, "state_blocks_retry"):
                    verify_completion_worm_anchor_status(
                        status, registry=ids["worm_registry"], expected_anchor_id=ANCHOR_ID,
                        expected_authority_id=ANCHOR_AUTHORITY_ID, expected_service_id=ANCHOR_SERVICE_ID,
                        expected_signer_id=ANCHOR_SIGNER_ID, expected_trust_domain=ANCHOR_DOMAIN,
                        expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=3,
                    )

    def test_exact_provider_outcome_replay_is_idempotent(self):
        ids = v330_identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as worm:
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:worm:2",
                outcome="COMPLETED", begin_tick=1, outcome_tick=2,
            )
            first = worm.ingest_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            second = worm.ingest_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            self.assertFalse(first["idempotent_replay"])
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(worm.event_count(), 1)

    def test_payload_substitution_is_blocked(self):
        ids = v330_identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as worm:
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:worm:3",
                outcome="COMPLETED", begin_tick=1, outcome_tick=2,
            )
            worm.ingest_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            tampered = copy.deepcopy(receipt)
            tampered["inner_contract"]["payload_sha256"] = C
            with self.assertRaises(CompletionWORMAnchorError):
                worm.ingest_provider_outcome(
                    tampered, provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
                )

    def test_unknown_can_reconcile_to_completed(self):
        ids = v330_identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as worm:
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="req:v330:worm:4", now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="req:v330:worm:4",
                outcome="UNKNOWN", provider_response_sha256=None, evidence_sha256=F, now_tick=2,
            )
            unknown = provider.issue_outcome_receipt(
                effect_id=intent["effect_id"], issued_at=2, valid_until=100,
            )
            worm.ingest_provider_outcome(
                unknown, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            provider.reconcile_unknown(
                effect_id=intent["effect_id"], provider_request_id="req:v330:worm:4",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=D, now_tick=3,
            )
            completed = provider.issue_outcome_receipt(
                effect_id=intent["effect_id"], issued_at=3, valid_until=100,
            )
            result = worm.ingest_provider_outcome(
                completed, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=3,
            )
            self.assertEqual(result["effect"]["state"], "COMPLETED")
            self.assertEqual(worm.event_count(), 2)

    def test_no_effect_opens_next_generation(self):
        ids = v330_identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as worm:
            first = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:worm:5:a",
                outcome="NO_EFFECT", begin_tick=1, outcome_tick=2,
            )
            worm.ingest_provider_outcome(
                first, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="req:v330:worm:5:b", now_tick=3,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="req:v330:worm:5:b",
                outcome="COMPLETED", provider_response_sha256=E, evidence_sha256=D, now_tick=4,
            )
            second = provider.issue_outcome_receipt(
                effect_id=intent["effect_id"], issued_at=4, valid_until=100,
            )
            result = worm.ingest_provider_outcome(
                second, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=4,
            )
            self.assertEqual(result["effect"]["generation"], 2)
            self.assertEqual(result["effect"]["state"], "COMPLETED")

    def test_event_chain_and_head_verify(self):
        ids = v330_identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as worm:
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:worm:6",
                outcome="COMPLETED", begin_tick=1, outcome_tick=2,
            )
            worm.ingest_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            chain = verify_completion_worm_anchor_event_chain(
                worm.events_since(0), registry=ids["worm_registry"],
                expected_anchor_id=ANCHOR_ID, expected_authority_id=ANCHOR_AUTHORITY_ID,
                expected_service_id=ANCHOR_SERVICE_ID, expected_provider_id=PROVIDER_ID,
                expected_provider_service_id=PROVIDER_SERVICE_ID,
                expected_signer_id=ANCHOR_SIGNER_ID, expected_trust_domain=ANCHOR_DOMAIN,
                evaluation_tick=2,
            )
            head = worm.head(now_tick=2)
            verified = verify_completion_worm_anchor_head(
                head, registry=ids["worm_registry"], expected_anchor_id=ANCHOR_ID,
                expected_authority_id=ANCHOR_AUTHORITY_ID, expected_service_id=ANCHOR_SERVICE_ID,
                expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                expected_signer_id=ANCHOR_SIGNER_ID, expected_trust_domain=ANCHOR_DOMAIN,
                evaluation_tick=2, expected_sequence=chain["head_sequence"],
                expected_head_event_sha256=chain["head_event_sha256"],
            )
            self.assertEqual(verified["status"], "PASS")
            self.assertFalse(verified["authority_granted"])

    def test_chain_parent_substitution_is_blocked(self):
        ids = v330_identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as worm:
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:worm:7",
                outcome="UNKNOWN", begin_tick=1, outcome_tick=2,
            )
            worm.ingest_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            events = worm.events_since(0)
            tampered = copy.deepcopy(events[0])
            tampered["inner_contract"]["previous_event_sha256"] = C
            with self.assertRaises(CompletionWORMAnchorError):
                verify_completion_worm_anchor_event_chain(
                    [tampered], registry=ids["worm_registry"],
                    expected_anchor_id=ANCHOR_ID, expected_authority_id=ANCHOR_AUTHORITY_ID,
                    expected_service_id=ANCHOR_SERVICE_ID, expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    expected_signer_id=ANCHOR_SIGNER_ID, expected_trust_domain=ANCHOR_DOMAIN,
                    evaluation_tick=2,
                )

    def test_absent_status_is_fresh_and_single_use(self):
        ids = v330_identities()
        intent = make_intent()
        with open_worm(":memory:", ids) as worm:
            session = VerifierFreshnessSession.create("verifier:v330:worm:8", 0)
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                challenge = challenges.issue(1, 20)
                status = worm.issue_status(
                    effect_id=intent["effect_id"], expected_payload_sha256=B,
                    challenge=challenge, verifier_id=session.verifier_id,
                    verifier_epoch_sha256=session.epoch_sha256, requested_at=1, issued_at=1,
                )
                result = verify_completion_worm_anchor_status(
                    status, registry=ids["worm_registry"], expected_anchor_id=ANCHOR_ID,
                    expected_authority_id=ANCHOR_AUTHORITY_ID, expected_service_id=ANCHOR_SERVICE_ID,
                    expected_signer_id=ANCHOR_SIGNER_ID, expected_trust_domain=ANCHOR_DOMAIN,
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
                )
                self.assertTrue(result["external_effect_permitted"])
                with self.assertRaises(Exception):
                    verify_completion_worm_anchor_status(
                        status, registry=ids["worm_registry"], expected_anchor_id=ANCHOR_ID,
                        expected_authority_id=ANCHOR_AUTHORITY_ID, expected_service_id=ANCHOR_SERVICE_ID,
                        expected_signer_id=ANCHOR_SIGNER_ID, expected_trust_domain=ANCHOR_DOMAIN,
                        expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=1,
                    )

    def test_http_requires_auth_for_ingest_and_minimizes_health(self):
        ids = v330_identities()
        intent = make_intent()
        token = "worm-client-v330"
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as worm:
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:worm:http",
                outcome="COMPLETED", begin_tick=1, outcome_tick=2,
            )
            app = CompletionWORMAnchorHTTPApplication(
                worm, clock=lambda: 2,
                client_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
            )
            denied, _ = app.handle(
                "POST", "/v1/outcomes/ingest", {"signed_provider_receipt": receipt}
            )
            accepted, payload = app.handle(
                "POST", "/v1/outcomes/ingest", {"signed_provider_receipt": receipt},
                {"Authorization": f"Bearer {token}"},
            )
            health_status, health = app.handle("GET", "/healthz")
            self.assertEqual(denied, 403)
            self.assertEqual(accepted, 200)
            self.assertEqual(payload["effect"]["state"], "COMPLETED")
            self.assertEqual(health_status, 200)
            encoded = str(health).lower()
            self.assertNotIn("private", encoded)
            self.assertNotIn("token", encoded)


class V330ComposedGuardTests(unittest.TestCase):
    def test_full_preflight_requires_both_quorums_and_worm_anchor(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, i)) for i in range(3)]
            provider = stack.enter_context(open_provider(":memory:", ids))
            witnesses = [stack.enter_context(open_completion_witness(":memory:", ids, i)) for i in range(3)]
            worm = stack.enter_context(open_worm(":memory:", ids))
            anchor(heads, ledger, 1)
            dispatch = canonical_sha256({"dispatch": "v330:guard"})
            ledger.reserve(intent, attempt_id="attempt:v330:guard", dispatch_id=dispatch, now_tick=2)
            started = ledger.start(
                intent["effect_id"], attempt_id="attempt:v330:guard",
                dispatch_id=dispatch, now_tick=3,
            )
            anchor(heads, ledger, 3)

            head_session = VerifierFreshnessSession.create("verifier:v330:guard:head", 0)
            head_challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", head_session))
            head_challenge = head_challenges.issue(4, 20)
            head_statuses = issue_head_responses(
                heads[:2], session=head_session, challenge=head_challenge,
                requested_at=4, issued_at=4,
            )

            provider_session = VerifierFreshnessSession.create("verifier:v330:guard:provider", 0)
            provider_challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", provider_session))
            provider_challenge = provider_challenges.issue(4, 20)
            provider_status = provider.issue_status(
                effect_id=intent["effect_id"], expected_payload_sha256=B,
                challenge=provider_challenge, verifier_id=provider_session.verifier_id,
                verifier_epoch_sha256=provider_session.epoch_sha256, requested_at=4, issued_at=4,
            )

            completion_session = VerifierFreshnessSession.create("verifier:v330:guard:completion", 0)
            completion_challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", completion_session))
            completion_challenge = completion_challenges.issue(4, 20)
            completion_statuses = issue_completion_statuses(
                witnesses[:2], session=completion_session, challenge=completion_challenge,
                effect_id=intent["effect_id"], requested_at=4, issued_at=4,
            )

            worm_session = VerifierFreshnessSession.create("verifier:v330:guard:worm", 0)
            worm_challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", worm_session))
            worm_challenge = worm_challenges.issue(4, 20)
            worm_status = worm.issue_status(
                effect_id=intent["effect_id"], expected_payload_sha256=B,
                challenge=worm_challenge, verifier_id=worm_session.verifier_id,
                verifier_epoch_sha256=worm_session.epoch_sha256, requested_at=4, issued_at=4,
            )

            hconfig = quorum_config(ids)
            cconfig = completion_quorum_config(ids)
            result = verify_external_effect_guard_with_completion_quorum_and_worm_anchor(
                intent, started["signed_receipt"],
                expected_attempt_id="attempt:v330:guard", expected_dispatch_id=dispatch,
                evaluation_tick=4, signed_local_head=ledger.head(now_tick=4),
                signed_head_responses=head_statuses, ledger_registry=ids["ledger_registry"],
                head_authority_registry=ids["head_registry"], expected_ledger_id=LEDGER_ID,
                expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID,
                expected_ledger_trust_domain=LEDGER_DOMAIN,
                head_quorum_config=hconfig,
                expected_head_quorum_config_sha256=hconfig["config_sha256"],
                head_challenge_ledger=head_challenges, expected_head_challenge=head_challenge,
                signed_provider_status=provider_status, provider_registry=ids["provider_registry"],
                expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                expected_provider_payload_sha256=B, provider_challenge_ledger=provider_challenges,
                expected_provider_challenge=provider_challenge,
                signed_completion_witness_statuses=completion_statuses,
                completion_witness_registry=ids["completion_witness_registry"],
                completion_quorum_config=cconfig,
                expected_completion_quorum_config_sha256=cconfig["config_sha256"],
                completion_challenge_ledger=completion_challenges,
                expected_completion_challenge=completion_challenge,
                signed_worm_anchor_status=worm_status, worm_anchor_registry=ids["worm_registry"],
                expected_worm_anchor_id=ANCHOR_ID,
                expected_worm_anchor_authority_id=ANCHOR_AUTHORITY_ID,
                expected_worm_anchor_service_id=ANCHOR_SERVICE_ID,
                expected_worm_anchor_signer_id=ANCHOR_SIGNER_ID,
                expected_worm_anchor_trust_domain=ANCHOR_DOMAIN,
                worm_anchor_challenge_ledger=worm_challenges,
                expected_worm_anchor_challenge=worm_challenge,
            )
            self.assertEqual(result["status"], "PASS")
            self.assertFalse(result["authority_granted"])

    def test_current_worm_anchor_blocks_rolled_back_provider_and_witness_threshold(self):
        ids = v330_identities()
        intent = make_intent()
        with ExitStack() as stack:
            provider = stack.enter_context(open_provider(":memory:", ids))
            witnesses = [stack.enter_context(open_completion_witness(":memory:", ids, i)) for i in range(3)]
            worm = stack.enter_context(open_worm(":memory:", ids))
            receipt = provider_outcome(
                provider, effect_id=intent["effect_id"], request_id="req:v330:guard:block",
                outcome="COMPLETED", begin_tick=1, outcome_tick=2,
            )
            # Only the durable external anchor remains current; two rolled-back
            # witness replicas are represented by clean stores.
            worm.ingest_provider_outcome(
                receipt, provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN, evaluation_tick=2,
            )
            session = VerifierFreshnessSession.create("verifier:v330:guard:block:worm", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(3, 20)
            status = worm.issue_status(
                effect_id=intent["effect_id"], expected_payload_sha256=B,
                challenge=challenge, verifier_id=session.verifier_id,
                verifier_epoch_sha256=session.epoch_sha256, requested_at=3, issued_at=3,
            )
            with self.assertRaisesRegex(CompletionWORMAnchorError, "state_blocks_retry"):
                verify_completion_worm_anchor_status(
                    status, registry=ids["worm_registry"], expected_anchor_id=ANCHOR_ID,
                    expected_authority_id=ANCHOR_AUTHORITY_ID, expected_service_id=ANCHOR_SERVICE_ID,
                    expected_signer_id=ANCHOR_SIGNER_ID, expected_trust_domain=ANCHOR_DOMAIN,
                    expected_effect_id=intent["effect_id"], expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges, expected_challenge=challenge, evaluation_tick=3,
                )


if __name__ == "__main__":
    unittest.main()
