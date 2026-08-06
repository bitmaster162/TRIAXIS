from __future__ import annotations

from contextlib import ExitStack
import hashlib
from pathlib import Path
import tempfile
import unittest

from tests.test_v3_29_execution_head_quorum_and_completion_witness import (
    B,
    E,
    F,
    PROVIDER_DOMAIN,
    PROVIDER_ID,
    PROVIDER_SERVICE_ID,
    PROVIDER_SIGNER_ID,
    LEDGER_AUTHORITY_ID,
    LEDGER_DOMAIN,
    LEDGER_ID,
    LEDGER_SIGNER_ID,
    anchor,
    issue_head_responses,
    make_intent,
    open_head,
    open_ledger,
    open_provider,
    quorum_config,
)
from tests.test_v3_30_completion_witness_quorum_and_worm_anchor import (
    completion_quorum_config,
    issue_completion_statuses,
    open_completion_witness,
    provider_outcome,
    open_worm,
    ANCHOR_ID,
    ANCHOR_AUTHORITY_ID,
    ANCHOR_SERVICE_ID,
    ANCHOR_SIGNER_ID,
    ANCHOR_DOMAIN,
    v330_identities,
)
from triaxis.completion_availability_control import (
    AVAILABILITY_MODE_ALL_CONFIGURED,
    CompletionAvailabilityError,
    make_completion_availability_policy,
    sign_completion_availability_witness,
    validate_completion_availability_policy,
    verify_availability_closed_completion_quorum,
    verify_completion_availability_witness,
    verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor,
)
from triaxis.completion_immutable_anchor import (
    CompletionImmutableAnchorError,
    FilesystemImmutableCompletionAnchor,
    SQLiteImmutableAnchorCheckpointLedger,
    verify_completion_immutable_anchor_event_chain,
    verify_completion_immutable_anchor_head,
    verify_completion_immutable_anchor_status,
    verify_completion_immutable_object_receipt,
)
from triaxis.completion_immutable_anchor_http import (
    CompletionImmutableAnchorHTTPApplication,
)
from triaxis.crypto_trust import (
    PURPOSE_COMPLETION_AVAILABILITY_CONTROL,
    PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.integrity import canonical_sha256, seal_mapping
from triaxis.trust_registry_quorum import (
    SQLiteEpochChallengeLedger,
    VerifierFreshnessSession,
)

AVAILABILITY_SIGNER_ID = "signer:completion-availability:v331"
AVAILABILITY_DOMAIN = "domain:completion-availability:v331"
IMMUTABLE_ANCHOR_ID = "completion-immutable-anchor:v331"
IMMUTABLE_AUTHORITY_ID = "authority:completion-immutable-anchor:v331"
IMMUTABLE_SERVICE_ID = "service:completion-immutable-anchor:v331"
IMMUTABLE_SIGNER_ID = "signer:completion-immutable-anchor:v331"
IMMUTABLE_DOMAIN = "domain:completion-immutable-anchor:v331"
RETENTION_POLICY_ID = "retention:completion:v331:high-risk"


def identities_v331() -> dict:
    ids = v330_identities()
    availability_pair = generate_ed25519_keypair()
    immutable_pair = generate_ed25519_keypair()
    ids.update(
        {
            "availability_pair": availability_pair,
            "availability_registry": TrustKeyRegistry(
                [
                    make_trust_key_record(
                        key_id="key:completion-availability:v331",
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
                        key_id="key:completion-immutable-anchor:v331",
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


def availability_policy(ids: dict, *, risk_class: str = "HIGH") -> dict:
    config = completion_quorum_config(ids)
    return make_completion_availability_policy(
        policy_id="completion-availability:v331:high-risk",
        completion_quorum_config_sha256=config["config_sha256"],
        risk_class=risk_class,
        required_witness_count=len(config["witnesses"]),
        valid_from=0,
        valid_until=10_000,
    )


def open_immutable_anchor(root: str | Path, ids: dict) -> FilesystemImmutableCompletionAnchor:
    return FilesystemImmutableCompletionAnchor(
        root,
        anchor_id=IMMUTABLE_ANCHOR_ID,
        authority_id=IMMUTABLE_AUTHORITY_ID,
        service_id=IMMUTABLE_SERVICE_ID,
        provider_id=PROVIDER_ID,
        provider_service_id=PROVIDER_SERVICE_ID,
        retention_policy_id=RETENTION_POLICY_ID,
        key_id="key:completion-immutable-anchor:v331",
        signer_id=IMMUTABLE_SIGNER_ID,
        trust_domain=IMMUTABLE_DOMAIN,
        private_key_b64=ids["immutable_pair"]["private_key_b64"],
        minimum_retention_ticks=100,
        receipt_ttl=100,
    )


def all_absent_statuses(ids: dict, witnesses: list, effect_id: str, *, tick: int = 10):
    session = VerifierFreshnessSession.create(
        f"verifier:v331:availability:{tick}", 0
    )
    ledger = SQLiteEpochChallengeLedger(":memory:", session)
    challenge = ledger.issue(1, 100)
    statuses = issue_completion_statuses(
        witnesses,
        session=session,
        challenge=challenge,
        effect_id=effect_id,
        requested_at=1,
        issued_at=tick,
    )
    return session, ledger, challenge, statuses


class V331AvailabilityClosedCompletionTests(unittest.TestCase):
    def test_all_configured_absent_witnesses_pass(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            _, ledger, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id
            )
            with ledger:
                result = verify_availability_closed_completion_quorum(
                    statuses,
                    registry=ids["completion_witness_registry"],
                    quorum_config=config,
                    expected_quorum_config_sha256=config["config_sha256"],
                    availability_policy=policy,
                    expected_availability_policy_sha256=policy["policy_sha256"],
                    expected_effect_id=effect_id,
                    expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=ledger,
                    expected_challenge=challenge,
                    evaluation_tick=10,
                )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["responding_witness_count"], 3)
        self.assertEqual(
            result["availability_witness"]["availability_mode"],
            AVAILABILITY_MODE_ALL_CONFIGURED,
        )

    def test_missing_configured_witness_blocks_even_when_threshold_exists(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            _, ledger, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id
            )
            with ledger:
                with self.assertRaises(CompletionAvailabilityError) as caught:
                    verify_availability_closed_completion_quorum(
                        statuses[:2],
                        registry=ids["completion_witness_registry"],
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        availability_policy=policy,
                        expected_availability_policy_sha256=policy["policy_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=ledger,
                        expected_challenge=challenge,
                        evaluation_tick=10,
                    )
        self.assertEqual(
            caught.exception.code, "completion_availability_witness_set_incomplete"
        )

    def test_one_stale_witness_blocks_closed_set(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            session = VerifierFreshnessSession.create("verifier:v331:stale", 0)
            with SQLiteEpochChallengeLedger(":memory:", session) as ledger:
                challenge = ledger.issue(1, 100)
                statuses = []
                for index, witness in enumerate(witnesses):
                    statuses.append(
                        witness.issue_status(
                            effect_id=effect_id,
                            expected_payload_sha256=B,
                            expected_provider_id=PROVIDER_ID,
                            expected_provider_service_id=PROVIDER_SERVICE_ID,
                            challenge=challenge,
                            verifier_id=session.verifier_id,
                            verifier_epoch_sha256=session.epoch_sha256,
                            requested_at=1,
                            issued_at=2 if index == 2 else 10,
                            valid_until=50,
                        )
                    )
                with self.assertRaises(CompletionAvailabilityError) as caught:
                    verify_availability_closed_completion_quorum(
                        statuses,
                        registry=ids["completion_witness_registry"],
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        availability_policy=policy,
                        expected_availability_policy_sha256=policy["policy_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=ledger,
                        expected_challenge=challenge,
                        evaluation_tick=10,
                        max_response_age=5,
                    )
        self.assertEqual(
            caught.exception.code, "completion_availability_witness_set_incomplete"
        )

    def test_disagreeing_permissive_states_do_not_form_closed_set(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            provider = stack.enter_context(open_provider(":memory:", ids))
            receipt = provider_outcome(
                provider,
                effect_id=effect_id,
                request_id="provider-request:v331:no-effect",
                outcome="NO_EFFECT",
                begin_tick=2,
                outcome_tick=3,
            )
            witnesses[2].reserve(
                effect_id=effect_id,
                payload_sha256=B,
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id="provider-request:v331:no-effect",
                now_tick=2,
            )
            witnesses[2].record_provider_outcome(
                receipt,
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                evaluation_tick=3,
            )
            _, ledger, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id
            )
            with ledger:
                with self.assertRaises(CompletionAvailabilityError) as caught:
                    verify_availability_closed_completion_quorum(
                        statuses,
                        registry=ids["completion_witness_registry"],
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        availability_policy=policy,
                        expected_availability_policy_sha256=policy["policy_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=ledger,
                        expected_challenge=challenge,
                        evaluation_tick=10,
                    )
        self.assertEqual(
            caught.exception.code, "completion_availability_witness_set_incomplete"
        )

    def test_blocking_member_still_vetoes_closed_set(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            provider = stack.enter_context(open_provider(":memory:", ids))
            receipt = provider_outcome(
                provider,
                effect_id=effect_id,
                request_id="provider-request:v331:completed",
                outcome="COMPLETED",
                begin_tick=2,
                outcome_tick=3,
            )
            witnesses[2].reserve(
                effect_id=effect_id,
                payload_sha256=B,
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id="provider-request:v331:completed",
                now_tick=2,
            )
            witnesses[2].record_provider_outcome(
                receipt,
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                evaluation_tick=3,
            )
            _, ledger, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id
            )
            with ledger:
                with self.assertRaises(CompletionAvailabilityError) as caught:
                    verify_availability_closed_completion_quorum(
                        statuses,
                        registry=ids["completion_witness_registry"],
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        availability_policy=policy,
                        expected_availability_policy_sha256=policy["policy_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=ledger,
                        expected_challenge=challenge,
                        evaluation_tick=10,
                    )
        self.assertEqual(caught.exception.code, "blocking_completion_witness_minority")

    def test_policy_required_count_must_match_pinned_set(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = make_completion_availability_policy(
            policy_id="completion-availability:v331:wrong-count",
            completion_quorum_config_sha256=config["config_sha256"],
            risk_class="HIGH",
            required_witness_count=2,
            valid_from=0,
            valid_until=100,
        )
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            _, ledger, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id
            )
            with ledger:
                with self.assertRaises(CompletionAvailabilityError) as caught:
                    verify_availability_closed_completion_quorum(
                        statuses,
                        registry=ids["completion_witness_registry"],
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        availability_policy=policy,
                        expected_availability_policy_sha256=policy["policy_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=ledger,
                        expected_challenge=challenge,
                        evaluation_tick=10,
                    )
        self.assertEqual(
            caught.exception.code,
            "completion_availability_required_count_mismatch",
        )

    def test_allowed_state_expansion_cannot_relabel_completed_as_permissive(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            _, ledger, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id
            )
            with ledger:
                with self.assertRaises(CompletionAvailabilityError) as caught:
                    verify_availability_closed_completion_quorum(
                        statuses,
                        registry=ids["completion_witness_registry"],
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        availability_policy=policy,
                        expected_availability_policy_sha256=policy["policy_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=ledger,
                        expected_challenge=challenge,
                        evaluation_tick=10,
                        allowed_states=("ABSENT", "NO_EFFECT", "COMPLETED"),
                    )
        self.assertEqual(
            caught.exception.code,
            "invalid_completion_availability_allowed_states",
        )

    def test_empty_allowed_state_set_fails_closed(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            _, ledger, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id
            )
            with ledger:
                with self.assertRaises(CompletionAvailabilityError) as caught:
                    verify_availability_closed_completion_quorum(
                        statuses,
                        registry=ids["completion_witness_registry"],
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        availability_policy=policy,
                        expected_availability_policy_sha256=policy["policy_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=B,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=ledger,
                        expected_challenge=challenge,
                        evaluation_tick=10,
                        allowed_states=(),
                    )
        self.assertEqual(
            caught.exception.code,
            "invalid_completion_availability_allowed_states",
        )

    def test_policy_rejects_non_closed_mode(self):
        ids = identities_v331()
        policy = availability_policy(ids)
        policy["availability_mode"] = "THRESHOLD_ONLY"
        policy = seal_mapping(policy, "policy_sha256")
        result = validate_completion_availability_policy(policy, evaluation_tick=10)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn(
            "availability_mode_not_closed",
            {error["code"] for error in result["errors"]},
        )

    def test_signed_availability_witness_verifies(self):
        ids = identities_v331()
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            _, ledger, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id
            )
            with ledger:
                result = verify_availability_closed_completion_quorum(
                    statuses,
                    registry=ids["completion_witness_registry"],
                    quorum_config=config,
                    expected_quorum_config_sha256=config["config_sha256"],
                    availability_policy=policy,
                    expected_availability_policy_sha256=policy["policy_sha256"],
                    expected_effect_id=effect_id,
                    expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=ledger,
                    expected_challenge=challenge,
                    evaluation_tick=10,
                )
        signed = sign_completion_availability_witness(
            result["availability_witness"],
            key_id="key:completion-availability:v331",
            signer_id=AVAILABILITY_SIGNER_ID,
            trust_domain=AVAILABILITY_DOMAIN,
            private_key_b64=ids["availability_pair"]["private_key_b64"],
            issued_at=10,
            valid_until=100,
        )
        verified = verify_completion_availability_witness(
            signed,
            registry=ids["availability_registry"],
            expected_signer_id=AVAILABILITY_SIGNER_ID,
            expected_trust_domain=AVAILABILITY_DOMAIN,
            availability_policy=policy,
            expected_availability_policy_sha256=policy["policy_sha256"],
            quorum_config=config,
            expected_quorum_config_sha256=config["config_sha256"],
            expected_effect_id=effect_id,
            expected_payload_sha256=B,
            expected_provider_id=PROVIDER_ID,
            expected_provider_service_id=PROVIDER_SERVICE_ID,
            evaluation_tick=10,
        )
        self.assertEqual(verified["verified_member_count"], 3)


class V331ImmutableCompletionAnchorTests(unittest.TestCase):
    def _completed_receipt(self, ids: dict, effect_id: str, *, request_id: str, tick: int):
        provider = open_provider(":memory:", ids)
        self.addCleanup(provider.close)
        return provider_outcome(
            provider,
            effect_id=effect_id,
            request_id=request_id,
            outcome="COMPLETED",
            begin_tick=tick,
            outcome_tick=tick + 1,
        )

    def test_completed_receipt_is_content_addressed_and_blocks_retry(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-anchor-") as td:
            with open_immutable_anchor(td, ids) as anchor:
                receipt = self._completed_receipt(
                    ids,
                    effect_id,
                    request_id="provider-request:v331:immutable:1",
                    tick=2,
                )
                stored = anchor.store_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
                object_receipt = verify_completion_immutable_object_receipt(
                    stored["signed_object_receipt"],
                    registry=ids["immutable_registry"],
                    expected_anchor_id=IMMUTABLE_ANCHOR_ID,
                    expected_authority_id=IMMUTABLE_AUTHORITY_ID,
                    expected_service_id=IMMUTABLE_SERVICE_ID,
                    expected_signer_id=IMMUTABLE_SIGNER_ID,
                    expected_trust_domain=IMMUTABLE_DOMAIN,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    signed_provider_receipt=receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                )
                object_path = Path(td) / object_receipt["object_receipt"]["object_key"]
                self.assertTrue(object_path.is_file())
                self.assertEqual(
                    hashlib.sha256(object_path.read_bytes()).hexdigest(),
                    object_receipt["object_receipt"]["content_sha256"],
                )
                session = VerifierFreshnessSession.create(
                    "verifier:v331:immutable:block", 0
                )
                with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                    challenge = challenges.issue(4, 100)
                    signed_status = anchor.issue_status(
                        effect_id=effect_id,
                        expected_payload_sha256=B,
                        challenge=challenge,
                        verifier_id=session.verifier_id,
                        verifier_epoch_sha256=session.epoch_sha256,
                        requested_at=4,
                        issued_at=4,
                        valid_until=50,
                    )
                    with self.assertRaises(CompletionImmutableAnchorError) as caught:
                        verify_completion_immutable_anchor_status(
                            signed_status,
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
                            expected_payload_sha256=B,
                            challenge_ledger=challenges,
                            expected_challenge=challenge,
                            evaluation_tick=4,
                        )
                self.assertEqual(
                    caught.exception.code, "immutable_anchor_state_blocks_retry"
                )

    def test_exact_replay_is_idempotent_without_overwrite(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-replay-") as td:
            with open_immutable_anchor(td, ids) as anchor:
                receipt = self._completed_receipt(
                    ids,
                    effect_id,
                    request_id="provider-request:v331:immutable:replay",
                    tick=2,
                )
                first = anchor.store_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
                second = anchor.store_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=4,
                    retention_until_tick=600,
                )
                self.assertFalse(first["idempotent_replay"])
                self.assertTrue(second["idempotent_replay"])
                self.assertEqual(anchor.event_count(), 1)
                self.assertEqual(anchor.effect_count(), 1)

    def test_unknown_reconciles_to_completed(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-reconcile-") as td:
            with open_immutable_anchor(td, ids) as anchor, open_provider(
                ":memory:", ids
            ) as provider:
                request_id = "provider-request:v331:immutable:unknown"
                provider.begin(
                    effect_id=effect_id,
                    payload_sha256=B,
                    provider_request_id=request_id,
                    now_tick=2,
                )
                provider.record_outcome(
                    effect_id=effect_id,
                    provider_request_id=request_id,
                    outcome="UNKNOWN",
                    provider_response_sha256=None,
                    evidence_sha256=F,
                    now_tick=3,
                )
                unknown_receipt = provider.issue_outcome_receipt(
                    effect_id=effect_id, issued_at=3, valid_until=100
                )
                anchor.store_provider_outcome(
                    unknown_receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
                provider.reconcile_unknown(
                    effect_id=effect_id,
                    provider_request_id=request_id,
                    outcome="COMPLETED",
                    provider_response_sha256=E,
                    evidence_sha256=canonical_sha256({"reconciled": True}),
                    now_tick=4,
                )
                completed = provider.issue_outcome_receipt(
                    effect_id=effect_id, issued_at=4, valid_until=100
                )
                anchor.store_provider_outcome(
                    completed,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=4,
                    retention_until_tick=500,
                )
                current = anchor.get(effect_id)
                self.assertEqual(current["state"], "COMPLETED")
                self.assertEqual(anchor.event_count(), 2)

    def test_no_effect_opens_next_generation(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-generation-") as td:
            with open_immutable_anchor(td, ids) as anchor, open_provider(
                ":memory:", ids
            ) as provider:
                request1 = "provider-request:v331:generation:1"
                provider.begin(
                    effect_id=effect_id,
                    payload_sha256=B,
                    provider_request_id=request1,
                    now_tick=2,
                )
                provider.record_outcome(
                    effect_id=effect_id,
                    provider_request_id=request1,
                    outcome="NO_EFFECT",
                    provider_response_sha256=None,
                    evidence_sha256=F,
                    now_tick=3,
                )
                receipt1 = provider.issue_outcome_receipt(
                    effect_id=effect_id, issued_at=3, valid_until=100
                )
                anchor.store_provider_outcome(
                    receipt1,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
                request2 = "provider-request:v331:generation:2"
                provider.begin(
                    effect_id=effect_id,
                    payload_sha256=B,
                    provider_request_id=request2,
                    now_tick=4,
                )
                provider.record_outcome(
                    effect_id=effect_id,
                    provider_request_id=request2,
                    outcome="COMPLETED",
                    provider_response_sha256=E,
                    evidence_sha256=canonical_sha256({"generation": 2}),
                    now_tick=5,
                )
                receipt2 = provider.issue_outcome_receipt(
                    effect_id=effect_id, issued_at=5, valid_until=100
                )
                anchor.store_provider_outcome(
                    receipt2,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=5,
                    retention_until_tick=600,
                )
                current = anchor.get(effect_id)
                self.assertEqual(current["generation"], 2)
                self.assertEqual(current["state"], "COMPLETED")

    def test_event_chain_and_head_verify(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-chain-") as td:
            with open_immutable_anchor(td, ids) as anchor:
                receipt = self._completed_receipt(
                    ids,
                    effect_id,
                    request_id="provider-request:v331:immutable:chain",
                    tick=2,
                )
                anchor.store_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
                chain = verify_completion_immutable_anchor_event_chain(
                    anchor.events_since(0),
                    registry=ids["immutable_registry"],
                    expected_anchor_id=IMMUTABLE_ANCHOR_ID,
                    expected_authority_id=IMMUTABLE_AUTHORITY_ID,
                    expected_service_id=IMMUTABLE_SERVICE_ID,
                    expected_signer_id=IMMUTABLE_SIGNER_ID,
                    expected_trust_domain=IMMUTABLE_DOMAIN,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    evaluation_tick=4,
                )
                head = verify_completion_immutable_anchor_head(
                    anchor.head(now_tick=4),
                    registry=ids["immutable_registry"],
                    expected_anchor_id=IMMUTABLE_ANCHOR_ID,
                    expected_authority_id=IMMUTABLE_AUTHORITY_ID,
                    expected_service_id=IMMUTABLE_SERVICE_ID,
                    expected_signer_id=IMMUTABLE_SIGNER_ID,
                    expected_trust_domain=IMMUTABLE_DOMAIN,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    expected_retention_policy_id=RETENTION_POLICY_ID,
                    evaluation_tick=4,
                )
                self.assertEqual(chain["head_sequence"], 1)
                self.assertEqual(
                    chain["head_event_sha256"], head["head"]["head_event_sha256"]
                )

    def test_checkpoint_detects_anchor_rollback(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-current-") as current_td, tempfile.TemporaryDirectory(
            prefix="triaxis-v331-rolled-back-"
        ) as old_td, tempfile.NamedTemporaryFile(prefix="triaxis-v331-checkpoint-", delete=False) as checkpoint_file:
            checkpoint_path = checkpoint_file.name
        try:
            with open_immutable_anchor(current_td, ids) as current, open_immutable_anchor(
                old_td, ids
            ) as rolled_back, SQLiteImmutableAnchorCheckpointLedger(
                checkpoint_path, anchor_id=IMMUTABLE_ANCHOR_ID
            ) as checkpoint:
                receipt = self._completed_receipt(
                    ids,
                    effect_id,
                    request_id="provider-request:v331:immutable:rollback",
                    tick=2,
                )
                current.store_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
                verify_completion_immutable_anchor_head(
                    current.head(now_tick=4),
                    registry=ids["immutable_registry"],
                    expected_anchor_id=IMMUTABLE_ANCHOR_ID,
                    expected_authority_id=IMMUTABLE_AUTHORITY_ID,
                    expected_service_id=IMMUTABLE_SERVICE_ID,
                    expected_signer_id=IMMUTABLE_SIGNER_ID,
                    expected_trust_domain=IMMUTABLE_DOMAIN,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    expected_retention_policy_id=RETENTION_POLICY_ID,
                    evaluation_tick=4,
                    checkpoint_ledger=checkpoint,
                )
                session = VerifierFreshnessSession.create(
                    "verifier:v331:immutable:rollback", 0
                )
                with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                    challenge = challenges.issue(5, 100)
                    old_status = rolled_back.issue_status(
                        effect_id=effect_id,
                        expected_payload_sha256=B,
                        challenge=challenge,
                        verifier_id=session.verifier_id,
                        verifier_epoch_sha256=session.epoch_sha256,
                        requested_at=5,
                        issued_at=5,
                        valid_until=50,
                    )
                    with self.assertRaises(CompletionImmutableAnchorError) as caught:
                        verify_completion_immutable_anchor_status(
                            old_status,
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
                            expected_payload_sha256=B,
                            challenge_ledger=challenges,
                            expected_challenge=challenge,
                            evaluation_tick=5,
                            checkpoint_ledger=checkpoint,
                        )
                self.assertEqual(
                    caught.exception.code, "immutable_anchor_checkpoint_rollback"
                )
        finally:
            Path(checkpoint_path).unlink(missing_ok=True)

    def test_checkpoint_detects_same_sequence_fork(self):
        ids = identities_v331()
        effect_a = make_intent("queue:v331:fork:a")["effect_id"]
        effect_b = make_intent("queue:v331:fork:b")["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-fork-a-") as a_td, tempfile.TemporaryDirectory(
            prefix="triaxis-v331-fork-b-"
        ) as b_td:
            with open_immutable_anchor(a_td, ids) as anchor_a, open_immutable_anchor(
                b_td, ids
            ) as anchor_b, SQLiteImmutableAnchorCheckpointLedger(
                ":memory:", anchor_id=IMMUTABLE_ANCHOR_ID
            ) as checkpoint:
                receipt_a = self._completed_receipt(
                    ids,
                    effect_a,
                    request_id="provider-request:v331:fork:a",
                    tick=2,
                )
                receipt_b = self._completed_receipt(
                    ids,
                    effect_b,
                    request_id="provider-request:v331:fork:b",
                    tick=2,
                )
                for anchor, receipt in ((anchor_a, receipt_a), (anchor_b, receipt_b)):
                    anchor.store_provider_outcome(
                        receipt,
                        provider_registry=ids["provider_registry"],
                        expected_provider_signer_id=PROVIDER_SIGNER_ID,
                        expected_provider_trust_domain=PROVIDER_DOMAIN,
                        evaluation_tick=3,
                        retention_until_tick=500,
                    )
                verify_completion_immutable_anchor_head(
                    anchor_a.head(now_tick=4),
                    registry=ids["immutable_registry"],
                    expected_anchor_id=IMMUTABLE_ANCHOR_ID,
                    expected_authority_id=IMMUTABLE_AUTHORITY_ID,
                    expected_service_id=IMMUTABLE_SERVICE_ID,
                    expected_signer_id=IMMUTABLE_SIGNER_ID,
                    expected_trust_domain=IMMUTABLE_DOMAIN,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    expected_retention_policy_id=RETENTION_POLICY_ID,
                    evaluation_tick=4,
                    checkpoint_ledger=checkpoint,
                )
                with self.assertRaises(CompletionImmutableAnchorError) as caught:
                    verify_completion_immutable_anchor_head(
                        anchor_b.head(now_tick=4),
                        registry=ids["immutable_registry"],
                        expected_anchor_id=IMMUTABLE_ANCHOR_ID,
                        expected_authority_id=IMMUTABLE_AUTHORITY_ID,
                        expected_service_id=IMMUTABLE_SERVICE_ID,
                        expected_signer_id=IMMUTABLE_SIGNER_ID,
                        expected_trust_domain=IMMUTABLE_DOMAIN,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        expected_retention_policy_id=RETENTION_POLICY_ID,
                        evaluation_tick=4,
                        checkpoint_ledger=checkpoint,
                    )
                self.assertEqual(
                    caught.exception.code, "immutable_anchor_checkpoint_fork"
                )

    def test_absent_status_is_fresh_single_use_and_checkpointed(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-absent-") as td:
            with open_immutable_anchor(td, ids) as anchor, SQLiteImmutableAnchorCheckpointLedger(
                ":memory:", anchor_id=IMMUTABLE_ANCHOR_ID
            ) as checkpoint:
                session = VerifierFreshnessSession.create(
                    "verifier:v331:immutable:absent", 0
                )
                with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                    challenge = challenges.issue(2, 100)
                    status = anchor.issue_status(
                        effect_id=effect_id,
                        expected_payload_sha256=B,
                        challenge=challenge,
                        verifier_id=session.verifier_id,
                        verifier_epoch_sha256=session.epoch_sha256,
                        requested_at=2,
                        issued_at=3,
                        valid_until=50,
                    )
                    result = verify_completion_immutable_anchor_status(
                        status,
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
                        expected_payload_sha256=B,
                        challenge_ledger=challenges,
                        expected_challenge=challenge,
                        evaluation_tick=3,
                        checkpoint_ledger=checkpoint,
                    )
                    self.assertTrue(result["external_effect_permitted"])
                    with self.assertRaises(Exception):
                        verify_completion_immutable_anchor_status(
                            status,
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
                            expected_payload_sha256=B,
                            challenge_ledger=challenges,
                            expected_challenge=challenge,
                            evaluation_tick=3,
                            checkpoint_ledger=checkpoint,
                        )

    def test_http_requires_auth_and_health_omits_secrets(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-http-") as td:
            with open_immutable_anchor(td, ids) as anchor:
                token = "v331-client-token"
                app = CompletionImmutableAnchorHTTPApplication(
                    anchor,
                    clock=lambda: 3,
                    client_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                )
                receipt = self._completed_receipt(
                    ids,
                    effect_id,
                    request_id="provider-request:v331:http",
                    tick=1,
                )
                denied, _ = app.handle(
                    "POST",
                    "/v1/outcomes/store",
                    {
                        "signed_provider_receipt": receipt,
                        "retention_until_tick": 500,
                        "legal_hold": True,
                    },
                )
                accepted, payload = app.handle(
                    "POST",
                    "/v1/outcomes/store",
                    {
                        "signed_provider_receipt": receipt,
                        "retention_until_tick": 500,
                        "legal_hold": True,
                    },
                    {"Authorization": f"Bearer {token}"},
                )
                code, health = app.handle("GET", "/healthz")
                serialized = repr(health)
                self.assertEqual(denied, 403)
                self.assertEqual(accepted, 200)
                self.assertEqual(payload["effect"]["state"], "COMPLETED")
                self.assertEqual(code, 200)
                self.assertNotIn("private_key", serialized)
                self.assertNotIn(token, serialized)
                self.assertFalse(health["anchor"]["physical_worm_established"])


    def test_restart_rebuilds_signed_state_and_materialized_objects(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-restart-") as td:
            receipt = self._completed_receipt(
                ids,
                effect_id,
                request_id="provider-request:v331:immutable:restart",
                tick=2,
            )
            with open_immutable_anchor(td, ids) as anchor:
                anchor.store_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
            with open_immutable_anchor(td, ids) as reopened:
                self.assertEqual(reopened.event_count(), 1)
                self.assertEqual(reopened.effect_count(), 1)
                self.assertEqual(reopened.get(effect_id)["state"], "COMPLETED")

    def test_materialized_provider_object_corruption_is_detected_on_reopen(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-corrupt-object-") as td:
            receipt = self._completed_receipt(
                ids,
                effect_id,
                request_id="provider-request:v331:immutable:corrupt-object",
                tick=2,
            )
            with open_immutable_anchor(td, ids) as anchor:
                stored = anchor.store_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
            object_path = Path(td) / stored["signed_object_receipt"][
                "inner_contract"
            ]["object_key"]
            object_path.chmod(0o640)
            object_path.write_bytes(b"{}\n")
            with self.assertRaises(CompletionImmutableAnchorError) as caught:
                open_immutable_anchor(td, ids)
            self.assertEqual(
                caught.exception.code, "immutable_anchor_object_content_mismatch"
            )

    def test_signed_object_receipt_corruption_is_detected_on_reopen(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        with tempfile.TemporaryDirectory(prefix="triaxis-v331-corrupt-receipt-") as td:
            receipt = self._completed_receipt(
                ids,
                effect_id,
                request_id="provider-request:v331:immutable:corrupt-receipt",
                tick=2,
            )
            with open_immutable_anchor(td, ids) as anchor:
                stored = anchor.store_provider_outcome(
                    receipt,
                    provider_registry=ids["provider_registry"],
                    expected_provider_signer_id=PROVIDER_SIGNER_ID,
                    expected_provider_trust_domain=PROVIDER_DOMAIN,
                    evaluation_tick=3,
                    retention_until_tick=500,
                )
            digest = stored["signed_object_receipt"]["inner_contract"][
                "content_sha256"
            ]
            receipt_path = Path(td, "receipts", f"{digest}.json")
            receipt_path.chmod(0o640)
            receipt_path.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(CompletionImmutableAnchorError) as caught:
                open_immutable_anchor(td, ids)
            self.assertEqual(
                caught.exception.code, "invalid_immutable_object_receipt_envelope"
            )


class V331ComposedGuardTests(unittest.TestCase):
    def _run_guard(
        self,
        *,
        completion_member_count: int = 3,
        immutable_completed: bool = False,
        rolled_back_immutable_status: bool = False,
    ) -> dict:
        ids = identities_v331()
        intent = make_intent()
        with ExitStack() as stack, tempfile.TemporaryDirectory(
            prefix="triaxis-v331-guard-anchor-"
        ) as anchor_root, tempfile.TemporaryDirectory(
            prefix="triaxis-v331-guard-rollback-"
        ) as rollback_root:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [
                stack.enter_context(open_head(":memory:", ids, index))
                for index in range(3)
            ]
            provider = stack.enter_context(open_provider(":memory:", ids))
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            worm = stack.enter_context(open_worm(":memory:", ids))
            immutable = stack.enter_context(open_immutable_anchor(anchor_root, ids))

            anchor(heads, ledger, 1)
            dispatch = canonical_sha256({"dispatch": "v331:guard"})
            ledger.reserve(
                intent,
                attempt_id="attempt:v331:guard",
                dispatch_id=dispatch,
                now_tick=2,
            )
            started = ledger.start(
                intent["effect_id"],
                attempt_id="attempt:v331:guard",
                dispatch_id=dispatch,
                now_tick=3,
            )
            anchor(heads, ledger, 3)

            if immutable_completed:
                with open_provider(":memory:", ids) as completed_provider:
                    receipt = provider_outcome(
                        completed_provider,
                        effect_id=intent["effect_id"],
                        request_id="provider-request:v331:guard:immutable-completed",
                        outcome="COMPLETED",
                        begin_tick=1,
                        outcome_tick=2,
                    )
                    immutable.store_provider_outcome(
                        receipt,
                        provider_registry=ids["provider_registry"],
                        expected_provider_signer_id=PROVIDER_SIGNER_ID,
                        expected_provider_trust_domain=PROVIDER_DOMAIN,
                        evaluation_tick=2,
                        retention_until_tick=1_000,
                    )

            head_session = VerifierFreshnessSession.create(
                "verifier:v331:guard:head", 0
            )
            head_challenges = stack.enter_context(
                SQLiteEpochChallengeLedger(":memory:", head_session)
            )
            head_challenge = head_challenges.issue(4, 20)
            head_statuses = issue_head_responses(
                heads[:2],
                session=head_session,
                challenge=head_challenge,
                requested_at=4,
                issued_at=4,
            )

            provider_session = VerifierFreshnessSession.create(
                "verifier:v331:guard:provider", 0
            )
            provider_challenges = stack.enter_context(
                SQLiteEpochChallengeLedger(":memory:", provider_session)
            )
            provider_challenge = provider_challenges.issue(4, 20)
            provider_status = provider.issue_status(
                effect_id=intent["effect_id"],
                expected_payload_sha256=B,
                challenge=provider_challenge,
                verifier_id=provider_session.verifier_id,
                verifier_epoch_sha256=provider_session.epoch_sha256,
                requested_at=4,
                issued_at=4,
            )

            completion_session = VerifierFreshnessSession.create(
                "verifier:v331:guard:completion", 0
            )
            completion_challenges = stack.enter_context(
                SQLiteEpochChallengeLedger(":memory:", completion_session)
            )
            completion_challenge = completion_challenges.issue(4, 20)
            completion_statuses = issue_completion_statuses(
                witnesses[:completion_member_count],
                session=completion_session,
                challenge=completion_challenge,
                effect_id=intent["effect_id"],
                requested_at=4,
                issued_at=4,
            )

            worm_session = VerifierFreshnessSession.create(
                "verifier:v331:guard:worm", 0
            )
            worm_challenges = stack.enter_context(
                SQLiteEpochChallengeLedger(":memory:", worm_session)
            )
            worm_challenge = worm_challenges.issue(4, 20)
            worm_status = worm.issue_status(
                effect_id=intent["effect_id"],
                expected_payload_sha256=B,
                challenge=worm_challenge,
                verifier_id=worm_session.verifier_id,
                verifier_epoch_sha256=worm_session.epoch_sha256,
                requested_at=4,
                issued_at=4,
            )

            immutable_session = VerifierFreshnessSession.create(
                "verifier:v331:guard:immutable", 0
            )
            immutable_challenges = stack.enter_context(
                SQLiteEpochChallengeLedger(":memory:", immutable_session)
            )
            immutable_challenge = immutable_challenges.issue(4, 20)
            immutable_source = immutable
            if rolled_back_immutable_status:
                immutable_source = stack.enter_context(
                    open_immutable_anchor(rollback_root, ids)
                )
            immutable_status = immutable_source.issue_status(
                effect_id=intent["effect_id"],
                expected_payload_sha256=B,
                challenge=immutable_challenge,
                verifier_id=immutable_session.verifier_id,
                verifier_epoch_sha256=immutable_session.epoch_sha256,
                requested_at=4,
                issued_at=4,
                valid_until=20,
            )

            checkpoint = stack.enter_context(
                SQLiteImmutableAnchorCheckpointLedger(
                    ":memory:", anchor_id=IMMUTABLE_ANCHOR_ID
                )
            )
            if rolled_back_immutable_status:
                checkpoint.observe_head(
                    immutable.head(now_tick=3)["inner_contract"],
                    observed_at_tick=3,
                )

            head_config = quorum_config(ids)
            completion_config = completion_quorum_config(ids)
            policy = availability_policy(ids)
            return verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor(
                intent,
                started["signed_receipt"],
                expected_attempt_id="attempt:v331:guard",
                expected_dispatch_id=dispatch,
                evaluation_tick=4,
                signed_local_head=ledger.head(now_tick=4),
                signed_head_responses=head_statuses,
                ledger_registry=ids["ledger_registry"],
                head_authority_registry=ids["head_registry"],
                expected_ledger_id=LEDGER_ID,
                expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID,
                expected_ledger_trust_domain=LEDGER_DOMAIN,
                head_quorum_config=head_config,
                expected_head_quorum_config_sha256=head_config["config_sha256"],
                head_challenge_ledger=head_challenges,
                expected_head_challenge=head_challenge,
                signed_provider_status=provider_status,
                provider_registry=ids["provider_registry"],
                expected_provider_id=PROVIDER_ID,
                expected_provider_service_id=PROVIDER_SERVICE_ID,
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                expected_provider_payload_sha256=B,
                provider_challenge_ledger=provider_challenges,
                expected_provider_challenge=provider_challenge,
                signed_completion_witness_statuses=completion_statuses,
                completion_witness_registry=ids["completion_witness_registry"],
                completion_quorum_config=completion_config,
                expected_completion_quorum_config_sha256=completion_config[
                    "config_sha256"
                ],
                availability_policy=policy,
                expected_availability_policy_sha256=policy["policy_sha256"],
                completion_challenge_ledger=completion_challenges,
                expected_completion_challenge=completion_challenge,
                signed_worm_anchor_status=worm_status,
                worm_anchor_registry=ids["worm_registry"],
                expected_worm_anchor_id=ANCHOR_ID,
                expected_worm_anchor_authority_id=ANCHOR_AUTHORITY_ID,
                expected_worm_anchor_service_id=ANCHOR_SERVICE_ID,
                expected_worm_anchor_signer_id=ANCHOR_SIGNER_ID,
                expected_worm_anchor_trust_domain=ANCHOR_DOMAIN,
                worm_anchor_challenge_ledger=worm_challenges,
                expected_worm_anchor_challenge=worm_challenge,
                signed_immutable_anchor_status=immutable_status,
                immutable_anchor_registry=ids["immutable_registry"],
                expected_immutable_anchor_id=IMMUTABLE_ANCHOR_ID,
                expected_immutable_anchor_authority_id=IMMUTABLE_AUTHORITY_ID,
                expected_immutable_anchor_service_id=IMMUTABLE_SERVICE_ID,
                expected_immutable_anchor_signer_id=IMMUTABLE_SIGNER_ID,
                expected_immutable_anchor_trust_domain=IMMUTABLE_DOMAIN,
                expected_immutable_anchor_retention_policy_id=RETENTION_POLICY_ID,
                immutable_anchor_challenge_ledger=immutable_challenges,
                expected_immutable_anchor_challenge=immutable_challenge,
                immutable_anchor_checkpoint_ledger=checkpoint,
            )

    def test_cumulative_v331_preflight_passes_only_with_closed_availability(self):
        result = self._run_guard()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["completion_availability_guard"]["responding_witness_count"], 3
        )
        self.assertFalse(result["authority_granted"])

    def test_missing_completion_witness_blocks_cumulative_preflight(self):
        result = self._run_guard(completion_member_count=2)
        self.assertEqual(result["status"], "BLOCK")
        self.assertEqual(
            result["errors"][0]["code"],
            "completion_availability_witness_set_incomplete",
        )

    def test_current_immutable_anchor_blocks_rolled_back_permissive_layers(self):
        result = self._run_guard(immutable_completed=True)
        self.assertEqual(result["status"], "BLOCK")
        self.assertEqual(
            result["errors"][0]["code"], "immutable_anchor_state_blocks_retry"
        )

    def test_checkpoint_blocks_rolled_back_immutable_anchor(self):
        # First create one current immutable event, pin its head, then ask the
        # cumulative guard to trust a clean sequence-zero snapshot.
        result = self._run_guard(
            immutable_completed=True, rolled_back_immutable_status=True
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertEqual(
            result["errors"][0]["code"], "immutable_anchor_checkpoint_rollback"
        )


if __name__ == "__main__":
    unittest.main()
