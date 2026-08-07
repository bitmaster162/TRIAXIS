from __future__ import annotations

from contextlib import ExitStack
import tempfile
import unittest

from tests.test_v3_29_execution_head_quorum_and_completion_witness import B, make_intent, PROVIDER_ID, PROVIDER_SERVICE_ID
from tests.test_v3_31_availability_closed_and_immutable_anchor import (
    identities_v331,
    open_immutable_anchor,
    IMMUTABLE_ANCHOR_ID,
    IMMUTABLE_AUTHORITY_ID,
    IMMUTABLE_SERVICE_ID,
    IMMUTABLE_SIGNER_ID,
    IMMUTABLE_DOMAIN,
    RETENTION_POLICY_ID,
)
from triaxis.completion_transparency_quorum import (
    CompletionTransparencyError,
    SQLiteCompletionTransparencyAuthority,
    make_completion_transparency_config,
    validate_completion_transparency_config,
    verify_completion_transparency_quorum,
)
from triaxis.crypto_trust import (
    PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY,
    PURPOSE_COMPLETION_TRANSPARENCY,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.integrity import seal_mapping
from triaxis.provider_native_idempotency import (
    PROVIDER_NATIVE_STATUS_CONTRACT_ID,
    FilesystemProviderNativeIdempotencyReference,
    ProviderNativeIdempotencyError,
    make_provider_native_policy,
    validate_provider_native_policy,
    verify_provider_native_status,
)
from triaxis.provider_transparency_guard import (
    ProviderTransparencyGuardError,
    verify_terminal_external_effect_guard,
)
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

NAMESPACE_ID = "provider-native-namespace:v332"
PN_SIGNER_ID = "signer:provider-native:v332"
PN_DOMAIN = "domain:provider-native:v332"


def provider_native_fixture(root: str):
    pair = generate_ed25519_keypair()
    key_id = "key:provider-native:v332"
    registry = TrustKeyRegistry([make_trust_key_record(
        key_id=key_id,
        signer_id=PN_SIGNER_ID,
        trust_domain=PN_DOMAIN,
        public_key_b64=pair["public_key_b64"],
        purposes=[PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY],
        valid_from=0,
        valid_until=100_000,
    )])
    provider = FilesystemProviderNativeIdempotencyReference(
        root,
        provider_id=PROVIDER_ID,
        service_id=PROVIDER_SERVICE_ID,
        namespace_id=NAMESPACE_ID,
        key_id=key_id,
        signer_id=PN_SIGNER_ID,
        trust_domain=PN_DOMAIN,
        private_key_b64=pair["private_key_b64"],
        response_ttl=100,
    )
    policy = make_provider_native_policy(
        policy_id="provider-native-policy:v332",
        provider_id=PROVIDER_ID,
        service_id=PROVIDER_SERVICE_ID,
        namespace_id=NAMESPACE_ID,
        valid_from=0,
        valid_until=10_000,
    )
    return pair, registry, provider, policy


def transparency_fixture(ids: dict, root: str):
    rows = []
    registry_records = []
    authorities = []
    for suffix in ("a", "b", "c"):
        pair = generate_ed25519_keypair()
        row = {
            "authority_id": f"authority:completion-transparency:v332:{suffix}",
            "service_id": f"service:completion-transparency:v332:{suffix}",
            "signer_id": f"signer:completion-transparency:v332:{suffix}",
            "key_id": f"key:completion-transparency:v332:{suffix}",
            "trust_domain": f"domain:completion-transparency:v332:{suffix}",
        }
        rows.append(row)
        registry_records.append(make_trust_key_record(
            key_id=row["key_id"], signer_id=row["signer_id"], trust_domain=row["trust_domain"],
            public_key_b64=pair["public_key_b64"], purposes=[PURPOSE_COMPLETION_TRANSPARENCY],
            valid_from=0, valid_until=100_000,
        ))
        authorities.append(SQLiteCompletionTransparencyAuthority(
            f"{root}/transparency-{suffix}.sqlite",
            authority_id=row["authority_id"], service_id=row["service_id"], anchor_id=IMMUTABLE_ANCHOR_ID,
            key_id=row["key_id"], signer_id=row["signer_id"], trust_domain=row["trust_domain"],
            private_key_b64=pair["private_key_b64"], response_ttl=100,
        ))
    config = make_completion_transparency_config(
        config_id="completion-transparency:v332:primary",
        authority_set_id="completion-transparency-set:v332:primary",
        anchor_id=IMMUTABLE_ANCHOR_ID,
        threshold=2,
        authorities=rows,
        valid_from=0,
        valid_until=10_000,
    )
    return rows, TrustKeyRegistry(registry_records), authorities, config


class V332ProviderNativeTests(unittest.TestCase):
    def test_policy_is_current_and_fail_closed_when_stale(self):
        policy = make_provider_native_policy(policy_id="p", provider_id=PROVIDER_ID, service_id=PROVIDER_SERVICE_ID, namespace_id=NAMESPACE_ID, valid_from=1, valid_until=10)
        self.assertEqual(validate_provider_native_policy(policy, 5)["status"], "PASS")
        self.assertEqual(validate_provider_native_policy(policy, 10)["status"], "BLOCK")

    def test_begin_replay_and_payload_conflict(self):
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            _, _, provider, _ = provider_native_fixture(td)
            first = provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id="req:1", now_tick=1)
            replay = provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id="req:2", now_tick=2)
            self.assertTrue(first["external_effect_permitted"])
            self.assertFalse(replay["external_effect_permitted"])
            with self.assertRaises(ProviderNativeIdempotencyError) as caught:
                provider.begin(effect_id=intent["effect_id"], payload_sha256="f"*64, provider_request_id="req:3", now_tick=3)
            self.assertEqual(caught.exception.code, "provider_native_payload_conflict")

    def test_reopen_replays_write_once_chain(self):
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            pair, _, provider, _ = provider_native_fixture(td)
            provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id="req:reopen", now_tick=1)
            provider.record_outcome(effect_id=intent["effect_id"], state="COMPLETED", provider_response_sha256="a"*64, evidence_sha256="b"*64, now_tick=2)
            reopened = FilesystemProviderNativeIdempotencyReference(td, provider_id=PROVIDER_ID, service_id=PROVIDER_SERVICE_ID, namespace_id=NAMESPACE_ID, key_id="key:provider-native:v332", signer_id=PN_SIGNER_ID, trust_domain=PN_DOMAIN, private_key_b64=pair["private_key_b64"], response_ttl=100)
            replay = reopened.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id="req:new", now_tick=3)
            self.assertFalse(replay["external_effect_permitted"])
            self.assertEqual(replay["effect"]["state"], "COMPLETED")

    def test_no_effect_opens_only_next_generation(self):
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            _, _, provider, _ = provider_native_fixture(td)
            provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id="req:1", now_tick=1)
            provider.record_outcome(effect_id=intent["effect_id"], state="NO_EFFECT", provider_response_sha256="a"*64, evidence_sha256="b"*64, now_tick=2)
            second = provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id="req:2", now_tick=3)
            self.assertTrue(second["external_effect_permitted"])
            self.assertEqual(second["effect"]["generation"], 2)

    def test_completed_status_blocks_retry(self):
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            _, registry, provider, policy = provider_native_fixture(td)
            provider.begin(effect_id=intent["effect_id"], payload_sha256=B, provider_request_id="req:1", now_tick=1)
            provider.record_outcome(effect_id=intent["effect_id"], state="COMPLETED", provider_response_sha256="a"*64, evidence_sha256="b"*64, now_tick=2)
            session = VerifierFreshnessSession.create("verifier:v332:pn:completed", 0)
            challenge = "challenge-provider-native-completed"
            status = provider.signed_status(effect_id=intent["effect_id"], payload_sha256=B, challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, policy=policy, now_tick=3)
            with self.assertRaises(ProviderNativeIdempotencyError) as caught:
                verify_provider_native_status(status, registry=registry, current_policy=policy, expected_policy_sha256=policy["policy_sha256"], expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID, expected_namespace_id=NAMESPACE_ID, expected_signer_id=PN_SIGNER_ID, expected_trust_domain=PN_DOMAIN, expected_effect_id=intent["effect_id"], expected_payload_sha256=B, expected_verifier_id=session.verifier_id, expected_verifier_epoch_sha256=session.epoch_sha256, expected_challenge=challenge, evaluation_tick=3)
            self.assertEqual(caught.exception.code, "provider_native_state_blocks_retry")

    def test_absent_status_passes_only_with_current_pinned_policy(self):
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            _, registry, provider, policy = provider_native_fixture(td)
            session = VerifierFreshnessSession.create("verifier:v332:pn:absent", 0)
            challenge = "challenge-provider-native-absent"
            status = provider.signed_status(effect_id=intent["effect_id"], payload_sha256=B, challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, policy=policy, now_tick=3)
            result = verify_provider_native_status(status, registry=registry, current_policy=policy, expected_policy_sha256=policy["policy_sha256"], expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID, expected_namespace_id=NAMESPACE_ID, expected_signer_id=PN_SIGNER_ID, expected_trust_domain=PN_DOMAIN, expected_effect_id=intent["effect_id"], expected_payload_sha256=B, expected_verifier_id=session.verifier_id, expected_verifier_epoch_sha256=session.epoch_sha256, expected_challenge=challenge, evaluation_tick=3)
            self.assertEqual(result["status"], "PASS")

    def test_expired_policy_cannot_validate_old_matching_digest(self):
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            _, registry, provider, _ = provider_native_fixture(td)
            stale = make_provider_native_policy(policy_id="provider-native-policy:expired", provider_id=PROVIDER_ID, service_id=PROVIDER_SERVICE_ID, namespace_id=NAMESPACE_ID, valid_from=0, valid_until=4)
            session = VerifierFreshnessSession.create("verifier:v332:pn:stale-policy", 0)
            challenge = "challenge-provider-native-stale-policy"
            status = provider.signed_status(effect_id=intent["effect_id"], payload_sha256=B, challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, policy=stale, now_tick=3)
            with self.assertRaises(ProviderNativeIdempotencyError) as caught:
                verify_provider_native_status(status, registry=registry, current_policy=stale, expected_policy_sha256=stale["policy_sha256"], expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID, expected_namespace_id=NAMESPACE_ID, expected_signer_id=PN_SIGNER_ID, expected_trust_domain=PN_DOMAIN, expected_effect_id=intent["effect_id"], expected_payload_sha256=B, expected_verifier_id=session.verifier_id, expected_verifier_epoch_sha256=session.epoch_sha256, expected_challenge=challenge, evaluation_tick=5)
            self.assertEqual(caught.exception.code, "provider_native_policy_not_current")

    def test_inner_and_envelope_freshness_windows_must_match(self):
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            pair, registry, provider, policy = provider_native_fixture(td)
            session = VerifierFreshnessSession.create("verifier:v332:pn:window", 0)
            challenge = "challenge-provider-native-window"
            good = provider.signed_status(effect_id=intent["effect_id"], payload_sha256=B, challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, policy=policy, now_tick=3)
            inner = dict(good["inner_contract"])
            inner["issued_at"] = 2
            inner["status_sha256"] = ""
            inner = seal_mapping(inner, "status_sha256")
            bad = sign_contract_envelope(inner, digest_field="status_sha256", purpose=PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY, key_id="key:provider-native:v332", signer_id=PN_SIGNER_ID, trust_domain=PN_DOMAIN, private_key_b64=pair["private_key_b64"], issued_at=3, valid_until=103)
            with self.assertRaises(ProviderNativeIdempotencyError) as caught:
                verify_provider_native_status(bad, registry=registry, current_policy=policy, expected_policy_sha256=policy["policy_sha256"], expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID, expected_namespace_id=NAMESPACE_ID, expected_signer_id=PN_SIGNER_ID, expected_trust_domain=PN_DOMAIN, expected_effect_id=intent["effect_id"], expected_payload_sha256=B, expected_verifier_id=session.verifier_id, expected_verifier_epoch_sha256=session.epoch_sha256, expected_challenge=challenge, evaluation_tick=3)
            self.assertEqual(caught.exception.code, "provider_native_status_envelope_window_mismatch")

    def test_caller_cannot_expand_permissive_states(self):
        intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            _, registry, provider, policy = provider_native_fixture(td)
            session = VerifierFreshnessSession.create("verifier:v332:pn:states", 0)
            challenge = "challenge-provider-native-states"
            status = provider.signed_status(effect_id=intent["effect_id"], payload_sha256=B, challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, policy=policy, now_tick=3)
            with self.assertRaises(ProviderNativeIdempotencyError) as caught:
                verify_provider_native_status(status, registry=registry, current_policy=policy, expected_policy_sha256=policy["policy_sha256"], expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID, expected_namespace_id=NAMESPACE_ID, expected_signer_id=PN_SIGNER_ID, expected_trust_domain=PN_DOMAIN, expected_effect_id=intent["effect_id"], expected_payload_sha256=B, expected_verifier_id=session.verifier_id, expected_verifier_epoch_sha256=session.epoch_sha256, expected_challenge=challenge, evaluation_tick=3, allowed_states=("ABSENT", "NO_EFFECT", "COMPLETED"))
            self.assertEqual(caught.exception.code, "invalid_allowed_provider_native_states")


class V332CompletionTransparencyTests(unittest.TestCase):
    def _setup(self):
        ids = identities_v331()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        anchor = open_immutable_anchor(f"{td.name}/anchor", ids)
        self.addCleanup(anchor.close)
        signed_head = anchor.head(now_tick=10)
        rows, registry, authorities, config = transparency_fixture(ids, td.name)
        for authority in authorities:
            self.addCleanup(authority.close)
            authority.observe_verified_head(signed_head["inner_contract"], observed_at=10)
        return ids, signed_head, rows, registry, authorities, config

    def _quorum(self, ids, signed_head, registry, authorities, config, *, response_count=2, now=10):
        session = VerifierFreshnessSession.create(f"verifier:v332:transparency:{now}:{response_count}", 0)
        ledger = SQLiteEpochChallengeLedger(":memory:", session)
        self.addCleanup(ledger.close)
        challenge = ledger.issue(1, 100)
        responses = [a.signed_response(challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, requested_at=1, now_tick=now) for a in authorities[:response_count]]
        kwargs = dict(anchor_registry=ids["immutable_registry"], transparency_registry=registry, expected_anchor_id=IMMUTABLE_ANCHOR_ID, expected_anchor_authority_id=IMMUTABLE_AUTHORITY_ID, expected_anchor_service_id=IMMUTABLE_SERVICE_ID, expected_anchor_signer_id=IMMUTABLE_SIGNER_ID, expected_anchor_trust_domain=IMMUTABLE_DOMAIN, expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID, expected_retention_policy_id=RETENTION_POLICY_ID, config=config, expected_config_sha256=config["config_sha256"], challenge_ledger=ledger, expected_challenge=challenge, evaluation_tick=now, max_response_age=5)
        return session, ledger, challenge, responses, kwargs

    def test_config_current_and_threshold(self):
        _, _, _, _, _, config = self._setup()
        self.assertEqual(validate_completion_transparency_config(config, 10)["status"], "PASS")
        self.assertEqual(validate_completion_transparency_config(config, 10_000)["status"], "BLOCK")

    def test_two_of_three_exact_head_passes(self):
        ids, signed_head, _, registry, authorities, config = self._setup()
        _, _, _, responses, kwargs = self._quorum(ids, signed_head, registry, authorities, config)
        result = verify_completion_transparency_quorum(signed_head, responses, **kwargs)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["quorum_witness"]["matching_authority_ids"]), 2)

    def test_threshold_not_reached_blocks(self):
        ids, signed_head, _, registry, authorities, config = self._setup()
        _, _, _, responses, kwargs = self._quorum(ids, signed_head, registry, authorities, config, response_count=1)
        with self.assertRaises(CompletionTransparencyError) as caught:
            verify_completion_transparency_quorum(signed_head, responses, **kwargs)
        self.assertEqual(caught.exception.code, "completion_transparency_threshold_not_reached")

    def test_authority_refuses_rollback_and_same_sequence_fork(self):
        ids, signed_head, _, _, authorities, _ = self._setup()
        authority = authorities[0]
        newer = dict(signed_head["inner_contract"])
        newer["sequence"] = 2
        newer["head_event_sha256"] = "a"*64
        newer["state_root_sha256"] = "b"*64
        newer["head_sha256"] = "c"*64
        authority.observe_verified_head(newer, observed_at=11)
        with self.assertRaises(CompletionTransparencyError) as rollback:
            authority.observe_verified_head(signed_head["inner_contract"], observed_at=12)
        self.assertEqual(rollback.exception.code, "transparency_checkpoint_rollback")
        fork = dict(newer)
        fork["head_sha256"] = "d"*64
        with self.assertRaises(CompletionTransparencyError) as caught:
            authority.observe_verified_head(fork, observed_at=13)
        self.assertEqual(caught.exception.code, "transparency_checkpoint_fork")

    def test_newer_valid_minority_vetoes_old_threshold(self):
        ids, signed_head, _, registry, authorities, config = self._setup()
        # Advance the third authority only; old local head remains sequence 0.
        newer = dict(signed_head["inner_contract"])
        newer["sequence"] = 1
        newer["head_event_sha256"] = "a"*64
        newer["state_root_sha256"] = "b"*64
        newer["head_sha256"] = "c"*64
        authorities[2].observe_verified_head(newer, observed_at=11)
        session, ledger, challenge, responses, kwargs = self._quorum(ids, signed_head, registry, authorities, config, response_count=2, now=12)
        responses.append(authorities[2].signed_response(challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, requested_at=1, now_tick=12))
        with self.assertRaises(CompletionTransparencyError) as caught:
            verify_completion_transparency_quorum(signed_head, responses, **kwargs)
        self.assertEqual(caught.exception.code, "completion_transparency_newer_minority_veto")

    def test_same_sequence_fork_minority_vetoes(self):
        ids, signed_head, rows, registry, authorities, config = self._setup()
        fork = dict(signed_head["inner_contract"])
        fork["head_event_sha256"] = "a"*64
        fork["state_root_sha256"] = "b"*64
        fork["head_sha256"] = "c"*64
        # Fresh authority built directly with fork before seeing canonical head.
        row = rows[2]
        session, ledger, challenge, responses, kwargs = self._quorum(ids, signed_head, registry, authorities[:2], config, response_count=2, now=12)
        # Re-sign third response's inner contract using its own original key is intentionally tested in the envelope-window test instead.
        # Here force the checkpoint through the authority API after clearing its local DB row.
        authorities[2]._conn.execute("DELETE FROM transparency_checkpoint WHERE anchor_id=?", (IMMUTABLE_ANCHOR_ID,))
        authorities[2].observe_verified_head(fork, observed_at=12)
        responses.append(authorities[2].signed_response(challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, requested_at=1, now_tick=12))
        with self.assertRaises(CompletionTransparencyError) as caught:
            verify_completion_transparency_quorum(signed_head, responses, **kwargs)
        self.assertEqual(caught.exception.code, "completion_transparency_fork_veto")

    def test_response_inner_and_envelope_window_must_match(self):
        ids, signed_head, rows, registry, authorities, config = self._setup()
        session, ledger, challenge, responses, kwargs = self._quorum(ids, signed_head, registry, authorities, config, response_count=2, now=10)
        # Reconstruct a validly signed but semantically split freshness window using authority A's private key is not exposed;
        # create a standalone authority with a known pair and one-member replacement config.
        pair = generate_ed25519_keypair()
        row = {"authority_id":"authority:split","service_id":"service:split","signer_id":"signer:split","key_id":"key:split","trust_domain":"domain:split"}
        with SQLiteCompletionTransparencyAuthority(":memory:", authority_id=row["authority_id"], service_id=row["service_id"], anchor_id=IMMUTABLE_ANCHOR_ID, key_id=row["key_id"], signer_id=row["signer_id"], trust_domain=row["trust_domain"], private_key_b64=pair["private_key_b64"], response_ttl=100) as authority:
            authority.observe_verified_head(signed_head["inner_contract"], observed_at=10)
            good = authority.signed_response(challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, requested_at=1, now_tick=10)
            inner = dict(good["inner_contract"]); inner["issued_at"] = 9; inner["response_sha256"] = ""; inner = seal_mapping(inner, "response_sha256")
            bad = sign_contract_envelope(inner, digest_field="response_sha256", purpose=PURPOSE_COMPLETION_TRANSPARENCY, key_id=row["key_id"], signer_id=row["signer_id"], trust_domain=row["trust_domain"], private_key_b64=pair["private_key_b64"], issued_at=10, valid_until=110)
            split_registry = TrustKeyRegistry([make_trust_key_record(key_id=row["key_id"], signer_id=row["signer_id"], trust_domain=row["trust_domain"], public_key_b64=pair["public_key_b64"], purposes=[PURPOSE_COMPLETION_TRANSPARENCY], valid_from=0, valid_until=100_000)])
            split_config = make_completion_transparency_config(config_id="split", authority_set_id="split", anchor_id=IMMUTABLE_ANCHOR_ID, threshold=2, authorities=[row, rows[1]], valid_from=0, valid_until=1000)
            kwargs2 = dict(kwargs); kwargs2["transparency_registry"] = TrustKeyRegistry(split_registry.as_records() + [registry.get(rows[1]["key_id"])]) ; kwargs2["config"] = split_config; kwargs2["expected_config_sha256"] = split_config["config_sha256"]
            with self.assertRaises(CompletionTransparencyError) as caught:
                verify_completion_transparency_quorum(signed_head, [bad, responses[1]], **kwargs2)
            self.assertEqual(caught.exception.code, "completion_transparency_envelope_window_mismatch")

    def test_challenge_is_single_use(self):
        ids, signed_head, _, registry, authorities, config = self._setup()
        _, _, _, responses, kwargs = self._quorum(ids, signed_head, registry, authorities, config)
        verify_completion_transparency_quorum(signed_head, responses, **kwargs)
        with self.assertRaises(Exception):
            verify_completion_transparency_quorum(signed_head, responses, **kwargs)

    def test_config_digest_is_pinned(self):
        ids, signed_head, _, registry, authorities, config = self._setup()
        _, _, _, responses, kwargs = self._quorum(ids, signed_head, registry, authorities, config)
        kwargs["expected_config_sha256"] = "f"*64
        with self.assertRaises(CompletionTransparencyError) as caught:
            verify_completion_transparency_quorum(signed_head, responses, **kwargs)
        self.assertEqual(caught.exception.code, "completion_transparency_config_substitution")


class V332TerminalGuardTests(unittest.TestCase):
    def test_guard_requires_prior_guard_and_separate_authorization(self):
        with self.assertRaises(ProviderTransparencyGuardError) as caught:
            verify_terminal_external_effect_guard(v331_guard_result={"status":"BLOCK"}, separate_authorization_valid=True, signed_provider_status={}, provider_status_kwargs={}, signed_local_anchor_head={}, signed_transparency_responses=[], transparency_kwargs={})
        self.assertEqual(caught.exception.code, "v331_guard_not_pass")

    def test_guard_rejects_missing_separate_authorization_after_evidence_pass(self):
        ids = identities_v331(); intent = make_intent()
        with tempfile.TemporaryDirectory() as td:
            _, pn_registry, provider, policy = provider_native_fixture(f"{td}/provider")
            session_pn = VerifierFreshnessSession.create("verifier:v332:guard:provider", 0)
            challenge_pn = "challenge-terminal-provider-guard"
            pn_status = provider.signed_status(effect_id=intent["effect_id"], payload_sha256=B, challenge=challenge_pn, verifier_id=session_pn.verifier_id, verifier_epoch_sha256=session_pn.epoch_sha256, policy=policy, now_tick=10)
            with open_immutable_anchor(f"{td}/anchor", ids) as anchor:
                signed_head = anchor.head(now_tick=10)
                rows, tr_registry, authorities, config = transparency_fixture(ids, td)
                with ExitStack() as stack:
                    for a in authorities: stack.callback(a.close); a.observe_verified_head(signed_head["inner_contract"], observed_at=10)
                    session = VerifierFreshnessSession.create("verifier:v332:guard:transparency", 0)
                    ledger = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
                    challenge = ledger.issue(1,100)
                    responses = [a.signed_response(challenge=challenge, verifier_id=session.verifier_id, verifier_epoch_sha256=session.epoch_sha256, requested_at=1, now_tick=10) for a in authorities[:2]]
                    pn_kwargs = dict(registry=pn_registry, current_policy=policy, expected_policy_sha256=policy["policy_sha256"], expected_provider_id=PROVIDER_ID, expected_service_id=PROVIDER_SERVICE_ID, expected_namespace_id=NAMESPACE_ID, expected_signer_id=PN_SIGNER_ID, expected_trust_domain=PN_DOMAIN, expected_effect_id=intent["effect_id"], expected_payload_sha256=B, expected_verifier_id=session_pn.verifier_id, expected_verifier_epoch_sha256=session_pn.epoch_sha256, expected_challenge=challenge_pn, evaluation_tick=10)
                    tr_kwargs = dict(anchor_registry=ids["immutable_registry"], transparency_registry=tr_registry, expected_anchor_id=IMMUTABLE_ANCHOR_ID, expected_anchor_authority_id=IMMUTABLE_AUTHORITY_ID, expected_anchor_service_id=IMMUTABLE_SERVICE_ID, expected_anchor_signer_id=IMMUTABLE_SIGNER_ID, expected_anchor_trust_domain=IMMUTABLE_DOMAIN, expected_provider_id=PROVIDER_ID, expected_provider_service_id=PROVIDER_SERVICE_ID, expected_retention_policy_id=RETENTION_POLICY_ID, config=config, expected_config_sha256=config["config_sha256"], challenge_ledger=ledger, expected_challenge=challenge, evaluation_tick=10)
                    with self.assertRaises(ProviderTransparencyGuardError) as caught:
                        verify_terminal_external_effect_guard(v331_guard_result={"status":"PASS", "authority_granted":False}, separate_authorization_valid=False, signed_provider_status=pn_status, provider_status_kwargs=pn_kwargs, signed_local_anchor_head=signed_head, signed_transparency_responses=responses, transparency_kwargs=tr_kwargs)
                    self.assertEqual(caught.exception.code, "separate_authorization_required")


if __name__ == "__main__":
    unittest.main()
