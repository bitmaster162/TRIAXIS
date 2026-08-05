from __future__ import annotations

from copy import deepcopy
import tempfile
import unittest
from pathlib import Path

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    APPROVAL_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    ExecutionLedgerError,
    action_scope_sha256,
    assured_action_request_sha256,
    seal_contract,
)
from triaxis.authenticated_action_assurance import (
    AuthenticatedSQLiteExecutionLedger,
    authorize_authenticated_action,
    validate_authenticated_authorization,
)
from triaxis.crypto_trust import (
    PURPOSE_ACTION_APPROVAL,
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_POLICY_BUNDLE,
    PURPOSE_STATE_WITNESS,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy


class Fixture:
    def __init__(self) -> None:
        self.keys = {}
        self.registry = TrustKeyRegistry()
        for key_id, signer, domain, purposes in (
            ("key:assurance", "assurance:1", "domain:assurance", [PURPOSE_ASSURANCE_ATTESTATION]),
            ("key:state", "adapter:state", "domain:state", [PURPOSE_STATE_WITNESS]),
            ("key:policy", "policy-engine:1", "domain:policy", [PURPOSE_POLICY_BUNDLE]),
            ("key:gate", "gate:1", "domain:gate", [PURPOSE_AUTHORIZATION_TOKEN]),
            ("key:operator", "principal:operator", "domain:operator", [PURPOSE_ACTION_APPROVAL]),
            ("key:security", "principal:security", "domain:security", [PURPOSE_ACTION_APPROVAL]),
        ):
            pair = generate_ed25519_keypair()
            self.keys[key_id] = pair
            self.registry.add(make_trust_key_record(
                key_id=key_id,
                signer_id=signer,
                trust_domain=domain,
                public_key_b64=pair["public_key_b64"],
                purposes=purposes,
                valid_from=1,
                valid_until=100,
            ))

    def policy(self) -> dict:
        return seal_policy({
            "contract_id": POLICY_BUNDLE_CONTRACT_ID,
            "policy_id": "policy:write",
            "subject_id": "subject:1",
            "issuer_id": "policy-engine:1",
            "sequence": 1,
            "minimum_accepted_sequence": 1,
            "state": "ACTIVE",
            "effective_from": 1,
            "valid_until": 50,
            "allowed_capabilities": ["WRITE"],
            "allowed_tools": ["git"],
            "allowed_targets": ["repo:1"],
            "max_risk_class": "R4",
            "required_approval_types": [],
            "supersedes_policy_sha256": None,
            "policy_sha256": "",
        })

    def state(self) -> dict:
        return seal_contract({
            "contract_id": STATE_WITNESS_CONTRACT_ID,
            "state_id": "state:1",
            "subject_id": "subject:1",
            "object_id": "repo:1",
            "adapter_id": "adapter:state",
            "version": 7,
            "state_sha256": "a" * 64,
            "attestation_level": "AUTHENTICATED",
            "observed_at": 5,
            "valid_until": 40,
            "witness_sha256": "",
        }, "witness_sha256")

    def approval(self, principal: str, domain: str, approval_type: str, scope: str) -> dict:
        return seal_contract({
            "contract_id": APPROVAL_CONTRACT_ID,
            "approval_id": f"approval:{principal}",
            "principal_id": principal,
            "trust_domain": domain,
            "approval_type": approval_type,
            "scope_sha256": scope,
            "issued_at": 5,
            "expires_at": 30,
            "approval_sha256": "",
        }, "approval_sha256")

    def action(self, risk: str = "R2", nonce: str = "nonce:1") -> dict:
        policy = self.policy()
        action = {
            "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
            "principal_id": "human:1",
            "intent_id": "intent:1",
            "decision_case_sha256": "b" * 64,
            "evidence_report_sha256": "c" * 64,
            "subject_id": "subject:1",
            "object_id": "repo:1",
            "capability": "WRITE",
            "tool_id": "git",
            "execution_target": "repo:1",
            "payload_sha256": "d" * 64,
            "policy_id": "policy:write",
            "policy_sequence": 1,
            "policy_sha256": policy["policy_sha256"],
            "state_witness": self.state(),
            "risk_class": risk,
            "nonce": nonce,
            "issued_at": 5,
            "expires_at": 25,
            "approvals": [],
            "assured_action_request_sha256": "",
            "scope_sha256": "",
            "action_sha256": "",
        }
        action["assured_action_request_sha256"] = assured_action_request_sha256(action)
        action["assurance_attestation"] = seal_contract({
            "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
            "attestation_id": "attestation:1",
            "issuer_id": "assurance:1",
            "trust_domain": "domain:assurance",
            "subject_id": action["subject_id"],
            "decision_case_sha256": action["decision_case_sha256"],
            "evidence_report_sha256": action["evidence_report_sha256"],
            "assured_action_request_sha256": action["assured_action_request_sha256"],
            "assurance_status": "PASS",
            "synthesis_decision": "ACCEPT",
            "attestation_level": "AUTHENTICATED",
            "issued_at": 5,
            "valid_until": 20,
            "attestation_sha256": "",
        }, "attestation_sha256")
        action["scope_sha256"] = action_scope_sha256(action)
        if risk == "R3":
            action["approvals"] = [
                self.approval("principal:operator", "domain:operator", "OPERATOR", action["scope_sha256"]),
                self.approval("principal:security", "domain:security", "SECURITY", action["scope_sha256"]),
            ]
        return seal_contract(action, "action_sha256")

    def sign(self, contract: dict, *, field: str, purpose: str, key_id: str, signer: str, domain: str, valid_until: int = 30) -> dict:
        return sign_contract_envelope(
            contract,
            digest_field=field,
            purpose=purpose,
            key_id=key_id,
            signer_id=signer,
            trust_domain=domain,
            private_key_b64=self.keys[key_id]["private_key_b64"],
            issued_at=5,
            valid_until=valid_until,
        )

    def authorized(self, action: dict | None = None, policy: dict | None = None, signed_approvals=None):
        action = self.action() if action is None else action
        policy = self.policy() if policy is None else policy
        signed_approvals = [] if signed_approvals is None else signed_approvals
        return authorize_authenticated_action(
            action_value=action,
            policy_value=policy,
            evaluation_tick=6,
            registry=self.registry,
            signed_assurance_attestation=self.sign(
                action["assurance_attestation"], field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION,
                key_id="key:assurance", signer="assurance:1", domain="domain:assurance", valid_until=20,
            ),
            signed_state_witness=self.sign(
                action["state_witness"], field="witness_sha256", purpose=PURPOSE_STATE_WITNESS,
                key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40,
            ),
            signed_policy_bundle=self.sign(
                policy, field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE,
                key_id="key:policy", signer="policy-engine:1", domain="domain:policy", valid_until=50,
            ),
            signed_approvals=signed_approvals,
            gate_key_id="key:gate",
            gate_signer_id="gate:1",
            gate_trust_domain="domain:gate",
            gate_private_key_b64=self.keys["key:gate"]["private_key_b64"],
        )


class CryptographicAuthenticityTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()

    def test_authenticated_positive_path(self):
        result = self.fx.authorized()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["token"]["outcome"], "ALLOW")
        self.assertEqual(validate_authenticated_authorization(result["signed_token"], registry=self.fx.registry, evaluation_tick=6)["status"], "PASS")

    def test_forged_assurance_digest_without_signature_blocks(self):
        action = self.fx.action()
        forged_pair = generate_ed25519_keypair()
        forged = sign_contract_envelope(
            action["assurance_attestation"], digest_field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION,
            key_id="key:assurance", signer_id="assurance:1", trust_domain="domain:assurance",
            private_key_b64=forged_pair["private_key_b64"], issued_at=5, valid_until=20,
        )
        result = authorize_authenticated_action(
            action_value=action, policy_value=self.fx.policy(), evaluation_tick=6, registry=self.fx.registry,
            signed_assurance_attestation=forged,
            signed_state_witness=self.fx.sign(action["state_witness"], field="witness_sha256", purpose=PURPOSE_STATE_WITNESS, key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40),
            signed_policy_bundle=self.fx.sign(self.fx.policy(), field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE, key_id="key:policy", signer="policy-engine:1", domain="domain:policy", valid_until=50),
            signed_approvals=[], gate_key_id="key:gate", gate_signer_id="gate:1", gate_trust_domain="domain:gate", gate_private_key_b64=self.fx.keys["key:gate"]["private_key_b64"],
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("invalid_signature", {row["code"] for row in result["errors"]})

    def test_unsigned_state_cannot_reach_authenticated_boundary(self):
        action = self.fx.action()
        result = authorize_authenticated_action(
            action_value=action, policy_value=self.fx.policy(), evaluation_tick=6, registry=self.fx.registry,
            signed_assurance_attestation=self.fx.sign(action["assurance_attestation"], field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION, key_id="key:assurance", signer="assurance:1", domain="domain:assurance", valid_until=20),
            signed_state_witness=action["state_witness"],
            signed_policy_bundle=self.fx.sign(self.fx.policy(), field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE, key_id="key:policy", signer="policy-engine:1", domain="domain:policy", valid_until=50),
            signed_approvals=[], gate_key_id="key:gate", gate_signer_id="gate:1", gate_trust_domain="domain:gate", gate_private_key_b64=self.fx.keys["key:gate"]["private_key_b64"],
        )
        self.assertEqual(result["status"], "BLOCK")

    def test_forged_policy_key_blocks(self):
        action = self.fx.action()
        policy = self.fx.policy()
        other = generate_ed25519_keypair()
        forged_policy = sign_contract_envelope(
            policy, digest_field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE,
            key_id="key:policy", signer_id="policy-engine:1", trust_domain="domain:policy",
            private_key_b64=other["private_key_b64"], issued_at=5, valid_until=50,
        )
        result = authorize_authenticated_action(
            action_value=action, policy_value=policy, evaluation_tick=6, registry=self.fx.registry,
            signed_assurance_attestation=self.fx.sign(action["assurance_attestation"], field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION, key_id="key:assurance", signer="assurance:1", domain="domain:assurance", valid_until=20),
            signed_state_witness=self.fx.sign(action["state_witness"], field="witness_sha256", purpose=PURPOSE_STATE_WITNESS, key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40),
            signed_policy_bundle=forged_policy, signed_approvals=[], gate_key_id="key:gate", gate_signer_id="gate:1", gate_trust_domain="domain:gate", gate_private_key_b64=self.fx.keys["key:gate"]["private_key_b64"],
        )
        self.assertEqual(result["status"], "BLOCK")

    def test_r3_requires_authentic_approval_signatures(self):
        action = self.fx.action(risk="R3", nonce="nonce:r3")
        signed = [
            self.fx.sign(action["approvals"][0], field="approval_sha256", purpose=PURPOSE_ACTION_APPROVAL, key_id="key:operator", signer="principal:operator", domain="domain:operator"),
            self.fx.sign(action["approvals"][1], field="approval_sha256", purpose=PURPOSE_ACTION_APPROVAL, key_id="key:security", signer="principal:security", domain="domain:security"),
        ]
        result = self.fx.authorized(action=action, signed_approvals=signed)
        self.assertEqual(result["status"], "PASS", result)
        forged = deepcopy(signed)
        forged[0]["signature_b64"] = forged[0]["signature_b64"][:-2] + "AA"
        result = self.fx.authorized(action=action, signed_approvals=forged)
        self.assertEqual(result["status"], "BLOCK")

    def test_key_purpose_is_enforced(self):
        action = self.fx.action()
        wrong = sign_contract_envelope(
            action["assurance_attestation"], digest_field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION,
            key_id="key:state", signer_id="adapter:state", trust_domain="domain:state",
            private_key_b64=self.fx.keys["key:state"]["private_key_b64"], issued_at=5, valid_until=20,
        )
        result = verify_contract_envelope(
            wrong, registry=self.fx.registry, evaluation_tick=6,
            expected_purpose=PURPOSE_ASSURANCE_ATTESTATION, expected_digest_field="attestation_sha256",
            expected_inner_contract_id=ASSURANCE_ATTESTATION_CONTRACT_ID,
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("key_purpose_denied", {row["code"] for row in result["errors"]})

    def test_revoked_key_blocks_existing_signature(self):
        action = self.fx.action()
        signed = self.fx.sign(action["assurance_attestation"], field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION, key_id="key:assurance", signer="assurance:1", domain="domain:assurance", valid_until=20)
        pair = self.fx.keys["key:assurance"]
        registry = TrustKeyRegistry([make_trust_key_record(
            key_id="key:assurance", signer_id="assurance:1", trust_domain="domain:assurance",
            public_key_b64=pair["public_key_b64"], purposes=[PURPOSE_ASSURANCE_ATTESTATION],
            valid_from=1, valid_until=100, revoked_at=6,
        )])
        result = verify_contract_envelope(signed, registry=registry, evaluation_tick=6, expected_purpose=PURPOSE_ASSURANCE_ATTESTATION, expected_digest_field="attestation_sha256")
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("signing_key_revoked", {row["code"] for row in result["errors"]})


    def test_gate_private_key_mismatch_returns_deny(self):
        action = self.fx.action()
        wrong = generate_ed25519_keypair()
        result = authorize_authenticated_action(
            action_value=action, policy_value=self.fx.policy(), evaluation_tick=6, registry=self.fx.registry,
            signed_assurance_attestation=self.fx.sign(action["assurance_attestation"], field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION, key_id="key:assurance", signer="assurance:1", domain="domain:assurance", valid_until=20),
            signed_state_witness=self.fx.sign(action["state_witness"], field="witness_sha256", purpose=PURPOSE_STATE_WITNESS, key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40),
            signed_policy_bundle=self.fx.sign(self.fx.policy(), field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE, key_id="key:policy", signer="policy-engine:1", domain="domain:policy", valid_until=50),
            signed_approvals=[], gate_key_id="key:gate", gate_signer_id="gate:1", gate_trust_domain="domain:gate", gate_private_key_b64=wrong["private_key_b64"],
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertEqual(result["token"]["outcome"], "DENY")

    def test_forged_gate_token_is_rejected_by_authenticated_ledger(self):
        result = self.fx.authorized()
        forged_pair = generate_ed25519_keypair()
        forged_signed_token = sign_contract_envelope(
            result["token"], digest_field="token_sha256", purpose=PURPOSE_AUTHORIZATION_TOKEN,
            key_id="key:gate", signer_id="gate:1", trust_domain="domain:gate",
            private_key_b64=forged_pair["private_key_b64"], issued_at=6, valid_until=20,
        )
        signed_state = self.fx.sign(self.fx.state(), field="witness_sha256", purpose=PURPOSE_STATE_WITNESS, key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40)
        with tempfile.TemporaryDirectory() as tmp:
            with AuthenticatedSQLiteExecutionLedger(Path(tmp) / "ledger.db", self.fx.registry) as ledger:
                with self.assertRaises(ExecutionLedgerError):
                    ledger.prepare_authenticated(forged_signed_token, signed_state, 6)

    def test_authenticated_ledger_accepts_exact_signed_token_and_state(self):
        result = self.fx.authorized()
        signed_state = self.fx.sign(self.fx.state(), field="witness_sha256", purpose=PURPOSE_STATE_WITNESS, key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40)
        with tempfile.TemporaryDirectory() as tmp:
            with AuthenticatedSQLiteExecutionLedger(Path(tmp) / "ledger.db", self.fx.registry) as ledger:
                prepared = ledger.prepare_authenticated(result["signed_token"], signed_state, 6)
        self.assertEqual(prepared["state"], "PREPARED")


if __name__ == "__main__":
    unittest.main()
