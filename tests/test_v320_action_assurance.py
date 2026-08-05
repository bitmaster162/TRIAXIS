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
    SQLiteExecutionLedger,
    action_scope_sha256,
    assured_action_request_sha256,
    authorize_action,
    seal_contract,
    validate_action_envelope,
    validate_authorization_token,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy



TRUSTED_ASSURANCE = {"assurance-compiler:1": "assurance-domain:1"}


def assurance_attestation(
    decision_digest: str = "b" * 64,
    evidence_digest: str = "c" * 64,
    subject: str = "subject:1",
    issuer: str = "assurance-compiler:1",
    trust_domain: str = "assurance-domain:1",
    assurance_status: str = "PASS",
    synthesis_decision: str = "ACCEPT",
    issued_at: int = 5,
    valid_until: int = 15,
    assured_action_digest: str = "f" * 64,
):
    return seal_contract(
        {
            "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
            "attestation_id": "attestation:1",
            "issuer_id": issuer,
            "trust_domain": trust_domain,
            "subject_id": subject,
            "decision_case_sha256": decision_digest,
            "evidence_report_sha256": evidence_digest,
            "assured_action_request_sha256": assured_action_digest,
            "assurance_status": assurance_status,
            "synthesis_decision": synthesis_decision,
            "attestation_level": "AUTHENTICATED",
            "issued_at": issued_at,
            "valid_until": valid_until,
            "attestation_sha256": "",
        },
        "attestation_sha256",
    )

def state(version: int = 7, digest_char: str = "a", subject: str = "subject:1", object_id: str = "repo:triaxis"):
    return seal_contract(
        {
            "contract_id": STATE_WITNESS_CONTRACT_ID,
            "state_id": "state:repo",
            "subject_id": subject,
            "object_id": object_id,
            "adapter_id": "git-adapter:1",
            "version": version,
            "state_sha256": digest_char * 64,
            "attestation_level": "AUTHENTICATED",
            "observed_at": 5,
            "valid_until": 20,
            "witness_sha256": "",
        },
        "witness_sha256",
    )


def policy(max_risk: str = "R4", required_approvals=None):
    return seal_policy(
        {
            "contract_id": POLICY_BUNDLE_CONTRACT_ID,
            "policy_id": "policy:repo-write",
            "subject_id": "subject:1",
            "issuer_id": "policy-engine:1",
            "sequence": 3,
            "minimum_accepted_sequence": 3,
            "state": "ACTIVE",
            "effective_from": 1,
            "valid_until": 20,
            "allowed_capabilities": ["READ", "WRITE"],
            "allowed_tools": ["git"],
            "allowed_targets": ["repo:triaxis"],
            "max_risk_class": max_risk,
            "required_approval_types": [] if required_approvals is None else required_approvals,
            "supersedes_policy_sha256": None,
            "policy_sha256": "",
        }
    )


def approval(approval_id: str, scope: str, trust_domain: str, approval_type: str = "OPERATOR"):
    return seal_contract(
        {
            "contract_id": APPROVAL_CONTRACT_ID,
            "approval_id": approval_id,
            "principal_id": f"principal:{approval_id}",
            "trust_domain": trust_domain,
            "approval_type": approval_type,
            "scope_sha256": scope,
            "issued_at": 5,
            "expires_at": 15,
            "approval_sha256": "",
        },
        "approval_sha256",
    )


def action(
    risk: str = "R2",
    approvals_spec=None,
    nonce: str = "nonce:1",
    witness=None,
    attestation_overrides=None,
    **updates,
):
    value = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "principal_id": "human:1",
        "intent_id": "intent:1",
        "decision_case_sha256": "b" * 64,
        "evidence_report_sha256": "c" * 64,
        "subject_id": "subject:1",
        "object_id": "repo:triaxis",
        "capability": "WRITE",
        "tool_id": "git",
        "execution_target": "repo:triaxis",
        "payload_sha256": "d" * 64,
        "policy_id": "policy:repo-write",
        "policy_sequence": 3,
        "policy_sha256": policy()["policy_sha256"],
        "state_witness": state() if witness is None else witness,
        "risk_class": risk,
        "nonce": nonce,
        "issued_at": 5,
        "expires_at": 15,
        "approvals": [],
        "assured_action_request_sha256": "",
        "scope_sha256": "",
        "action_sha256": "",
    }
    value.update(updates)
    value["assured_action_request_sha256"] = assured_action_request_sha256(value)
    attestation = {
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": "attestation:1",
        "issuer_id": "assurance-compiler:1",
        "trust_domain": "assurance-domain:1",
        "subject_id": value["subject_id"],
        "decision_case_sha256": value["decision_case_sha256"],
        "evidence_report_sha256": value["evidence_report_sha256"],
        "assured_action_request_sha256": value["assured_action_request_sha256"],
        "assurance_status": "PASS",
        "synthesis_decision": "ACCEPT",
        "attestation_level": "AUTHENTICATED",
        "issued_at": 5,
        "valid_until": 15,
        "attestation_sha256": "",
    }
    if attestation_overrides:
        attestation.update(attestation_overrides)
    value["assurance_attestation"] = seal_contract(attestation, "attestation_sha256")
    value["scope_sha256"] = action_scope_sha256(value)
    if approvals_spec:
        value["approvals"] = [
            approval(aid, value["scope_sha256"], domain, atype)
            for aid, domain, atype in approvals_spec
        ]
    return seal_contract(value, "action_sha256")



class ActionAssuranceTests(unittest.TestCase):
    def test_valid_r2_action_authorizes(self):
        a = action()
        self.assertEqual(validate_action_envelope(a, 6)["status"], "PASS")
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "ALLOW", token)
        self.assertEqual(validate_authorization_token(token, 6)["status"], "PASS")

    def test_payload_and_scope_tamper_block(self):
        a = action()
        a["payload_sha256"] = "e" * 64
        a = seal_contract(a, "action_sha256")
        result = validate_action_envelope(a, 6)
        self.assertIn("scope_digest_mismatch", {item["code"] for item in result["errors"]})

    def test_state_subject_substitution_blocks(self):
        a = action(witness=state(subject="subject:other"))
        result = validate_action_envelope(a, 6)
        self.assertIn("state_subject_mismatch", {item["code"] for item in result["errors"]})

    def test_stale_state_blocks(self):
        witness = state()
        witness["valid_until"] = 6
        witness = seal_contract(witness, "witness_sha256")
        a = action(witness=witness)
        result = validate_action_envelope(a, 6)
        self.assertIn("stale_state_witness", {item["code"] for item in result["errors"]})

    def test_expired_action_denies(self):
        a = action(expires_at=6)
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")

    def test_policy_denies_wrong_tool(self):
        a = action(tool_id="shell")
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("tool_allowed", {item["code"] for item in token["errors"]})

    def test_r3_requires_two_trust_domains(self):
        one = action(risk="R3", approvals_spec=[("A1", "domain:one", "OPERATOR")])
        self.assertEqual(authorize_action(one, policy(), 6, "gate:1", TRUSTED_ASSURANCE)["outcome"], "DENY")
        two = action(
            risk="R3",
            approvals_spec=[
                ("A1", "domain:one", "OPERATOR"),
                ("A2", "domain:two", "SECURITY"),
            ],
        )
        self.assertEqual(authorize_action(two, policy(), 6, "gate:1", TRUSTED_ASSURANCE)["outcome"], "ALLOW")

    def test_r4_requires_human_approval(self):
        no_human = action(
            risk="R4",
            approvals_spec=[
                ("A1", "domain:one", "OPERATOR"),
                ("A2", "domain:two", "SECURITY"),
            ],
        )
        self.assertEqual(authorize_action(no_human, policy(), 6, "gate:1", TRUSTED_ASSURANCE)["outcome"], "DENY")
        with_human = action(
            risk="R4",
            approvals_spec=[
                ("A1", "domain:one", "HUMAN"),
                ("A2", "domain:two", "SECURITY"),
            ],
        )
        self.assertEqual(authorize_action(with_human, policy(), 6, "gate:1", TRUSTED_ASSURANCE)["outcome"], "ALLOW")

    def test_approval_scope_substitution_blocks(self):
        a = action(risk="R3", approvals_spec=[("A1", "d1", "OPERATOR"), ("A2", "d2", "SECURITY")])
        a = deepcopy(a)
        a["approvals"][0]["scope_sha256"] = "f" * 64
        a["approvals"][0] = seal_contract(a["approvals"][0], "approval_sha256")
        a = seal_contract(a, "action_sha256")
        result = validate_action_envelope(a, 6)
        self.assertIn("approval_scope_mismatch", {item["code"] for item in result["errors"]})

    def test_decision_digest_requires_exact_assurance_binding(self):
        a = action(decision_case_sha256="0" * 64, attestation_overrides={"decision_case_sha256": "b" * 64})
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("assurance_decision_mismatch", {item["code"] for item in token["errors"]})

    def test_evidence_digest_requires_exact_assurance_binding(self):
        a = action(evidence_report_sha256="0" * 64, attestation_overrides={"evidence_report_sha256": "c" * 64})
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("assurance_evidence_mismatch", {item["code"] for item in token["errors"]})

    def test_untrusted_assurance_issuer_denies(self):
        a = action(attestation_overrides={"issuer_id": "attacker:1", "trust_domain": "attacker"})
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("untrusted_assurance_issuer", {item["code"] for item in token["errors"]})

    def test_wrong_trust_domain_denies(self):
        a = action(attestation_overrides={"trust_domain": "wrong-domain"})
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("untrusted_assurance_issuer", {item["code"] for item in token["errors"]})

    def test_non_pass_or_expired_attestation_denies(self):
        blocked = action(attestation_overrides={"assurance_status": "BLOCK"})
        expired = action(attestation_overrides={"valid_until": 6}, nonce="nonce:expired")
        self.assertEqual(authorize_action(blocked, policy(), 6, "gate:1", TRUSTED_ASSURANCE)["outcome"], "DENY")
        self.assertEqual(authorize_action(expired, policy(), 6, "gate:1", TRUSTED_ASSURANCE)["outcome"], "DENY")

    def test_synthesizer_cannot_authorize_reject(self):
        a = action(attestation_overrides={"synthesis_decision": "REJECT"})
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("invalid_synthesis_decision", {item["code"] for item in token["errors"]})

    def test_action_is_bound_to_exact_policy_digest(self):
        a = action()
        substituted = policy()
        substituted["allowed_tools"] = ["git", "shell"]
        substituted = seal_policy(substituted)
        token = authorize_action(a, substituted, 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("policy_digest_mismatch", {item["code"] for item in token["errors"]})

    def test_pass_attestation_cannot_be_reused_for_another_payload(self):
        original = action()
        altered = action(
            nonce="payload:other",
            payload_sha256="e" * 64,
            attestation_overrides={
                "assured_action_request_sha256": original["assured_action_request_sha256"]
            },
        )
        token = authorize_action(altered, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("assured_action_request_mismatch", {item["code"] for item in token["errors"]})

    def test_set_only_trust_registry_is_rejected(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1", {"assurance-compiler:1"})
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("untrusted_assurance_issuer", {item["code"] for item in token["errors"]})

    def test_ledger_prepare_complete_and_exact_retry(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                first = ledger.prepare(token, a["state_witness"], 6)
                second = ledger.prepare(token, a["state_witness"], 6)
                self.assertEqual(first["token_sha256"], second["token_sha256"])
                complete = ledger.complete(token["nonce"], token["token_sha256"], "e" * 64, "effect:1", 7)
                retry = ledger.complete(token["nonce"], token["token_sha256"], "e" * 64, "effect:1", 7)
                self.assertEqual(complete["receipt"], retry["receipt"])
                self.assertEqual(complete["state"], "COMPLETED")

    def test_nonce_replay_conflict(self):
        a1 = action(nonce="same")
        t1 = authorize_action(a1, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        a2 = action(nonce="same", payload_sha256="e" * 64)
        t2 = authorize_action(a2, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                ledger.prepare(t1, a1["state_witness"], 6)
                with self.assertRaises(ExecutionLedgerError) as ctx:
                    ledger.prepare(t2, a2["state_witness"], 6)
                self.assertEqual(ctx.exception.code, "nonce_replay_conflict")

    def test_state_change_since_authorization_blocks_prepare(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        changed = state(version=8, digest_char="e")
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                with self.assertRaises(ExecutionLedgerError) as ctx:
                    ledger.prepare(token, changed, 6)
                self.assertEqual(ctx.exception.code, "state_changed_since_authorization")

    def test_unknown_outcome_can_reconcile_complete(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                ledger.prepare(token, a["state_witness"], 6)
                unknown = ledger.mark_unknown(token["nonce"], token["token_sha256"], 7)
                self.assertEqual(unknown["state"], "UNKNOWN")
                completed = ledger.complete(token["nonce"], token["token_sha256"], "f" * 64, "effect:recovered", 8)
                self.assertEqual(completed["state"], "RECONCILED_COMPLETE")
                self.assertEqual(completed["receipt"]["resolution"], "RECONCILED")

    def test_unknown_outcome_can_reconcile_no_effect(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                ledger.prepare(token, a["state_witness"], 6)
                ledger.mark_unknown(token["nonce"], token["token_sha256"], 7)
                denied = ledger.reconcile_denied(token["nonce"], token["token_sha256"], "external id absent", 8)
                self.assertEqual(denied["state"], "RECONCILED_DENY")

    def test_completion_conflict_blocks(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1", TRUSTED_ASSURANCE)
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                ledger.prepare(token, a["state_witness"], 6)
                ledger.complete(token["nonce"], token["token_sha256"], "e" * 64, "effect:1", 7)
                with self.assertRaises(ExecutionLedgerError) as ctx:
                    ledger.complete(token["nonce"], token["token_sha256"], "f" * 64, "effect:2", 8)
                self.assertEqual(ctx.exception.code, "completion_conflict")


if __name__ == "__main__":
    unittest.main()
