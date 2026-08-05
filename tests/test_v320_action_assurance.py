from __future__ import annotations

from copy import deepcopy
import tempfile
import unittest
from pathlib import Path

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    APPROVAL_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    ExecutionLedgerError,
    SQLiteExecutionLedger,
    action_scope_sha256,
    authorize_action,
    seal_contract,
    validate_action_envelope,
    validate_authorization_token,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy


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


def action(risk: str = "R2", approvals_spec=None, nonce: str = "nonce:1", witness=None, **updates):
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
        "state_witness": state() if witness is None else witness,
        "risk_class": risk,
        "nonce": nonce,
        "issued_at": 5,
        "expires_at": 15,
        "approvals": [],
        "scope_sha256": "",
        "action_sha256": "",
    }
    value.update(updates)
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
        token = authorize_action(a, policy(), 6, "gate:1")
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
        token = authorize_action(a, policy(), 6, "gate:1")
        self.assertEqual(token["outcome"], "DENY")

    def test_policy_denies_wrong_tool(self):
        a = action(tool_id="shell")
        token = authorize_action(a, policy(), 6, "gate:1")
        self.assertEqual(token["outcome"], "DENY")
        self.assertIn("tool_allowed", {item["code"] for item in token["errors"]})

    def test_r3_requires_two_trust_domains(self):
        one = action(risk="R3", approvals_spec=[("A1", "domain:one", "OPERATOR")])
        self.assertEqual(authorize_action(one, policy(), 6, "gate:1")["outcome"], "DENY")
        two = action(
            risk="R3",
            approvals_spec=[
                ("A1", "domain:one", "OPERATOR"),
                ("A2", "domain:two", "SECURITY"),
            ],
        )
        self.assertEqual(authorize_action(two, policy(), 6, "gate:1")["outcome"], "ALLOW")

    def test_r4_requires_human_approval(self):
        no_human = action(
            risk="R4",
            approvals_spec=[
                ("A1", "domain:one", "OPERATOR"),
                ("A2", "domain:two", "SECURITY"),
            ],
        )
        self.assertEqual(authorize_action(no_human, policy(), 6, "gate:1")["outcome"], "DENY")
        with_human = action(
            risk="R4",
            approvals_spec=[
                ("A1", "domain:one", "HUMAN"),
                ("A2", "domain:two", "SECURITY"),
            ],
        )
        self.assertEqual(authorize_action(with_human, policy(), 6, "gate:1")["outcome"], "ALLOW")

    def test_approval_scope_substitution_blocks(self):
        a = action(risk="R3", approvals_spec=[("A1", "d1", "OPERATOR"), ("A2", "d2", "SECURITY")])
        a = deepcopy(a)
        a["approvals"][0]["scope_sha256"] = "f" * 64
        a["approvals"][0] = seal_contract(a["approvals"][0], "approval_sha256")
        a = seal_contract(a, "action_sha256")
        result = validate_action_envelope(a, 6)
        self.assertIn("approval_scope_mismatch", {item["code"] for item in result["errors"]})

    def test_ledger_prepare_complete_and_exact_retry(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1")
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
        t1 = authorize_action(a1, policy(), 6, "gate:1")
        a2 = action(nonce="same", payload_sha256="e" * 64)
        t2 = authorize_action(a2, policy(), 6, "gate:1")
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                ledger.prepare(t1, a1["state_witness"], 6)
                with self.assertRaises(ExecutionLedgerError) as ctx:
                    ledger.prepare(t2, a2["state_witness"], 6)
                self.assertEqual(ctx.exception.code, "nonce_replay_conflict")

    def test_state_change_since_authorization_blocks_prepare(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1")
        changed = state(version=8, digest_char="e")
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                with self.assertRaises(ExecutionLedgerError) as ctx:
                    ledger.prepare(token, changed, 6)
                self.assertEqual(ctx.exception.code, "state_changed_since_authorization")

    def test_unknown_outcome_can_reconcile_complete(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1")
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
        token = authorize_action(a, policy(), 6, "gate:1")
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                ledger.prepare(token, a["state_witness"], 6)
                ledger.mark_unknown(token["nonce"], token["token_sha256"], 7)
                denied = ledger.reconcile_denied(token["nonce"], token["token_sha256"], "external id absent", 8)
                self.assertEqual(denied["state"], "RECONCILED_DENY")

    def test_completion_conflict_blocks(self):
        a = action()
        token = authorize_action(a, policy(), 6, "gate:1")
        with tempfile.TemporaryDirectory() as td:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                ledger.prepare(token, a["state_witness"], 6)
                ledger.complete(token["nonce"], token["token_sha256"], "e" * 64, "effect:1", 7)
                with self.assertRaises(ExecutionLedgerError) as ctx:
                    ledger.complete(token["nonce"], token["token_sha256"], "f" * 64, "effect:2", 8)
                self.assertEqual(ctx.exception.code, "completion_conflict")


if __name__ == "__main__":
    unittest.main()
