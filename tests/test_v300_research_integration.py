from __future__ import annotations

from copy import deepcopy
import unittest

from triaxis.assurance_v1 import (
    ASSURANCE_CASE_CONTRACT_ID,
    BRANCH_CONTRACT_ID,
    DEFEATER_CONTRACT_ID,
    EVIDENCE_CONTRACT_ID,
    FALSIFICATION_CONTRACT_ID,
    GATE_REQUEST_CONTRACT_ID,
    INTAKE_CONTRACT_ID,
    SYNTHESIS_CONTRACT_ID,
    seal_contract,
    validate_assurance_case,
)


def reseal(case):
    for branch in case["branches"]:
        sealed = seal_contract({**branch, "branch_sha256": ""}, "branch_sha256")
        branch.clear(); branch.update(sealed)
    for record in case["evidence"]:
        sealed = seal_contract({**record, "evidence_sha256": ""}, "evidence_sha256")
        record.clear(); record.update(sealed)
    for d in case["defeaters"]:
        sealed = seal_contract({**d, "defeater_sha256": ""}, "defeater_sha256")
        d.clear(); d.update(sealed)
    case["intake"] = seal_contract({**case["intake"], "intake_sha256": ""}, "intake_sha256")
    case["falsification"] = seal_contract({**case["falsification"], "falsification_sha256": ""}, "falsification_sha256")
    case["synthesis"] = seal_contract({**case["synthesis"], "synthesis_sha256": ""}, "synthesis_sha256")
    case["gate_request"] = seal_contract({**case["gate_request"], "gate_request_sha256": ""}, "gate_request_sha256")
    return seal_contract({**case, "case_sha256": ""}, "case_sha256")


def valid_case(profile="A2", risk="R2"):
    evidence = [
        {
            "contract_id": EVIDENCE_CONTRACT_ID,
            "evidence_id": "E1",
            "source_group": "primary-source-a",
            "source_type": "PRIMARY_SOURCE",
            "verification_mode": "SOURCE_CORROBORATION",
            "content_sha256": "a" * 64,
            "evidence_sha256": "",
        },
        {
            "contract_id": EVIDENCE_CONTRACT_ID,
            "evidence_id": "E2",
            "source_group": "deterministic-test",
            "source_type": "TEST_ARTIFACT",
            "verification_mode": "EXECUTABLE_TEST",
            "content_sha256": "b" * 64,
            "evidence_sha256": "",
        },
    ]
    branches = [
        {
            "contract_id": BRANCH_CONTRACT_ID,
            "branch_id": "B_PRIMARY",
            "pass_type": "PRIMARY",
            "provider": "provider-a",
            "model_family": "model-a",
            "context_id": "ctx-primary",
            "retrieval_set_id": "retrieval-a",
            "verification_mode": "GENERATIVE",
            "claims": [{"claim_id": "C1", "load_bearing": True, "classification": "SOURCE_BACKED", "evidence_ids": ["E1"]}],
            "branch_sha256": "",
        },
        {
            "contract_id": BRANCH_CONTRACT_ID,
            "branch_id": "B_DEVIL",
            "pass_type": "DEVIL",
            "provider": "provider-b",
            "model_family": "model-b",
            "context_id": "ctx-devil",
            "retrieval_set_id": "retrieval-b",
            "verification_mode": "GENERATIVE",
            "claims": [{"claim_id": "C2", "load_bearing": False, "classification": "INFERENCE", "evidence_ids": []}],
            "branch_sha256": "",
        },
        {
            "contract_id": BRANCH_CONTRACT_ID,
            "branch_id": "B_FALSIFIER",
            "pass_type": "FALSIFIER",
            "provider": "verifier-runtime",
            "model_family": "deterministic",
            "context_id": "ctx-verifier",
            "retrieval_set_id": "test-bank",
            "verification_mode": "EXECUTABLE_TEST",
            "claims": [{"claim_id": "C3", "load_bearing": True, "classification": "VERIFIED", "evidence_ids": ["E2"]}],
            "branch_sha256": "",
        },
    ]
    if risk in {"R3", "R4"}:
        branches.append({
            "contract_id": BRANCH_CONTRACT_ID,
            "branch_id": "B_REVIEW",
            "pass_type": "INDEPENDENT_REVIEW",
            "provider": "provider-c",
            "model_family": "model-c",
            "context_id": "ctx-review",
            "retrieval_set_id": "retrieval-c",
            "verification_mode": "GENERATIVE",
            "claims": [{"claim_id": "C4", "load_bearing": False, "classification": "INFERENCE", "evidence_ids": []}],
            "branch_sha256": "",
        })
    case = {
        "contract_id": ASSURANCE_CASE_CONTRACT_ID,
        "control_profile": profile,
        "intake": {
            "contract_id": INTAKE_CONTRACT_ID,
            "principal_id": "human:operator",
            "intent_id": "intent:1",
            "goal": "evaluate candidate",
            "capabilities": ["READ", "WRITE", "EXECUTE"],
            "max_risk_class": risk,
            "approvals": ([{"type": "HUMAN", "principal_id": "human:operator"}] if risk == "R4" else []),
            "intake_sha256": "",
        },
        "branches": branches,
        "evidence": evidence,
        "defeaters": [{
            "contract_id": DEFEATER_CONTRACT_ID,
            "defeater_id": "D1",
            "severity": "MATERIAL",
            "status": "MITIGATED",
            "resolution_evidence_ids": ["E2"],
            "defeater_sha256": "",
        }],
        "falsification": {
            "contract_id": FALSIFICATION_CONTRACT_ID,
            "hypothesis": "candidate works",
            "competing_hypothesis": "candidate fails",
            "observable_variable": "test outcome",
            "measurement": "execute frozen test",
            "threshold": "all critical cases pass",
            "time_window": "current run",
            "decision_update_rule": "failure => reject",
            "falsification_sha256": "",
        },
        "synthesis": {
            "contract_id": SYNTHESIS_CONTRACT_ID,
            "decision": "ACCEPT_WITH_CONTROLS",
            "authority_request": {"capabilities": ["READ"], "risk_class": risk},
            "synthesis_sha256": "",
        },
        "gate_request": {
            "contract_id": GATE_REQUEST_CONTRACT_ID,
            "policy_version": "policy:1",
            "state_snapshot_ref": "state:1",
            "action_payload_sha256": "c" * 64,
            "execution_target": "target:1",
            "nonce": "nonce:1",
            "expires_at": 10,
            "gate_request_sha256": "",
        },
        "case_sha256": "",
    }
    return reseal(case)


class V300ResearchIntegrationTests(unittest.TestCase):
    def test_valid_a2_case_passes(self):
        result = validate_assurance_case(valid_case())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["independence"]["B_FALSIFIER"], "I3_EXTERNAL_VERIFIER")

    def test_role_names_do_not_create_independence(self):
        case = valid_case()
        primary = case["branches"][0]
        devil = case["branches"][1]
        for field in ("provider", "model_family", "context_id", "retrieval_set_id"):
            devil[field] = primary[field]
        case = reseal(case)
        result = validate_assurance_case(case)
        self.assertEqual(result["independence"]["B_DEVIL"], "I0_ROLE_PLAY_ONLY")

    def test_authority_expansion_blocks(self):
        case = valid_case()
        case["synthesis"]["authority_request"]["capabilities"] = ["DELETE"]
        result = validate_assurance_case(reseal(case))
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("authority_expansion", {e["code"] for e in result["errors"]})

    def test_synthesizer_cannot_mint_permission(self):
        case = valid_case()
        case["synthesis"]["permission_status"] = "ALLOW"
        result = validate_assurance_case(reseal(case))
        self.assertIn("synthesis_self_authorization", {e["code"] for e in result["errors"]})

    def test_decorative_falsifier_blocks(self):
        case = valid_case()
        case["falsification"]["threshold"] = ""
        result = validate_assurance_case(reseal(case))
        self.assertIn("decorative_falsifier", {e["code"] for e in result["errors"]})

    def test_open_blocking_defeater_escalates(self):
        case = valid_case()
        case["defeaters"][0]["severity"] = "DECISION_BLOCKING"
        case["defeaters"][0]["status"] = "OPEN"
        case["defeaters"][0]["resolution_evidence_ids"] = []
        result = validate_assurance_case(reseal(case))
        self.assertEqual(result["status"], "ESCALATE")

    def test_resolved_defeater_requires_evidence(self):
        case = valid_case()
        case["defeaters"][0]["resolution_evidence_ids"] = []
        result = validate_assurance_case(reseal(case))
        self.assertIn("missing_resolution_evidence", {e["code"] for e in result["errors"]})

    def test_load_bearing_claim_requires_evidence_or_assumption_label(self):
        case = valid_case()
        case["branches"][0]["claims"][0]["evidence_ids"] = []
        result = validate_assurance_case(reseal(case))
        self.assertIn("unsupported_load_bearing_claim", {e["code"] for e in result["errors"]})

    def test_a3_requires_external_verifier(self):
        case = valid_case(profile="A3", risk="R3")
        falsifier = next(b for b in case["branches"] if b["pass_type"] == "FALSIFIER")
        falsifier["verification_mode"] = "GENERATIVE"
        result = validate_assurance_case(reseal(case))
        self.assertIn("external_verifier_required", {e["code"] for e in result["errors"]})

    def test_r3_requires_heterogeneous_review(self):
        case = valid_case(risk="R3")
        review = next(b for b in case["branches"] if b["pass_type"] == "INDEPENDENT_REVIEW")
        primary = next(b for b in case["branches"] if b["pass_type"] == "PRIMARY")
        for field in ("provider", "model_family", "context_id", "retrieval_set_id"):
            review[field] = primary[field]
        result = validate_assurance_case(reseal(case))
        self.assertIn("independent_review_required", {e["code"] for e in result["errors"]})

    def test_r4_requires_human_approval(self):
        case = valid_case(risk="R4")
        case["intake"]["approvals"] = []
        result = validate_assurance_case(reseal(case))
        self.assertIn("human_approval_required", {e["code"] for e in result["errors"]})

    def test_gate_request_cannot_mint_outcome(self):
        case = valid_case()
        case["gate_request"]["gate_outcome"] = "ALLOW"
        result = validate_assurance_case(reseal(case))
        self.assertIn("gate_request_contains_outcome", {e["code"] for e in result["errors"]})

    def test_unverified_assumption_is_honestly_allowed_structurally(self):
        case = valid_case()
        claim = case["branches"][0]["claims"][0]
        claim["evidence_ids"] = []
        claim["classification"] = "UNVERIFIED_ASSUMPTION"
        result = validate_assurance_case(reseal(case))
        self.assertEqual(result["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
