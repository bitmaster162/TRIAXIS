from __future__ import annotations

from copy import deepcopy
import unittest

from triaxis.assurance_v2 import (
    ASSURANCE_CASE_CONTRACT_ID, BRANCH_CONTRACT_ID, DEFEATER_CONTRACT_ID,
    EVIDENCE_CONTRACT_ID, FALSIFICATION_CONTRACT_ID, GATE_REQUEST_CONTRACT_ID,
    INTAKE_CONTRACT_ID, SYNTHESIS_CONTRACT_ID, seal_contract, validate_assurance_case,
)


def reseal(case):
    for key, digest in (("intake", "intake_sha256"), ("falsification", "falsification_sha256"), ("synthesis", "synthesis_sha256"), ("gate_request", "gate_request_sha256")):
        case[key] = seal_contract({**case[key], digest: ""}, digest)
    for list_key, digest in (("branches", "branch_sha256"), ("evidence", "evidence_sha256"), ("defeaters", "defeater_sha256")):
        for item in case[list_key]:
            sealed = seal_contract({**item, digest: ""}, digest)
            item.clear(); item.update(sealed)
    return seal_contract({**case, "case_sha256": ""}, "case_sha256")


def valid_case(profile="A2", risk="R2"):
    branches = [
        {"contract_id":BRANCH_CONTRACT_ID,"branch_id":"P","pass_type":"PRIMARY","provider":"openai","model_family":"gpt","context_id":"ctx-p","retrieval_set_id":"r-p","input_mode":"FULL_CONTEXT","verification_mode":"GENERATIVE","claims":[{"claim_id":"C1","load_bearing":True,"classification":"SOURCE_BACKED","evidence_ids":["E1"]}],"branch_sha256":""},
        {"contract_id":BRANCH_CONTRACT_ID,"branch_id":"D","pass_type":"DEVIL","provider":"google","model_family":"gemini","context_id":"ctx-d","retrieval_set_id":"r-d","input_mode":"BLIND_ARTIFACT","verification_mode":"GENERATIVE","claims":[{"claim_id":"C2","load_bearing":False,"classification":"INFERENCE","evidence_ids":[]}],"branch_sha256":""},
        {"contract_id":BRANCH_CONTRACT_ID,"branch_id":"F","pass_type":"FALSIFIER","provider":"runtime","model_family":"deterministic","context_id":"ctx-f","retrieval_set_id":"tests","input_mode":"INDEPENDENT_RETRIEVAL","verification_mode":"EXECUTABLE_TEST","claims":[{"claim_id":"C3","load_bearing":True,"classification":"VERIFIED","evidence_ids":["E2"]}],"branch_sha256":""},
    ]
    if risk in {"R3","R4"}:
        branches.append({"contract_id":BRANCH_CONTRACT_ID,"branch_id":"R","pass_type":"INDEPENDENT_REVIEW","provider":"anthropic","model_family":"claude","context_id":"ctx-r","retrieval_set_id":"r-r","input_mode":"INDEPENDENT_RETRIEVAL","verification_mode":"GENERATIVE","claims":[{"claim_id":"C4","load_bearing":True,"classification":"SOURCE_BACKED","evidence_ids":["E3"]}],"branch_sha256":""})
    c={
        "contract_id":ASSURANCE_CASE_CONTRACT_ID,
        "control_profile":profile,
        "intake":{"contract_id":INTAKE_CONTRACT_ID,"principal_id":"human:1","intent_id":"intent:1","goal":"assess","capabilities":["READ","WRITE"],"allowed_tools":["repo"],"forbidden_outcomes":["external_side_effect"],"max_risk_class":risk,"evaluation_tick":5,"approvals":([{"type":"HUMAN","principal_id":"human:1"}] if risk=="R4" else []),"intake_sha256":""},
        "branches":branches,
        "evidence":[
            {"contract_id":EVIDENCE_CONTRACT_ID,"evidence_id":"E1","source_group":"source-a","source_type":"PRIMARY_SOURCE","verification_mode":"SOURCE_CORROBORATION","content_sha256":"a"*64,"observed_at":4,"valid_until":8,"evidence_sha256":""},
            {"contract_id":EVIDENCE_CONTRACT_ID,"evidence_id":"E2","source_group":"test-a","source_type":"TEST_ARTIFACT","verification_mode":"EXECUTABLE_TEST","content_sha256":"b"*64,"observed_at":5,"valid_until":8,"evidence_sha256":""},
            {"contract_id":EVIDENCE_CONTRACT_ID,"evidence_id":"E3","source_group":"source-c","source_type":"PRIMARY_SOURCE","verification_mode":"SOURCE_CORROBORATION","content_sha256":"c"*64,"observed_at":4,"valid_until":8,"evidence_sha256":""},
        ],
        "defeaters":[{"contract_id":DEFEATER_CONTRACT_ID,"defeater_id":"D1","severity":"MATERIAL","status":"MITIGATED","resolution_evidence_ids":["E2"],"defeater_sha256":""}],
        "falsification":{"contract_id":FALSIFICATION_CONTRACT_ID,"falsifier_branch_id":"F","test_evidence_ids":["E2"],"hypothesis":"works","competing_hypothesis":"fails","observable_variable":"result","measurement":"run test","threshold":"critical tests pass","time_window":"run","decision_update_rule":"failure => reject","falsification_sha256":""},
        "synthesis":{"contract_id":SYNTHESIS_CONTRACT_ID,"decision":"ACCEPT_WITH_CONTROLS","authority_request":{"capabilities":["READ"],"risk_class":risk},"synthesis_sha256":""},
        "gate_request":{"contract_id":GATE_REQUEST_CONTRACT_ID,"policy_version":"p1","state_snapshot_ref":"s1","action_payload_sha256":"d"*64,"execution_target":"t1","nonce":"n1","expires_at":7,"gate_request_sha256":""},
        "case_sha256":"",
    }
    return reseal(c)


class V310Tests(unittest.TestCase):
    def test_positive(self): self.assertEqual(validate_assurance_case(valid_case())["status"],"PASS")
    def test_review_reusing_primary_source_blocks(self):
        c=valid_case(risk="R3"); next(b for b in c["branches"] if b["branch_id"]=="R")["claims"][0]["evidence_ids"]=["E1"]
        self.assertIn("independent_review_required",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})
    def test_missing_test_evidence_blocks(self):
        c=valid_case(); c["falsification"]["test_evidence_ids"]=[]
        self.assertIn("missing_test_evidence",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})
    def test_full_context_devil_blocks(self):
        c=valid_case(); next(b for b in c["branches"] if b["branch_id"]=="D")["input_mode"]="FULL_CONTEXT"
        self.assertIn("blind_review_required",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})
    def test_bad_payload_digest_blocks(self):
        c=valid_case(); c["gate_request"]["action_payload_sha256"]="x"
        self.assertIn("invalid_action_payload_digest",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})
    def test_stale_evidence_blocks(self):
        c=valid_case(); c["evidence"][0]["valid_until"]=4
        self.assertIn("stale_evidence",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})
    def test_unverified_load_bearing_escalates(self):
        c=valid_case(); cl=c["branches"][0]["claims"][0]; cl["evidence_ids"]=[]; cl["classification"]="UNVERIFIED_ASSUMPTION"
        self.assertEqual(validate_assurance_case(reseal(c))["status"],"ESCALATE")
    def test_expired_gate_blocks(self):
        c=valid_case(); c["gate_request"]["expires_at"]=5
        self.assertIn("expired_gate_request",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})
    def test_falsifier_binding_blocks_wrong_branch(self):
        c=valid_case(); c["falsification"]["falsifier_branch_id"]="D"
        self.assertIn("invalid_falsifier_binding",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})
    def test_non_verifying_test_evidence_blocks(self):
        c=valid_case(); c["falsification"]["test_evidence_ids"]=["E1"]
        self.assertIn("non_verifying_test_evidence",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})
    def test_exactly_one_primary(self):
        c=valid_case(); x=deepcopy(c["branches"][0]); x["branch_id"]="P2"; x["claims"][0]["claim_id"]="C9"; c["branches"].append(x)
        self.assertIn("invalid_primary_count",{e["code"] for e in validate_assurance_case(reseal(c))["errors"]})

if __name__=='__main__': unittest.main()
