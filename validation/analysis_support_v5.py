"""Valid fixtures for the recovered TRIAXIS Analysis Bundle v5."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, Callable

from triaxis import analysis_v5


def _claim(claim_id: str, role: str, text: str, option_id: str = "O1") -> dict[str, Any]:
    return {
        "claim_id": claim_id,
        "role": role,
        "text": text,
        "target_option_ids": [option_id],
        "evidence_ids": ["E1"],
    }


def reseal_analysis_bundle_v5(bundle: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(bundle))
    result["frame"] = analysis_v5.seal_contract(result["frame"], "frame_sha256")
    passes: list[dict[str, Any]] = []
    for item in result["passes"]:
        passes.append(analysis_v5.seal_contract(item, "pass_sha256"))
    result["passes"] = passes
    result["synthesis"]["pass_digests"] = {
        item["pass_type"]: item["pass_sha256"] for item in passes
    }
    result["synthesis"] = analysis_v5.seal_contract(result["synthesis"], "synthesis_sha256")
    return analysis_v5.seal_contract(result, "bundle_sha256")


def build_valid_analysis_bundle_v5(
    *,
    run_id: str = "analysis-v5-recovery-001",
    control_profile: str = "A2",
    evaluation_tick: int = 5,
) -> dict[str, Any]:
    frame = {
        "contract_id": analysis_v5.ANALYSIS_FRAME_CONTRACT_ID,
        "run_id": run_id,
        "control_profile": control_profile,
        "goal": "Validate a bounded TRIAXIS recovery decision",
        "evaluation_tick": evaluation_tick,
        "frame_sha256": "",
    }
    passes = [
        {
            "contract_id": analysis_v5.ANALYTIC_PASS_CONTRACT_ID,
            "pass_id": "pass-primary",
            "pass_type": "PRIMARY",
            "independence_class": "SAME_MODEL_PASS",
            "independent_verification_refs": [],
            "claims": [_claim("P_RATIONALE", "RATIONALE", "O1 is the bounded candidate")],
            "payload": {"proposed_option_id": "O1"},
            "pass_sha256": "",
        },
        {
            "contract_id": analysis_v5.ANALYTIC_PASS_CONTRACT_ID,
            "pass_id": "pass-audit",
            "pass_type": "SELF_AUDIT",
            "independence_class": "SAME_MODEL_PASS",
            "independent_verification_refs": [],
            "claims": [_claim("S_CONTROL", "CONTROL", "Reject invalid synthesis before state commit")],
            "payload": {"audit_status": "PASS_WITH_CONDITIONS"},
            "pass_sha256": "",
        },
        {
            "contract_id": analysis_v5.ANALYTIC_PASS_CONTRACT_ID,
            "pass_id": "pass-devil",
            "pass_type": "DEVIL",
            "independence_class": "SAME_MODEL_PASS",
            "independent_verification_refs": [],
            "claims": [_claim("D_ACTION_RISK", "RISK", "State can be consumed before analysis acceptance")],
            "payload": {"failure_chain": "valid envelope -> invalid analysis -> state poison"},
            "pass_sha256": "",
        },
        {
            "contract_id": analysis_v5.ANALYTIC_PASS_CONTRACT_ID,
            "pass_id": "pass-angel",
            "pass_type": "ANGEL",
            "independence_class": "SAME_MODEL_PASS",
            "independent_verification_refs": [],
            "claims": [_claim("A_VALUE", "VALUE", "Authenticated monotonic state is valuable")],
            "payload": {"valuable_core": ["authenticated state"]},
            "pass_sha256": "",
        },
        {
            "contract_id": analysis_v5.ANALYTIC_PASS_CONTRACT_ID,
            "pass_id": "pass-falsifier",
            "pass_type": "FALSIFIER",
            "independence_class": "INDEPENDENT_VERIFICATION" if control_profile == "A3" else "SAME_MODEL_PASS",
            "independent_verification_refs": ["artifact:external-review-001"] if control_profile == "A3" else [],
            "claims": [_claim("T_DISCRIMINATES", "TEST_META", "State equality distinguishes atomic rejection")],
            "payload": {"test_id": "T1"},
            "pass_sha256": "",
        },
    ]
    synthesis = {
        "contract_id": analysis_v5.SYNTHESIS_RECEIPT_CONTRACT_ID,
        "synthesis_id": "synthesis-001",
        "decision_status": "SELECT_WITH_CONDITIONS",
        "selected_option_ids": ["O1"],
        "rationale_claim_ids": ["P_RATIONALE", "S_CONTROL"],
        "residual_risk_claim_ids": ["D_ACTION_RISK"],
        "decisive_test_ids": ["T1"],
        "action_permission": "DENY",
        "pass_digests": {},
        "synthesis_sha256": "",
    }
    bundle = {
        "contract_id": analysis_v5.ANALYSIS_BUNDLE_CONTRACT_ID,
        "frame": frame,
        "passes": passes,
        "conflict_register": {"conflicts": []},
        "provenance_registry": {
            "records": [{
                "reference": "artifact:external-review-001",
                "purpose": "INDEPENDENT_REVIEW",
                "verification": "VERIFIED",
            }]
        },
        "synthesis": synthesis,
        "bundle_sha256": "",
    }
    return reseal_analysis_bundle_v5(bundle)


def mutated_bundle_v5(
    bundle: Mapping[str, Any],
    mutation: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    result = deepcopy(dict(bundle))
    mutation(result)
    return reseal_analysis_bundle_v5(result)


__all__ = [
    "build_valid_analysis_bundle_v5",
    "mutated_bundle_v5",
    "reseal_analysis_bundle_v5",
]
