"""Risk-adaptive TRIAXIS assurance-plan router.

The router prevents every request from paying for a decorative full council.
It selects the minimum assurance plan required by risk, ambiguity,
irreversibility, external side effects and measured role usefulness.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .integrity import seal_mapping

ASSURANCE_PLAN_CONTRACT_ID = "TRIAXIS_ASSURANCE_PLAN_v1"
RISK_CLASSES = ("R0", "R1", "R2", "R3", "R4")
BUDGET_TIERS = frozenset({"LOW", "STANDARD", "HIGH"})


def select_assurance_plan(request: Mapping[str, Any]) -> dict[str, Any]:
    risk = request.get("risk_class")
    if risk not in RISK_CLASSES:
        raise ValueError("risk_class must be R0-R4")
    ambiguity = request.get("ambiguity")
    if ambiguity not in {"LOW", "MEDIUM", "HIGH"}:
        raise ValueError("ambiguity must be LOW/MEDIUM/HIGH")
    budget = request.get("budget_tier", "STANDARD")
    if budget not in BUDGET_TIERS:
        raise ValueError("budget_tier must be LOW/STANDARD/HIGH")
    external_side_effect = request.get("external_side_effect") is True
    irreversible = request.get("irreversible") is True
    over_refusal_sensitive = request.get("over_refusal_sensitive") is True
    factual_load_bearing = request.get("factual_load_bearing") is True
    role_evidence = request.get("role_evidence", {})
    if not isinstance(role_evidence, Mapping):
        role_evidence = {}

    risk_index = RISK_CLASSES.index(risk)
    passes = ["PRIMARY"]
    deterministic_checks = ["SCHEMA", "POLICY", "PAYLOAD_BINDING", "STATE_FRESHNESS"]
    external_verifiers: list[str] = []
    independent_review = False
    human_approval = False
    input_modes: dict[str, str] = {"PRIMARY": "FULL_CONTEXT"}

    # Self-audit is useful for low-cost structural cleanup, but is not counted as
    # independent review.
    if risk_index >= 1 or ambiguity != "LOW":
        passes.append("SELF_AUDIT")
        input_modes["SELF_AUDIT"] = "BLIND_ARTIFACT" if ambiguity == "HIGH" else "FULL_CONTEXT"

    # DEVIL is activated only where adversarial defect discovery is material,
    # and can be disabled if empirical precision is below its configured floor.
    devil_enabled = role_evidence.get("DEVIL", "UNMEASURED") != "DISABLED_LOW_VALUE"
    if devil_enabled and (risk_index >= 2 or ambiguity == "HIGH"):
        passes.append("DEVIL")
        input_modes["DEVIL"] = "BLIND_ARTIFACT"

    # ANGEL is not a default safety authority. It is included only when false
    # denial/opportunity cost is part of the objective and the role has not been
    # empirically disabled.
    angel_enabled = role_evidence.get("ANGEL", "UNMEASURED") != "DISABLED_LOW_VALUE"
    if angel_enabled and over_refusal_sensitive and risk_index >= 1:
        passes.append("ANGEL")
        input_modes["ANGEL"] = "BLIND_ARTIFACT"

    if factual_load_bearing or risk_index >= 2:
        passes.append("FALSIFIER")
        input_modes["FALSIFIER"] = "INDEPENDENT_RETRIEVAL"
        external_verifiers.append("EXECUTABLE_OR_AUTHORITATIVE_VERIFIER")

    if risk_index >= 3 or irreversible:
        independent_review = True
        passes.append("INDEPENDENT_REVIEW")
        input_modes["INDEPENDENT_REVIEW"] = "INDEPENDENT_RETRIEVAL"
        deterministic_checks.extend(["APPROVAL_THRESHOLD", "REVERSIBILITY", "NONCE_SINGLE_USE"])

    if risk == "R4" or irreversible:
        human_approval = True
        deterministic_checks.extend(["HUMAN_APPROVAL", "RECOVERY_OR_COMPENSATION_PLAN"])

    if external_side_effect:
        deterministic_checks.extend(["COMPLETE_MEDIATION", "EXECUTION_LEDGER", "POSTCONDITION"])

    if budget == "LOW" and risk_index <= 1:
        # Low budget may remove optional LLM passes, never deterministic gates.
        passes = [name for name in passes if name not in {"SELF_AUDIT", "ANGEL"}]
        input_modes = {name: mode for name, mode in input_modes.items() if name in passes}

    control_profile = "A0" if risk_index == 0 else "A1" if risk_index == 1 else "A2" if risk_index == 2 else "A3"
    plan = {
        "contract_id": ASSURANCE_PLAN_CONTRACT_ID,
        "risk_class": risk,
        "control_profile": control_profile,
        "passes": passes,
        "input_modes": input_modes,
        "external_verifiers": sorted(set(external_verifiers)),
        "independent_review_required": independent_review,
        "human_approval_required": human_approval,
        "deterministic_checks": sorted(set(deterministic_checks)),
        "synthesizer_can_authorize": False,
        "write_credentials_in_reasoning_plane": False,
        "plan_sha256": "",
    }
    return seal_mapping(plan, "plan_sha256")


__all__ = ["ASSURANCE_PLAN_CONTRACT_ID", "select_assurance_plan"]
