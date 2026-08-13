"""
TRIAXIS R12 deterministic reference runtime.

Semantic axes are separated:
1) OperationalState - what may happen next.
2) EventOutcome - what physically happened.
3) FailureCause - why a blocked/failed/partial event did not complete.
4) ScientificVerdict - PASS/FAIL/QUARANTINED/UNKNOWN/NOT_APPLICABLE.
5) Model denominator eligibility.

Research/reference implementation only. No external side effects.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, Sequence


class OperationalState(str, Enum):
    STOP_COMMITTED="STOP_COMMITTED"
    REOPEN_REQUIRED="REOPEN_REQUIRED"
    BIND_REQUIRED="BIND_REQUIRED"
    REQUEST_INPUT="REQUEST_INPUT"
    REQUEST_AUTHORITY="REQUEST_AUTHORITY"
    HOLD_USER_AUTHORITY_DENIED="HOLD_USER_AUTHORITY_DENIED"
    HOLD_PLATFORM_POLICY="HOLD_PLATFORM_POLICY"
    HOLD_EXTERNAL_ACCESS="HOLD_EXTERNAL_ACCESS"
    HOLD_INFRASTRUCTURE="HOLD_INFRASTRUCTURE"
    COMMIT_DIRECT="COMMIT_DIRECT"
    HOLD_NO_CAPABILITY="HOLD_NO_CAPABILITY"
    HOLD_INVALID_INSTRUMENT="HOLD_INVALID_INSTRUMENT"
    EXECUTE_EXTERNAL="EXECUTE_EXTERNAL"
    HOLD_INCOMPLETE="HOLD_INCOMPLETE"


class EventOutcome(str, Enum):
    NOT_ATTEMPTED="NOT_ATTEMPTED"
    BLOCKED_PRE_EXECUTION="BLOCKED_PRE_EXECUTION"
    EXECUTED_SUCCESS="EXECUTED_SUCCESS"
    EXECUTED_FAILURE="EXECUTED_FAILURE"
    PARTIAL="PARTIAL"


class FailureCause(str, Enum):
    NONE="NONE"
    INFRASTRUCTURE_BLOCKED="INFRASTRUCTURE_BLOCKED"
    PLATFORM_POLICY_BLOCKED="PLATFORM_POLICY_BLOCKED"
    EXTERNAL_ACCESS_DENIED="EXTERNAL_ACCESS_DENIED"
    USER_AUTHORITY_DENIED="USER_AUTHORITY_DENIED"
    INSTRUMENT_CONTRACT_MISMATCH="INSTRUMENT_CONTRACT_MISMATCH"
    INSTRUMENT_IMPLEMENTATION_FAILURE="INSTRUMENT_IMPLEMENTATION_FAILURE"
    EVIDENCE_CHAIN_INCOMPLETE="EVIDENCE_CHAIN_INCOMPLETE"
    MODEL_OUTPUT_CONTRACT_FAILURE="MODEL_OUTPUT_CONTRACT_FAILURE"
    MODEL_TASK_FAILURE="MODEL_TASK_FAILURE"
    MODEL_TOOL_USE_FAILURE="MODEL_TOOL_USE_FAILURE"
    CAPABILITY_EXECUTION_FAILURE="CAPABILITY_EXECUTION_FAILURE"
    UNKNOWN="UNKNOWN"


class ScientificVerdict(str, Enum):
    NOT_APPLICABLE="NOT_APPLICABLE"
    PASS="PASS"
    FAIL="FAIL"
    QUARANTINED="QUARANTINED"
    UNKNOWN="UNKNOWN"


class ContractStatus(str, Enum):
    NOT_NEEDED="NOT_NEEDED"
    ADMIT="ADMIT"
    QUARANTINE="QUARANTINE"
    UNKNOWN_HOLD="UNKNOWN_HOLD"


class EvidenceClass(str, Enum):
    INDEPENDENT_MODEL_EVIDENCE="INDEPENDENT_MODEL_EVIDENCE"
    BACKEND_EXECUTION_EVIDENCE="BACKEND_EXECUTION_EVIDENCE"
    NONINDEPENDENT_MODEL_EVIDENCE="NONINDEPENDENT_MODEL_EVIDENCE"
    CONTROLLER_INTEGRITY_EVIDENCE="CONTROLLER_INTEGRITY_EVIDENCE"
    INSTRUMENT_EVIDENCE="INSTRUMENT_EVIDENCE"
    INVALID_FOR_SCIENTIFIC_POOLING="INVALID_FOR_SCIENTIFIC_POOLING"
    UNKNOWN_HOLD="UNKNOWN_HOLD"


class RecoveryDisposition(str, Enum):
    COMMIT="COMMIT"
    HOLD_NO_RETRY="HOLD_NO_RETRY"
    ACQUIRE_EVIDENCE="ACQUIRE_EVIDENCE"
    REPAIR_INSTRUMENT_OR_HOLD="REPAIR_INSTRUMENT_OR_HOLD"
    RETRY_ONCE_IF_TRANSIENT="RETRY_ONCE_IF_TRANSIENT"
    CORRECT_ONCE_IF_PROTOCOL="CORRECT_ONCE_IF_PROTOCOL"
    HOLD_UNKNOWN="HOLD_UNKNOWN"


MODEL_FAILURE_CAUSES=frozenset({
    FailureCause.MODEL_OUTPUT_CONTRACT_FAILURE,
    FailureCause.MODEL_TASK_FAILURE,
    FailureCause.MODEL_TOOL_USE_FAILURE,
})


@dataclass(frozen=True)
class OperationalContext:
    prior_committed: bool=False
    material_new_evidence: bool=False
    target_bound: bool=True
    required_inputs_present: bool=True
    consequential_action: bool=False
    authority_known: bool=True
    authority_granted: bool=True
    platform_allows: bool=True
    external_access_available: bool=True
    infrastructure_available: bool=True
    internally_sufficient: bool=False
    real_deficit: bool=False
    capability_available: bool=True
    instrument_valid: bool=True


def decide_operational_state(c:OperationalContext)->OperationalState:
    if c.prior_committed:
        return OperationalState.REOPEN_REQUIRED if c.material_new_evidence else OperationalState.STOP_COMMITTED
    if not c.target_bound:
        return OperationalState.BIND_REQUIRED
    if not c.required_inputs_present:
        return OperationalState.REQUEST_INPUT
    if c.consequential_action and not c.authority_known:
        return OperationalState.REQUEST_AUTHORITY
    if c.consequential_action and c.authority_known and not c.authority_granted:
        return OperationalState.HOLD_USER_AUTHORITY_DENIED
    if not c.platform_allows:
        return OperationalState.HOLD_PLATFORM_POLICY
    if not c.external_access_available:
        return OperationalState.HOLD_EXTERNAL_ACCESS
    if not c.infrastructure_available:
        return OperationalState.HOLD_INFRASTRUCTURE
    if c.internally_sufficient and not c.real_deficit:
        return OperationalState.COMMIT_DIRECT
    if c.real_deficit and not c.capability_available:
        return OperationalState.HOLD_NO_CAPABILITY
    if c.real_deficit and c.capability_available and not c.instrument_valid:
        return OperationalState.HOLD_INVALID_INSTRUMENT
    if c.real_deficit and c.capability_available and c.instrument_valid:
        return OperationalState.EXECUTE_EXTERNAL
    return OperationalState.HOLD_INCOMPLETE


@dataclass(frozen=True)
class EventFacts:
    action_attempted: bool=True
    action_executed: bool=True
    action_completed: bool=True
    consequential_action: bool=False
    user_authority: bool=True
    platform_policy_blocked: bool=False
    external_access_denied: bool=False
    infrastructure_blocked: bool=False
    scientific_candidate_executed: bool=False
    instrument_required: bool=False
    instrument_applicable: bool=True
    instrument_functioning: bool=True
    evidence_complete: bool=True
    output_contract_satisfied: bool=True
    tool_needed: bool=False
    tool_invocation_valid: bool=True
    tool_runtime_success: bool=True
    score_available: bool=False
    score_pass: bool=False


@dataclass(frozen=True)
class EventAdjudication:
    outcome: EventOutcome
    failure_cause: FailureCause
    scientific_verdict: ScientificVerdict
    model_denominator_eligible: bool


def adjudicate_event(f:EventFacts)->EventAdjudication:
    if f.consequential_action and not f.user_authority:
        return EventAdjudication(
            EventOutcome.BLOCKED_PRE_EXECUTION,
            FailureCause.USER_AUTHORITY_DENIED,
            ScientificVerdict.NOT_APPLICABLE,
            False,
        )
    if f.platform_policy_blocked:
        return EventAdjudication(
            EventOutcome.BLOCKED_PRE_EXECUTION,
            FailureCause.PLATFORM_POLICY_BLOCKED,
            ScientificVerdict.NOT_APPLICABLE,
            False,
        )
    if f.external_access_denied:
        return EventAdjudication(
            EventOutcome.BLOCKED_PRE_EXECUTION,
            FailureCause.EXTERNAL_ACCESS_DENIED,
            ScientificVerdict.NOT_APPLICABLE,
            False,
        )
    if f.infrastructure_blocked:
        return EventAdjudication(
            EventOutcome.BLOCKED_PRE_EXECUTION,
            FailureCause.INFRASTRUCTURE_BLOCKED,
            ScientificVerdict.NOT_APPLICABLE,
            False,
        )
    if not f.action_attempted:
        return EventAdjudication(
            EventOutcome.NOT_ATTEMPTED,
            FailureCause.NONE,
            ScientificVerdict.NOT_APPLICABLE,
            False,
        )

    if f.instrument_required and not f.instrument_applicable:
        return EventAdjudication(
            EventOutcome.PARTIAL,
            FailureCause.INSTRUMENT_CONTRACT_MISMATCH,
            ScientificVerdict.QUARANTINED,
            False,
        )
    if f.instrument_required and not f.instrument_functioning:
        return EventAdjudication(
            EventOutcome.EXECUTED_FAILURE,
            FailureCause.INSTRUMENT_IMPLEMENTATION_FAILURE,
            ScientificVerdict.UNKNOWN,
            False,
        )
    if not f.evidence_complete:
        return EventAdjudication(
            EventOutcome.PARTIAL,
            FailureCause.EVIDENCE_CHAIN_INCOMPLETE,
            ScientificVerdict.UNKNOWN if f.scientific_candidate_executed else ScientificVerdict.NOT_APPLICABLE,
            False,
        )

    if f.tool_needed and not f.tool_invocation_valid:
        if f.scientific_candidate_executed:
            return EventAdjudication(
                EventOutcome.EXECUTED_FAILURE,
                FailureCause.MODEL_TOOL_USE_FAILURE,
                ScientificVerdict.FAIL,
                True,
            )
        return EventAdjudication(
            EventOutcome.EXECUTED_FAILURE,
            FailureCause.UNKNOWN,
            ScientificVerdict.NOT_APPLICABLE,
            False,
        )
    if f.tool_needed and not f.tool_runtime_success:
        return EventAdjudication(
            EventOutcome.EXECUTED_FAILURE,
            FailureCause.CAPABILITY_EXECUTION_FAILURE,
            ScientificVerdict.UNKNOWN if f.scientific_candidate_executed else ScientificVerdict.NOT_APPLICABLE,
            False,
        )

    if f.scientific_candidate_executed:
        if not f.output_contract_satisfied:
            return EventAdjudication(
                EventOutcome.EXECUTED_FAILURE,
                FailureCause.MODEL_OUTPUT_CONTRACT_FAILURE,
                ScientificVerdict.FAIL,
                True,
            )
        if f.score_available:
            if f.score_pass:
                return EventAdjudication(
                    EventOutcome.EXECUTED_SUCCESS,
                    FailureCause.NONE,
                    ScientificVerdict.PASS,
                    True,
                )
            return EventAdjudication(
                EventOutcome.EXECUTED_FAILURE,
                FailureCause.MODEL_TASK_FAILURE,
                ScientificVerdict.FAIL,
                True,
            )
        if f.action_completed:
            return EventAdjudication(
                EventOutcome.EXECUTED_SUCCESS,
                FailureCause.NONE,
                ScientificVerdict.UNKNOWN,
                False,
            )
        return EventAdjudication(
            EventOutcome.PARTIAL,
            FailureCause.EVIDENCE_CHAIN_INCOMPLETE,
            ScientificVerdict.UNKNOWN,
            False,
        )

    if f.action_executed and f.action_completed:
        return EventAdjudication(
            EventOutcome.EXECUTED_SUCCESS,
            FailureCause.NONE,
            ScientificVerdict.NOT_APPLICABLE,
            False,
        )
    if f.action_executed and not f.action_completed:
        return EventAdjudication(
            EventOutcome.PARTIAL,
            FailureCause.EVIDENCE_CHAIN_INCOMPLETE,
            ScientificVerdict.NOT_APPLICABLE,
            False,
        )
    return EventAdjudication(
        EventOutcome.NOT_ATTEMPTED,
        FailureCause.NONE,
        ScientificVerdict.NOT_APPLICABLE,
        False,
    )


@dataclass(frozen=True)
class ContractContext:
    required: bool=True
    authoritative_contract_known: bool=True
    candidate_contract_known: bool=True
    same_canonical_representation: bool=True
    equivalence_compatible: bool=True


def evaluate_contract(c:ContractContext)->ContractStatus:
    if not c.required:
        return ContractStatus.NOT_NEEDED
    if not c.authoritative_contract_known or not c.candidate_contract_known:
        return ContractStatus.UNKNOWN_HOLD
    if not c.same_canonical_representation or not c.equivalence_compatible:
        return ContractStatus.QUARANTINE
    return ContractStatus.ADMIT


@dataclass(frozen=True)
class ProviderContext:
    scientific_candidate_executed: bool=True
    scientific_model_is_backend_model: bool=True
    backend_only_runs_pinned_external_model: bool=False
    controller_frozen_before_output: bool=True
    task_frozen_before_output: bool=True
    oracle_seen_before_freeze: bool=False
    protocol_changed_after_output: bool=False
    same_adaptive_designer_stream: bool=False
    valid_instrument: bool=True


def classify_evidence_independence(p:ProviderContext)->EvidenceClass:
    if not p.scientific_candidate_executed:
        return EvidenceClass.UNKNOWN_HOLD
    if not p.valid_instrument:
        return EvidenceClass.INVALID_FOR_SCIENTIFIC_POOLING
    if p.oracle_seen_before_freeze or p.protocol_changed_after_output:
        return EvidenceClass.INVALID_FOR_SCIENTIFIC_POOLING
    if p.backend_only_runs_pinned_external_model:
        return EvidenceClass.BACKEND_EXECUTION_EVIDENCE
    if p.same_adaptive_designer_stream:
        return EvidenceClass.NONINDEPENDENT_MODEL_EVIDENCE
    if p.scientific_model_is_backend_model and p.controller_frozen_before_output and p.task_frozen_before_output:
        return EvidenceClass.INDEPENDENT_MODEL_EVIDENCE
    return EvidenceClass.UNKNOWN_HOLD


def recovery_disposition(
    a:EventAdjudication,
    *,
    transient:bool=False,
    correction_allowed_by_protocol:bool=False,
)->RecoveryDisposition:
    if a.outcome is EventOutcome.EXECUTED_SUCCESS:
        return RecoveryDisposition.COMMIT
    if a.failure_cause in {
        FailureCause.PLATFORM_POLICY_BLOCKED,
        FailureCause.EXTERNAL_ACCESS_DENIED,
        FailureCause.USER_AUTHORITY_DENIED,
        FailureCause.INSTRUMENT_CONTRACT_MISMATCH,
    }:
        return RecoveryDisposition.HOLD_NO_RETRY
    if a.failure_cause is FailureCause.INFRASTRUCTURE_BLOCKED:
        return RecoveryDisposition.RETRY_ONCE_IF_TRANSIENT if transient else RecoveryDisposition.HOLD_NO_RETRY
    if a.failure_cause is FailureCause.INSTRUMENT_IMPLEMENTATION_FAILURE:
        return RecoveryDisposition.REPAIR_INSTRUMENT_OR_HOLD
    if a.failure_cause is FailureCause.EVIDENCE_CHAIN_INCOMPLETE:
        return RecoveryDisposition.ACQUIRE_EVIDENCE
    if a.failure_cause in MODEL_FAILURE_CAUSES:
        return RecoveryDisposition.CORRECT_ONCE_IF_PROTOCOL if correction_allowed_by_protocol else RecoveryDisposition.HOLD_NO_RETRY
    if a.failure_cause is FailureCause.CAPABILITY_EXECUTION_FAILURE:
        return RecoveryDisposition.RETRY_ONCE_IF_TRANSIENT if transient else RecoveryDisposition.HOLD_NO_RETRY
    return RecoveryDisposition.HOLD_UNKNOWN


@dataclass(frozen=True)
class Receipt:
    target:str
    controller:str
    scientific_model:Optional[str]
    execution_backend:Optional[str]
    operational_state:OperationalState
    event_outcome:EventOutcome
    failure_cause:FailureCause
    scientific_verdict:ScientificVerdict
    contract_status:ContractStatus
    scientific_candidate_executed:bool
    instrument_applicable:bool
    instrument_functioning:bool
    model_denominator_eligible:bool
    corrections:int=0
    retries:int=0
    countermodels:int=0
    side_effect:str="NONE"
    reopen_on:Optional[str]=None


def validate_receipt(r:Receipt)->Sequence[str]:
    errors:list[str]=[]

    if r.corrections not in (0,1):
        errors.append("CORRECTION_BUDGET_EXCEEDED")
    if r.retries not in (0,1):
        errors.append("RETRY_BUDGET_EXCEEDED")
    if r.countermodels not in (0,1):
        errors.append("COUNTERMODEL_BUDGET_EXCEEDED")

    if r.event_outcome is EventOutcome.BLOCKED_PRE_EXECUTION:
        if r.scientific_verdict is not ScientificVerdict.NOT_APPLICABLE:
            errors.append("BLOCKED_HAS_SCIENTIFIC_VERDICT")
        if r.model_denominator_eligible:
            errors.append("BLOCKED_IN_MODEL_DENOMINATOR")

    if r.scientific_verdict is ScientificVerdict.PASS:
        if not r.scientific_candidate_executed:
            errors.append("PASS_WITHOUT_CANDIDATE")
        if r.failure_cause is not FailureCause.NONE:
            errors.append("PASS_WITH_FAILURE_CAUSE")
        if r.contract_status is not ContractStatus.ADMIT:
            errors.append("PASS_WITHOUT_ADMITTED_CONTRACT")
        if not r.instrument_applicable or not r.instrument_functioning:
            errors.append("PASS_WITH_INVALID_INSTRUMENT")
        if not r.model_denominator_eligible:
            errors.append("PASS_NOT_IN_MODEL_DENOMINATOR")

    if r.scientific_verdict is ScientificVerdict.FAIL:
        if r.failure_cause not in MODEL_FAILURE_CAUSES:
            errors.append("SCIENTIFIC_FAIL_WITH_NONMODEL_CAUSE")
        if not r.scientific_candidate_executed:
            errors.append("FAIL_WITHOUT_CANDIDATE")
        if r.contract_status is not ContractStatus.ADMIT:
            errors.append("FAIL_WITHOUT_ADMITTED_CONTRACT")
        if not r.instrument_applicable or not r.instrument_functioning:
            errors.append("FAIL_WITH_INVALID_INSTRUMENT")
        if not r.model_denominator_eligible:
            errors.append("FAIL_NOT_IN_MODEL_DENOMINATOR")

    if r.scientific_verdict is ScientificVerdict.QUARANTINED:
        if r.failure_cause is not FailureCause.INSTRUMENT_CONTRACT_MISMATCH:
            errors.append("QUARANTINE_WRONG_CAUSE")
        if r.contract_status is not ContractStatus.QUARANTINE:
            errors.append("QUARANTINE_WRONG_CONTRACT_STATUS")
        if r.model_denominator_eligible:
            errors.append("QUARANTINE_IN_MODEL_DENOMINATOR")

    if not r.scientific_candidate_executed and r.model_denominator_eligible:
        errors.append("NONMODEL_EVENT_IN_MODEL_DENOMINATOR")

    if r.event_outcome is EventOutcome.EXECUTED_SUCCESS and r.failure_cause is not FailureCause.NONE:
        errors.append("SUCCESS_WITH_FAILURE_CAUSE")

    return tuple(errors)


def receipt_to_dict(r:Receipt)->dict:
    d=asdict(r)
    for k,v in tuple(d.items()):
        if isinstance(v,Enum):
            d[k]=v.value
    return d


__all__=[
    "OperationalState","EventOutcome","FailureCause","ScientificVerdict",
    "ContractStatus","EvidenceClass","RecoveryDisposition",
    "OperationalContext","EventFacts","EventAdjudication","ContractContext",
    "ProviderContext","Receipt","decide_operational_state","adjudicate_event",
    "evaluate_contract","classify_evidence_independence","recovery_disposition",
    "validate_receipt","receipt_to_dict",
]
