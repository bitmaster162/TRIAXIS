"""
TRIAXIS R13 unified deterministic reference runtime.

Unifies:
- operational gating;
- R12 event semantics;
- evaluator contract validity;
- provider/model/backend separation;
- R13 two-phase consequential side-effect commit.

Reference/research implementation only. No network or remote side effects.
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
    SUBMISSION_REJECTED="SUBMISSION_REJECTED"
    RESULT_STATE_UNVERIFIED="RESULT_STATE_UNVERIFIED"
    RESULT_STATE_MISMATCH="RESULT_STATE_MISMATCH"
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
    INVALID_FOR_SCIENTIFIC_POOLING="INVALID_FOR_SCIENTIFIC_POOLING"
    UNKNOWN_HOLD="UNKNOWN_HOLD"


class SubmissionOutcome(str, Enum):
    NOT_APPLICABLE="NOT_APPLICABLE"
    NOT_SUBMITTED="NOT_SUBMITTED"
    REJECTED="REJECTED"
    ACCEPTED="ACCEPTED"


class VerificationOutcome(str, Enum):
    NOT_APPLICABLE="NOT_APPLICABLE"
    NOT_PERFORMED="NOT_PERFORMED"
    MATCH="MATCH"
    MISMATCH="MISMATCH"
    UNAVAILABLE="UNAVAILABLE"


class CommitState(str, Enum):
    NOT_APPLICABLE="NOT_APPLICABLE"
    NOT_COMMITTED="NOT_COMMITTED"
    COMMITTED="COMMITTED"


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
class SideEffectFacts:
    consequential: bool=False
    submission_outcome: SubmissionOutcome=SubmissionOutcome.NOT_APPLICABLE
    verification_outcome: VerificationOutcome=VerificationOutcome.NOT_APPLICABLE
    expected_fingerprint: Optional[str]=None
    observed_fingerprint: Optional[str]=None


@dataclass(frozen=True)
class Adjudication:
    event_outcome: EventOutcome
    failure_cause: FailureCause
    scientific_verdict: ScientificVerdict
    model_denominator_eligible: bool
    commit_state: CommitState


def _side_effect_commit(f:SideEffectFacts)->tuple[CommitState,FailureCause]:
    if not f.consequential:
        return CommitState.NOT_APPLICABLE, FailureCause.NONE
    if f.submission_outcome is SubmissionOutcome.NOT_SUBMITTED:
        return CommitState.NOT_COMMITTED, FailureCause.RESULT_STATE_UNVERIFIED
    if f.submission_outcome is SubmissionOutcome.REJECTED:
        return CommitState.NOT_COMMITTED, FailureCause.SUBMISSION_REJECTED
    if f.submission_outcome is not SubmissionOutcome.ACCEPTED:
        return CommitState.NOT_COMMITTED, FailureCause.RESULT_STATE_UNVERIFIED
    if f.verification_outcome in {VerificationOutcome.NOT_PERFORMED,VerificationOutcome.UNAVAILABLE,VerificationOutcome.NOT_APPLICABLE}:
        return CommitState.NOT_COMMITTED, FailureCause.RESULT_STATE_UNVERIFIED
    if f.verification_outcome is VerificationOutcome.MISMATCH:
        return CommitState.NOT_COMMITTED, FailureCause.RESULT_STATE_MISMATCH
    if f.verification_outcome is VerificationOutcome.MATCH:
        if (
            f.expected_fingerprint is not None
            and f.observed_fingerprint is not None
            and f.expected_fingerprint != f.observed_fingerprint
        ):
            return CommitState.NOT_COMMITTED, FailureCause.RESULT_STATE_MISMATCH
        return CommitState.COMMITTED, FailureCause.NONE
    return CommitState.NOT_COMMITTED, FailureCause.RESULT_STATE_UNVERIFIED


def adjudicate(e:EventFacts, s:SideEffectFacts=SideEffectFacts())->Adjudication:
    # Pre-execution blockers.
    if e.consequential_action and not e.user_authority:
        return Adjudication(EventOutcome.BLOCKED_PRE_EXECUTION,FailureCause.USER_AUTHORITY_DENIED,ScientificVerdict.NOT_APPLICABLE,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)
    if e.platform_policy_blocked:
        return Adjudication(EventOutcome.BLOCKED_PRE_EXECUTION,FailureCause.PLATFORM_POLICY_BLOCKED,ScientificVerdict.NOT_APPLICABLE,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)
    if e.external_access_denied:
        return Adjudication(EventOutcome.BLOCKED_PRE_EXECUTION,FailureCause.EXTERNAL_ACCESS_DENIED,ScientificVerdict.NOT_APPLICABLE,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)
    if e.infrastructure_blocked:
        return Adjudication(EventOutcome.BLOCKED_PRE_EXECUTION,FailureCause.INFRASTRUCTURE_BLOCKED,ScientificVerdict.NOT_APPLICABLE,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)
    if not e.action_attempted:
        return Adjudication(EventOutcome.NOT_ATTEMPTED,FailureCause.NONE,ScientificVerdict.NOT_APPLICABLE,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)

    # Instrument semantics before scientific verdict.
    if e.instrument_required and not e.instrument_applicable:
        return Adjudication(EventOutcome.PARTIAL,FailureCause.INSTRUMENT_CONTRACT_MISMATCH,ScientificVerdict.QUARANTINED,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)
    if e.instrument_required and not e.instrument_functioning:
        return Adjudication(EventOutcome.EXECUTED_FAILURE,FailureCause.INSTRUMENT_IMPLEMENTATION_FAILURE,ScientificVerdict.UNKNOWN,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)
    if not e.evidence_complete:
        return Adjudication(EventOutcome.PARTIAL,FailureCause.EVIDENCE_CHAIN_INCOMPLETE,ScientificVerdict.UNKNOWN if e.scientific_candidate_executed else ScientificVerdict.NOT_APPLICABLE,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)

    # Capability failures.
    if e.tool_needed and not e.tool_invocation_valid:
        if e.scientific_candidate_executed:
            return Adjudication(EventOutcome.EXECUTED_FAILURE,FailureCause.MODEL_TOOL_USE_FAILURE,ScientificVerdict.FAIL,True,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)
        return Adjudication(EventOutcome.EXECUTED_FAILURE,FailureCause.UNKNOWN,ScientificVerdict.NOT_APPLICABLE,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)
    if e.tool_needed and not e.tool_runtime_success:
        return Adjudication(EventOutcome.EXECUTED_FAILURE,FailureCause.CAPABILITY_EXECUTION_FAILURE,ScientificVerdict.UNKNOWN if e.scientific_candidate_executed else ScientificVerdict.NOT_APPLICABLE,False,CommitState.NOT_COMMITTED if s.consequential else CommitState.NOT_APPLICABLE)

    # Scientific result, if any.
    sci_verdict=ScientificVerdict.NOT_APPLICABLE
    sci_cause=FailureCause.NONE
    denom=False
    if e.scientific_candidate_executed:
        if not e.output_contract_satisfied:
            sci_verdict=ScientificVerdict.FAIL
            sci_cause=FailureCause.MODEL_OUTPUT_CONTRACT_FAILURE
            denom=True
        elif e.score_available:
            if e.score_pass:
                sci_verdict=ScientificVerdict.PASS
                sci_cause=FailureCause.NONE
                denom=True
            else:
                sci_verdict=ScientificVerdict.FAIL
                sci_cause=FailureCause.MODEL_TASK_FAILURE
                denom=True
        else:
            sci_verdict=ScientificVerdict.UNKNOWN
            sci_cause=FailureCause.NONE

    # Consequential side effect gates terminal event success.
    commit_state, side_cause = _side_effect_commit(s)
    if s.consequential:
        if side_cause is FailureCause.SUBMISSION_REJECTED:
            return Adjudication(EventOutcome.EXECUTED_FAILURE,side_cause,sci_verdict,denom,commit_state)
        if side_cause is FailureCause.RESULT_STATE_MISMATCH:
            return Adjudication(EventOutcome.EXECUTED_FAILURE,side_cause,sci_verdict,denom,commit_state)
        if side_cause is FailureCause.RESULT_STATE_UNVERIFIED:
            return Adjudication(EventOutcome.PARTIAL,side_cause,sci_verdict,denom,commit_state)
        # Side effect is verified committed. Preserve model failure if scientific task itself failed.
        if sci_cause in MODEL_FAILURE_CAUSES:
            return Adjudication(EventOutcome.EXECUTED_FAILURE,sci_cause,sci_verdict,denom,commit_state)
        return Adjudication(EventOutcome.EXECUTED_SUCCESS,FailureCause.NONE,sci_verdict,denom,commit_state)

    # Non-consequential event.
    if sci_cause in MODEL_FAILURE_CAUSES:
        return Adjudication(EventOutcome.EXECUTED_FAILURE,sci_cause,sci_verdict,denom,CommitState.NOT_APPLICABLE)
    if e.action_executed and e.action_completed:
        return Adjudication(EventOutcome.EXECUTED_SUCCESS,FailureCause.NONE,sci_verdict,denom,CommitState.NOT_APPLICABLE)
    if e.action_executed:
        return Adjudication(EventOutcome.PARTIAL,FailureCause.EVIDENCE_CHAIN_INCOMPLETE,sci_verdict,False,CommitState.NOT_APPLICABLE)
    return Adjudication(EventOutcome.NOT_ATTEMPTED,FailureCause.NONE,sci_verdict,False,CommitState.NOT_APPLICABLE)


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
    if not p.valid_instrument or p.oracle_seen_before_freeze or p.protocol_changed_after_output:
        return EvidenceClass.INVALID_FOR_SCIENTIFIC_POOLING
    if p.backend_only_runs_pinned_external_model:
        return EvidenceClass.BACKEND_EXECUTION_EVIDENCE
    if p.same_adaptive_designer_stream:
        return EvidenceClass.NONINDEPENDENT_MODEL_EVIDENCE
    if p.scientific_model_is_backend_model and p.controller_frozen_before_output and p.task_frozen_before_output:
        return EvidenceClass.INDEPENDENT_MODEL_EVIDENCE
    return EvidenceClass.UNKNOWN_HOLD


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
    model_denominator_eligible:bool
    contract_status:ContractStatus
    commit_state:CommitState
    submission_outcome:SubmissionOutcome
    verification_outcome:VerificationOutcome
    expected_fingerprint:Optional[str]=None
    observed_fingerprint:Optional[str]=None


def validate_receipt(r:Receipt)->Sequence[str]:
    errors=[]
    if r.event_outcome is EventOutcome.BLOCKED_PRE_EXECUTION and r.model_denominator_eligible:
        errors.append("BLOCKED_IN_MODEL_DENOMINATOR")
    if r.scientific_verdict in {ScientificVerdict.PASS,ScientificVerdict.FAIL} and r.contract_status is not ContractStatus.ADMIT:
        errors.append("SCIENTIFIC_VERDICT_WITHOUT_ADMIT")
    if r.scientific_verdict is ScientificVerdict.QUARANTINED:
        if r.failure_cause is not FailureCause.INSTRUMENT_CONTRACT_MISMATCH:
            errors.append("QUARANTINE_WRONG_CAUSE")
        if r.model_denominator_eligible:
            errors.append("QUARANTINE_IN_MODEL_DENOMINATOR")
    if r.commit_state is CommitState.COMMITTED:
        if r.submission_outcome is not SubmissionOutcome.ACCEPTED:
            errors.append("COMMIT_WITHOUT_ACCEPTED_SUBMISSION")
        if r.verification_outcome is not VerificationOutcome.MATCH:
            errors.append("COMMIT_WITHOUT_MATCH_VERIFICATION")
        if (
            r.expected_fingerprint is not None
            and r.observed_fingerprint is not None
            and r.expected_fingerprint != r.observed_fingerprint
        ):
            errors.append("COMMIT_WITH_FINGERPRINT_MISMATCH")
    if r.failure_cause in {FailureCause.RESULT_STATE_MISMATCH,FailureCause.RESULT_STATE_UNVERIFIED,FailureCause.SUBMISSION_REJECTED} and r.commit_state is CommitState.COMMITTED:
        errors.append("SIDE_EFFECT_FAILURE_COMMITTED")
    if r.event_outcome is EventOutcome.EXECUTED_SUCCESS and r.commit_state is CommitState.NOT_COMMITTED:
        errors.append("TERMINAL_SUCCESS_WITH_UNCOMMITTED_CONSEQUENTIAL_EFFECT")
    return tuple(errors)


def receipt_to_dict(r:Receipt)->dict:
    d=asdict(r)
    for k,v in tuple(d.items()):
        if isinstance(v,Enum):
            d[k]=v.value
    return d
