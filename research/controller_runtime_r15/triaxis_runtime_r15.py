"""
TRIAXIS R15 integrated minimal deterministic runtime.

Pure control semantics. No network or external side effects.

R15 = frozen R14 control adjudication + evidence-gated responsibility/remediation.
Responsibility is not inferred from failure cause alone.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Optional

# ---------- Frozen R14 control axes ----------

class Op(str,Enum):
 STOP="STOP_COMMITTED"; REOPEN="REOPEN_REQUIRED"; BIND="BIND_REQUIRED"; INPUT="REQUEST_INPUT"
 AUTH="REQUEST_AUTHORITY"; USER_DENY="HOLD_USER_AUTHORITY_DENIED"; POLICY="HOLD_PLATFORM_POLICY"
 ACCESS="HOLD_EXTERNAL_ACCESS"; INFRA="HOLD_INFRASTRUCTURE"; DIRECT="COMMIT_DIRECT"
 NO_CAP="HOLD_NO_CAPABILITY"; BAD_INST="HOLD_INVALID_INSTRUMENT"; EXEC="EXECUTE_EXTERNAL"; HOLD="HOLD_INCOMPLETE"

class Outcome(str,Enum):
 NOT_ATTEMPTED="NOT_ATTEMPTED"; BLOCKED="BLOCKED_PRE_EXECUTION"; SUCCESS="EXECUTED_SUCCESS"; FAIL="EXECUTED_FAILURE"; PARTIAL="PARTIAL"

class Cause(str,Enum):
 NONE="NONE"; INFRA="INFRASTRUCTURE_BLOCKED"; POLICY="PLATFORM_POLICY_BLOCKED"; ACCESS="EXTERNAL_ACCESS_DENIED"; USER="USER_AUTHORITY_DENIED"
 INST_CONTRACT="INSTRUMENT_CONTRACT_MISMATCH"; INST_IMPL="INSTRUMENT_IMPLEMENTATION_FAILURE"; EVIDENCE="EVIDENCE_CHAIN_INCOMPLETE"
 MODEL_FORMAT="MODEL_OUTPUT_CONTRACT_FAILURE"; MODEL_TASK="MODEL_TASK_FAILURE"; MODEL_TOOL="MODEL_TOOL_USE_FAILURE"; CAP="CAPABILITY_EXECUTION_FAILURE"
 SUBMIT_REJECT="SUBMISSION_REJECTED"; UNVERIFIED="RESULT_STATE_UNVERIFIED"; MISMATCH="RESULT_STATE_MISMATCH"
 RETRY_UNSAFE="RETRY_UNSAFE"; RETRY_SPENT="RETRY_BUDGET_SPENT"; RETRY_UNAVAILABLE="RETRY_BUDGET_UNAVAILABLE"; UNKNOWN="UNKNOWN"

class Verdict(str,Enum):
 NA="NOT_APPLICABLE"; PASS="PASS"; FAIL="FAIL"; QUAR="QUARANTINED"; UNKNOWN="UNKNOWN"

class Sub(str,Enum):
 NA="NOT_APPLICABLE"; NONE="NOT_SUBMITTED"; REJECT="REJECTED"; ACCEPT="ACCEPTED"; UNKNOWN="UNKNOWN_AFTER_SUBMIT"

class Verify(str,Enum):
 NA="NOT_APPLICABLE"; NONE="NOT_PERFORMED"; EXPECTED="EXPECTED_STATE_MATCH"; PRE="PRE_STATE_MATCH"; UNEXPECTED="UNEXPECTED_STATE"; UNAVAILABLE="UNAVAILABLE"

class Safety(str,Enum):
 NA="NOT_APPLICABLE"; KEY="EXPLICIT_IDEMPOTENCY_KEY"; CAS="CONDITIONAL_COMPARE_AND_SWAP"; IDEMPOTENT="PROVEN_IDEMPOTENT_OPERATION"; NONIDEMPOTENT="NON_IDEMPOTENT"; UNKNOWN="UNKNOWN"

class Budget(str,Enum):
 NA="NOT_APPLICABLE"; UNUSED="UNUSED"; USED="USED"

class Commit(str,Enum):
 NA="NOT_APPLICABLE"; NO="NOT_COMMITTED"; YES="COMMITTED"

class Action(str,Enum):
 NONE="NONE"; COMMIT="COMMIT"; RETRY="RETRY_ONCE_SAME_GUARD"; HOLD="HOLD_NO_RETRY"; MISMATCH="HOLD_MISMATCH"; AMBIG="HOLD_AMBIGUOUS"
 EVIDENCE="ACQUIRE_EVIDENCE"; FIX_INST="REPAIR_INSTRUMENT_OR_HOLD"; CORRECT="CORRECT_ONCE_IF_PROTOCOL"

SAFE={Safety.KEY,Safety.CAS,Safety.IDEMPOTENT}
MODEL_CAUSES={Cause.MODEL_FORMAT,Cause.MODEL_TASK,Cause.MODEL_TOOL}

@dataclass(frozen=True)
class O:
 prior:bool=False; new:bool=False; bound:bool=True; inputs:bool=True; consequential:bool=False; auth_known:bool=True; auth:bool=True
 platform:bool=True; access:bool=True; infra:bool=True; sufficient:bool=False; deficit:bool=False; capability:bool=True; instrument:bool=True

def op(c:O)->Op:
 if c.prior:return Op.REOPEN if c.new else Op.STOP
 if not c.bound:return Op.BIND
 if not c.inputs:return Op.INPUT
 if c.consequential and not c.auth_known:return Op.AUTH
 if c.consequential and not c.auth:return Op.USER_DENY
 if not c.platform:return Op.POLICY
 if not c.access:return Op.ACCESS
 if not c.infra:return Op.INFRA
 if c.sufficient and not c.deficit:return Op.DIRECT
 if c.deficit and not c.capability:return Op.NO_CAP
 if c.deficit and c.capability and not c.instrument:return Op.BAD_INST
 if c.deficit and c.capability and c.instrument:return Op.EXEC
 return Op.HOLD

@dataclass(frozen=True)
class E:
 attempted:bool=True; executed:bool=True; completed:bool=True; consequential:bool=False; authority:bool=True
 policy_block:bool=False; access_denied:bool=False; infra_block:bool=False; candidate:bool=False
 instrument_required:bool=False; instrument_applicable:bool=True; instrument_functioning:bool=True; evidence:bool=True
 output_contract:bool=True; tool_needed:bool=False; tool_args:bool=True; tool_runtime:bool=True; scored:bool=False; score_pass:bool=False

@dataclass(frozen=True)
class M:
 consequential:bool=False; sub:Sub=Sub.NA; verify:Verify=Verify.NA; safety:Safety=Safety.NA; budget:Budget=Budget.NA
 pre:Optional[str]=None; expected:Optional[str]=None; observed:Optional[str]=None

@dataclass(frozen=True)
class Control:
 outcome:Outcome; cause:Cause; verdict:Verdict; denominator:bool; commit:Commit; action:Action

def mutation(m:M):
 if not m.consequential:return Commit.NA,Cause.NONE,Action.NONE
 if m.sub is Sub.NONE:return Commit.NO,Cause.UNVERIFIED,Action.HOLD
 if m.sub is Sub.REJECT:return Commit.NO,Cause.SUBMIT_REJECT,Action.HOLD
 if m.verify is Verify.EXPECTED:
  if m.expected is not None and m.observed is not None and m.expected!=m.observed:return Commit.NO,Cause.MISMATCH,Action.MISMATCH
  return Commit.YES,Cause.NONE,Action.COMMIT
 if m.verify is Verify.UNEXPECTED:return Commit.NO,Cause.MISMATCH,Action.MISMATCH
 if m.verify in {Verify.NONE,Verify.UNAVAILABLE,Verify.NA}:return Commit.NO,Cause.UNVERIFIED,Action.AMBIG
 if m.verify is Verify.PRE:
  if m.pre is not None and m.observed is not None and m.pre!=m.observed:return Commit.NO,Cause.MISMATCH,Action.MISMATCH
  if m.budget is Budget.USED:return Commit.NO,Cause.RETRY_SPENT,Action.HOLD
  if m.budget is not Budget.UNUSED:return Commit.NO,Cause.RETRY_UNAVAILABLE,Action.HOLD
  if m.safety in SAFE:return Commit.NO,Cause.NONE,Action.RETRY
  return Commit.NO,Cause.RETRY_UNSAFE,Action.HOLD
 return Commit.NO,Cause.UNVERIFIED,Action.AMBIG

def control(e:E,m:M=M())->Control:
 c=Commit.NO if m.consequential else Commit.NA
 if e.consequential and not e.authority:return Control(Outcome.BLOCKED,Cause.USER,Verdict.NA,False,c,Action.HOLD)
 if e.policy_block:return Control(Outcome.BLOCKED,Cause.POLICY,Verdict.NA,False,c,Action.HOLD)
 if e.access_denied:return Control(Outcome.BLOCKED,Cause.ACCESS,Verdict.NA,False,c,Action.HOLD)
 if e.infra_block:return Control(Outcome.BLOCKED,Cause.INFRA,Verdict.NA,False,c,Action.HOLD)
 if not e.attempted:return Control(Outcome.NOT_ATTEMPTED,Cause.NONE,Verdict.NA,False,c,Action.NONE)
 if e.instrument_required and not e.instrument_applicable:return Control(Outcome.PARTIAL,Cause.INST_CONTRACT,Verdict.QUAR,False,c,Action.HOLD)
 if e.instrument_required and not e.instrument_functioning:return Control(Outcome.FAIL,Cause.INST_IMPL,Verdict.UNKNOWN,False,c,Action.FIX_INST)
 if not e.evidence:return Control(Outcome.PARTIAL,Cause.EVIDENCE,Verdict.UNKNOWN if e.candidate else Verdict.NA,False,c,Action.EVIDENCE)
 if e.tool_needed and not e.tool_args:
  return Control(Outcome.FAIL,Cause.MODEL_TOOL,Verdict.FAIL,True,c,Action.CORRECT) if e.candidate else Control(Outcome.FAIL,Cause.UNKNOWN,Verdict.NA,False,c,Action.HOLD)
 if e.tool_needed and not e.tool_runtime:return Control(Outcome.FAIL,Cause.CAP,Verdict.UNKNOWN if e.candidate else Verdict.NA,False,c,Action.AMBIG if m.consequential else Action.HOLD)

 verdict=Verdict.NA; cause=Cause.NONE; denom=False
 if e.candidate:
  if not e.output_contract:verdict,cause,denom=Verdict.FAIL,Cause.MODEL_FORMAT,True
  elif e.scored:
   verdict,cause,denom=(Verdict.PASS,Cause.NONE,True) if e.score_pass else (Verdict.FAIL,Cause.MODEL_TASK,True)
  else:verdict=Verdict.UNKNOWN

 commit,mc,act=mutation(m)
 if m.consequential:
  if mc in {Cause.SUBMIT_REJECT,Cause.MISMATCH,Cause.RETRY_UNSAFE,Cause.RETRY_SPENT,Cause.RETRY_UNAVAILABLE}:return Control(Outcome.FAIL,mc,verdict,denom,commit,act)
  if mc is Cause.UNVERIFIED:return Control(Outcome.PARTIAL,mc,verdict,denom,commit,act)
  if act is Action.RETRY:return Control(Outcome.PARTIAL,Cause.NONE,verdict,denom,commit,act)
  if cause in MODEL_CAUSES:return Control(Outcome.FAIL,cause,verdict,denom,commit,Action.COMMIT)
  return Control(Outcome.SUCCESS,Cause.NONE,verdict,denom,commit,Action.COMMIT)

 if cause in MODEL_CAUSES:return Control(Outcome.FAIL,cause,verdict,denom,Commit.NA,Action.CORRECT)
 if e.executed and e.completed:return Control(Outcome.SUCCESS,Cause.NONE,verdict,denom,Commit.NA,Action.COMMIT)
 if e.executed:return Control(Outcome.PARTIAL,Cause.EVIDENCE,verdict,False,Commit.NA,Action.EVIDENCE)
 return Control(Outcome.NOT_ATTEMPTED,Cause.NONE,verdict,False,Commit.NA,Action.NONE)

# ---------- R15 responsibility/remediation axes ----------

class Responsibility(str,Enum):
 NONE="NONE"; USER="USER"; CONTROLLER="CONTROLLER"; PLATFORM="PLATFORM"
 EXTERNAL_SERVICE="EXTERNAL_SERVICE"; INFRASTRUCTURE="INFRASTRUCTURE"
 INSTRUMENT="INSTRUMENT"; SCIENTIFIC_MODEL="SCIENTIFIC_MODEL"; UNKNOWN="UNKNOWN"

class Remediation(str,Enum):
 NONE="NONE"; REQUEST_USER_AUTHORITY="REQUEST_USER_AUTHORITY"; HOLD_PLATFORM_NO_BYPASS="HOLD_PLATFORM_NO_BYPASS"
 FIX_EXTERNAL_ACCESS="FIX_EXTERNAL_ACCESS"; RETRY_IF_TRANSIENT="RETRY_IF_TRANSIENT"; REPAIR_INSTRUMENT="REPAIR_INSTRUMENT"
 ACQUIRE_EVIDENCE="ACQUIRE_EVIDENCE"; CORRECT_MODEL_ONCE_IF_PROTOCOL="CORRECT_MODEL_ONCE_IF_PROTOCOL"
 RECONCILE_RESULT_STATE="RECONCILE_RESULT_STATE"; REPAIR_CONTROLLER="REPAIR_CONTROLLER"; HOLD_UNKNOWN="HOLD_UNKNOWN"

@dataclass(frozen=True)
class R:
 explicit_platform_block:bool=False
 explicit_user_denial:bool=False
 explicit_external_access_denial:bool=False
 explicit_infrastructure_block:bool=False
 isolated_instrument_defect:bool=False
 valid_instrument_model_failure:bool=False
 isolated_controller_defect:bool=False
 transient:bool=False

@dataclass(frozen=True)
class Route:
 responsibility:Responsibility
 remediation:Remediation

def route(cause:Cause,r:R=R())->Route:
 if cause is Cause.NONE:return Route(Responsibility.NONE,Remediation.NONE)

 # Positive discriminators take precedence only when compatible with the observed cause.
 if r.isolated_controller_defect and cause in {
  Cause.MISMATCH,Cause.UNVERIFIED,Cause.UNKNOWN,Cause.CAP,
  Cause.RETRY_UNSAFE,Cause.RETRY_SPENT,Cause.RETRY_UNAVAILABLE
 }:
  return Route(Responsibility.CONTROLLER,Remediation.REPAIR_CONTROLLER)

 if cause is Cause.POLICY:
  return Route(Responsibility.PLATFORM,Remediation.HOLD_PLATFORM_NO_BYPASS) if r.explicit_platform_block else Route(Responsibility.UNKNOWN,Remediation.HOLD_UNKNOWN)

 if cause is Cause.USER:
  return Route(Responsibility.USER,Remediation.REQUEST_USER_AUTHORITY) if r.explicit_user_denial else Route(Responsibility.UNKNOWN,Remediation.HOLD_UNKNOWN)

 if cause is Cause.ACCESS:
  return Route(Responsibility.EXTERNAL_SERVICE,Remediation.FIX_EXTERNAL_ACCESS) if r.explicit_external_access_denial else Route(Responsibility.UNKNOWN,Remediation.HOLD_UNKNOWN)

 if cause is Cause.INFRA:
  if not r.explicit_infrastructure_block:return Route(Responsibility.UNKNOWN,Remediation.HOLD_UNKNOWN)
  return Route(Responsibility.INFRASTRUCTURE,Remediation.RETRY_IF_TRANSIENT if r.transient else Remediation.HOLD_UNKNOWN)

 if cause in {Cause.INST_IMPL,Cause.INST_CONTRACT}:
  return Route(Responsibility.INSTRUMENT,Remediation.REPAIR_INSTRUMENT) if r.isolated_instrument_defect else Route(Responsibility.UNKNOWN,Remediation.HOLD_UNKNOWN)

 if cause is Cause.EVIDENCE:
  return Route(Responsibility.UNKNOWN,Remediation.ACQUIRE_EVIDENCE)

 if cause in MODEL_CAUSES:
  return Route(Responsibility.SCIENTIFIC_MODEL,Remediation.CORRECT_MODEL_ONCE_IF_PROTOCOL) if r.valid_instrument_model_failure else Route(Responsibility.UNKNOWN,Remediation.HOLD_UNKNOWN)

 if cause in {Cause.MISMATCH,Cause.UNVERIFIED}:
  return Route(Responsibility.UNKNOWN,Remediation.RECONCILE_RESULT_STATE)

 if cause is Cause.CAP:
  return Route(Responsibility.UNKNOWN,Remediation.RETRY_IF_TRANSIENT if r.transient else Remediation.HOLD_UNKNOWN)

 return Route(Responsibility.UNKNOWN,Remediation.HOLD_UNKNOWN)

@dataclass(frozen=True)
class A:
 outcome:Outcome
 cause:Cause
 verdict:Verdict
 denominator:bool
 commit:Commit
 action:Action
 responsibility:Responsibility
 remediation:Remediation

def adjudicate(e:E,m:M=M(),r:R=R())->A:
 c=control(e,m)
 rr=route(c.cause,r)
 return A(c.outcome,c.cause,c.verdict,c.denominator,c.commit,c.action,rr.responsibility,rr.remediation)
