#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
import triaxis_runtime_r15 as r

GOVERNANCE={"MERGE_PERMISSION":"DENY","deploy_permission":"DENY","can_trade":False,"capital_permission":"DENY"}

def sha256_file(p:Path)->str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def obj(x,k):
    v=x.get(k)
    if not isinstance(v,dict): raise ValueError(f"{k} must be object")
    return v

def s(x,k):
    v=x.get(k)
    if not isinstance(v,str) or not v.strip(): raise ValueError(f"{k} must be non-empty string")
    return v

def canonicalize(x:dict,source_path:Path|None=None)->dict:
    tid=s(x,"transaction_id"); target=s(x,"target"); controller=s(x,"controller_version")
    e0=obj(x,"event"); m0=obj(x,"mutation"); q0=obj(x,"responsibility_evidence")
    e=r.E(**e0)
    m=r.M(
      consequential=m0.get("consequential",False),
      sub=r.Sub(m0.get("submission_outcome","NOT_APPLICABLE")),
      verify=r.Verify(m0.get("verification_outcome","NOT_APPLICABLE")),
      safety=r.Safety(m0.get("retry_safety","NOT_APPLICABLE")),
      budget=r.Budget(m0.get("retry_budget_state","NOT_APPLICABLE")),
      pre=m0.get("pre_fingerprint"),expected=m0.get("expected_fingerprint"),observed=m0.get("observed_fingerprint"))
    q=r.R(**q0)
    a=r.adjudicate(e,m,q)
    errors=[]

    if e.consequential!=m.consequential: errors.append("CONSEQUENTIAL_AXIS_MISMATCH")
    if a.commit is r.Commit.YES:
        if m.verify is not r.Verify.EXPECTED: errors.append("COMMIT_WITHOUT_EXPECTED_STATE_MATCH")
        if m.expected is not None and m.observed is not None and m.expected!=m.observed: errors.append("COMMIT_FINGERPRINT_MISMATCH")
    if a.action is r.Action.RETRY:
        if m.verify is not r.Verify.PRE: errors.append("RETRY_WITHOUT_PRE_STATE_MATCH")
        if m.safety not in r.SAFE: errors.append("RETRY_WITHOUT_SAFE_REPLAY")
        if m.budget is not r.Budget.UNUSED: errors.append("RETRY_WITHOUT_UNUSED_BUDGET")
    if a.denominator and a.verdict not in {r.Verdict.PASS,r.Verdict.FAIL}: errors.append("MODEL_DENOMINATOR_WITHOUT_PASS_FAIL")
    if a.verdict is r.Verdict.QUAR and a.denominator: errors.append("QUARANTINE_IN_MODEL_DENOMINATOR")

    specific={r.Responsibility.USER,r.Responsibility.CONTROLLER,r.Responsibility.PLATFORM,
              r.Responsibility.EXTERNAL_SERVICE,r.Responsibility.INFRASTRUCTURE,
              r.Responsibility.INSTRUMENT,r.Responsibility.SCIENTIFIC_MODEL}
    if a.responsibility in specific:
        justified=(
          (a.responsibility is r.Responsibility.PLATFORM and q.explicit_platform_block and a.cause is r.Cause.POLICY) or
          (a.responsibility is r.Responsibility.USER and q.explicit_user_denial and a.cause is r.Cause.USER) or
          (a.responsibility is r.Responsibility.EXTERNAL_SERVICE and q.explicit_external_access_denial and a.cause is r.Cause.ACCESS) or
          (a.responsibility is r.Responsibility.INFRASTRUCTURE and q.explicit_infrastructure_block and a.cause is r.Cause.INFRA) or
          (a.responsibility is r.Responsibility.INSTRUMENT and q.isolated_instrument_defect and a.cause in {r.Cause.INST_IMPL,r.Cause.INST_CONTRACT}) or
          (a.responsibility is r.Responsibility.SCIENTIFIC_MODEL and q.valid_instrument_model_failure and a.cause in r.MODEL_CAUSES) or
          (a.responsibility is r.Responsibility.CONTROLLER and q.isolated_controller_defect)
        )
        if not justified: errors.append("RESPONSIBILITY_WITHOUT_DISCRIMINATOR")

    reported=x.get("provider_reported_classification")
    return {
      "schema":"triaxis.r15e.canonical_transaction_receipt/v1",
      "transaction_id":tid,"target":target,"controller_version":controller,
      "source_authority":x.get("source_authority"),
      "source_file_sha256":sha256_file(source_path) if source_path else None,
      "identity":x.get("identity",{}),
      "provider_reported_classification":reported,
      "canonical":{
        "event_outcome":a.outcome.value,"failure_cause":a.cause.value,
        "scientific_verdict":a.verdict.value,"model_denominator_eligible":a.denominator,
        "commit_state":a.commit.value,"next_action":a.action.value,
        "responsibility":a.responsibility.value,"remediation":a.remediation.value,
        "submission_outcome":m.sub.value,"verification_outcome":m.verify.value,
        "retry_safety":m.safety.value,"retry_budget_state":m.budget.value,
      },
      "classification_changed_from_provider":reported is not None and reported!=a.cause.value,
      "validation":{"status":"PASS" if not errors else "FAIL","errors":errors},
      "raw_evidence":x.get("raw_evidence"),
      "notes":x.get("notes",[]),
      "governance":GOVERNANCE,
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("input",type=Path); ap.add_argument("-o","--output",type=Path); ap.add_argument("--pretty",action="store_true")
    a=ap.parse_args(); x=json.loads(a.input.read_text(encoding="utf-8")); y=canonicalize(x,a.input)
    text=json.dumps(y,ensure_ascii=False,indent=2 if a.pretty or a.output else None,sort_keys=True)+"\n"
    if a.output:a.output.write_text(text,encoding="utf-8"); print(a.output)
    else: print(text,end="")
    return 0 if y["validation"]["status"]=="PASS" else 2

if __name__=="__main__": raise SystemExit(main())
