#!/usr/bin/env python3
"""Closure trigger for TRIAXIS v3.16 external gossip head."""
from __future__ import annotations
import json, tempfile
from contextlib import ExitStack
from pathlib import Path
from tests.test_v3_16_external_gossip_head import ExternalGossipHeadFixture
from triaxis.policy_head_authority import PolicyHeadAuthorityError


def observe(fn):
    try: fn(); return "PASS"
    except PolicyHeadAuthorityError as exc: return exc.code

def run_trigger():
    fx=ExternalGossipHeadFixture(); rows=[]
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
        root=Path(tmp); low=fx.populate(stack,root/"low",2); high=fx.populate(stack,root/"high",3)
        issuer=fx.issuer(stack,root/"high",high); cp=issuer.issue(issued_at=10,valid_until=100)
        authority=fx.authority(stack,root); authority.install(cp,10)
        rows.append({"case_id":"CURRENT_EXTERNAL_HEAD","expected":"PASS","observed":observe(lambda:fx.verify(stack,root,high,cp,authority)),"positive_control":True})
        rows.append({"case_id":"WHOLE_LOCAL_GOSSIP_ROLLBACK","expected":"local_gossip_state_rollback_detected","observed":observe(lambda:fx.verify(stack,root,low,cp,authority)),"positive_control":False})
        rows.append({"case_id":"EXACT_CHECKPOINT_RETRY","expected":"PASS","observed":observe(lambda:authority.install(cp,11)),"positive_control":True})
    for row in rows: row["status"]="PASS" if row["expected"]==row["observed"] else "FAIL"
    return {"contract_id":"TRIAXIS_EXTERNAL_GOSSIP_HEAD_TRIGGER_RESULT_v1","target":"TRIAXIS-v3.16-RC1-EXTERNAL-GOSSIP-HEAD","status":"PASS" if all(r["status"]=="PASS" for r in rows) else "FAIL","case_count":len(rows),"pass_count":sum(r["status"]=="PASS" for r in rows),"rows":rows}
if __name__=="__main__": print(json.dumps(run_trigger(),sort_keys=True,indent=2))
