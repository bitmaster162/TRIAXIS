#!/usr/bin/env python3
from __future__ import annotations
import json,tempfile
from contextlib import ExitStack
from pathlib import Path
from tests.test_v3_17_external_gossip_head_quorum import GossipHeadQuorumFixture
from triaxis.policy_head_authority import PolicyHeadAuthorityError

def obs(fn):
    try:fn();return 'PASS'
    except PolicyHeadAuthorityError as e:return e.code
def run_trigger():
    fx=GossipHeadQuorumFixture();rows=[]
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
        root=Path(tmp);_,high,cp1,cp2=fx.checkpoints(stack,root);services=[fx.service(stack,root,i) for i in range(3)]
        services[0].install(cp1,12);services[1].install(cp1,12);services[1].install(cp2,13);services[2].install(cp1,12);services[2].install(cp2,13)
        rows.append({'case_id':'ONE_STALE_TWO_CURRENT','expected':'PASS','observed':obs(lambda:fx.verify(stack,root,high,cp2,services))})
        root2=root/'split';root2.mkdir();_,high2,cp1b,cp2b=fx.checkpoints(stack,root2);a=fx.service(stack,root2,0);b=fx.service(stack,root2,1);a.install(cp1b,12);b.install(cp1b,12);b.install(cp2b,13)
        rows.append({'case_id':'SPLIT_WITHOUT_THRESHOLD','expected':'gossip_head_authority_quorum_not_met','observed':obs(lambda:fx.verify(stack,root2,high2,cp2b,[a,b]))})
    for r in rows:r['status']='PASS' if r['expected']==r['observed'] else 'FAIL'
    return {'contract_id':'TRIAXIS_EXTERNAL_GOSSIP_HEAD_QUORUM_TRIGGER_RESULT_v1','target':'TRIAXIS-v3.17-RC1-EXTERNAL-GOSSIP-HEAD-QUORUM','status':'PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL','case_count':len(rows),'pass_count':sum(r['status']=='PASS' for r in rows),'rows':rows}
if __name__=='__main__':print(json.dumps(run_trigger(),sort_keys=True,indent=2))
