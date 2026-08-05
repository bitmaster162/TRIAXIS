from __future__ import annotations
import json, sys
from typing import Any, Callable
sys.path.insert(0,'/mnt/data/TRIAXIS_V340_EXACT_WORK/src')
from triaxis.action_assurance import ACTION_ENVELOPE_CONTRACT_ID, ASSURANCE_ATTESTATION_CONTRACT_ID, STATE_WITNESS_CONTRACT_ID, action_scope_sha256, assured_action_request_sha256, authorize_action, seal_contract, validate_authorization_token
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy
PROTOCOL_ID='TRIAXIS_V340_POSTCOMMIT_EFFECTIVE_EXPIRY_TRIGGER_v1'
COMMIT='1ec7eafbdfff5a25bd7256c49d90917be673a922'
TREE='00733c5cc03e08fcfacf63bd1d9a401e791f0c35'
TRUST={'assurance:1':'domain:1'}

def policy(valid_until=20):
 return seal_policy({'contract_id':POLICY_BUNDLE_CONTRACT_ID,'policy_id':'p1','subject_id':'subject:1','issuer_id':'policy:1','sequence':1,'minimum_accepted_sequence':1,'state':'ACTIVE','effective_from':1,'valid_until':valid_until,'allowed_capabilities':['WRITE'],'allowed_tools':['git'],'allowed_targets':['repo:1'],'max_risk_class':'R2','required_approval_types':[],'supersedes_policy_sha256':None,'policy_sha256':''})
def state(valid_until=20):
 return seal_contract({'contract_id':STATE_WITNESS_CONTRACT_ID,'state_id':'s1','subject_id':'subject:1','object_id':'repo:1','adapter_id':'adapter:1','version':1,'state_sha256':'a'*64,'attestation_level':'AUTHENTICATED','observed_at':5,'valid_until':valid_until,'witness_sha256':''},'witness_sha256')
def action(pol, state_until=20, att_until=20, action_until=20, nonce='n'):
 st=state(state_until)
 v={'contract_id':ACTION_ENVELOPE_CONTRACT_ID,'principal_id':'human:1','intent_id':'i1','decision_case_sha256':'b'*64,'evidence_report_sha256':'c'*64,'subject_id':'subject:1','object_id':'repo:1','capability':'WRITE','tool_id':'git','execution_target':'repo:1','payload_sha256':'d'*64,'policy_id':'p1','policy_sequence':1,'policy_sha256':pol['policy_sha256'],'state_witness':st,'risk_class':'R2','nonce':nonce,'issued_at':5,'expires_at':action_until,'approvals':[],'assured_action_request_sha256':'','scope_sha256':'','action_sha256':''}
 v['assured_action_request_sha256']=assured_action_request_sha256(v)
 v['assurance_attestation']=seal_contract({'contract_id':ASSURANCE_ATTESTATION_CONTRACT_ID,'attestation_id':'a1','issuer_id':'assurance:1','trust_domain':'domain:1','subject_id':'subject:1','decision_case_sha256':'b'*64,'evidence_report_sha256':'c'*64,'assured_action_request_sha256':v['assured_action_request_sha256'],'assurance_status':'PASS','synthesis_decision':'ACCEPT','attestation_level':'AUTHENTICATED','issued_at':5,'valid_until':att_until,'attestation_sha256':''},'attestation_sha256')
 v['scope_sha256']=action_scope_sha256(v)
 return seal_contract(v,'action_sha256')
def later_status(pol, **kwargs):
 a=action(pol,**kwargs)
 t=authorize_action(a,pol,6,'gate:1',TRUST)
 if t['outcome']!='ALLOW': return 'AUTHORIZE_'+t['outcome']
 return validate_authorization_token(t,8)['status']
def row(cid,desc,fn,expected,pos=False):
 try: actual=fn(); exc=None
 except Exception as e: actual='EXCEPTION'; exc=f'{type(e).__name__}: {e}'
 return {'case_id':cid,'description':desc,'positive_control':pos,'expected_outcome':expected,'actual_outcome':actual,'pass':actual==expected,'exception':exc}
def main():
 rows=[
  row('OA35-P01','Token remains valid while every source remains current',lambda:later_status(policy(20),state_until=20,att_until=20,action_until=20,nonce='positive'),'PASS',True),
  row('OA35-N01','Token must expire with the policy bundle',lambda:later_status(policy(7),state_until=20,att_until=20,action_until=20,nonce='policy'),'BLOCK'),
  row('OA35-N02','Token must expire with the assurance attestation',lambda:later_status(policy(20),state_until=20,att_until=7,action_until=20,nonce='att'),'BLOCK'),
  row('OA35-N03','Token must expire with the authenticated state witness',lambda:later_status(policy(20),state_until=7,att_until=20,action_until=20,nonce='state'),'BLOCK'),
 ]
 out={'protocol_id':PROTOCOL_ID,'candidate_commit':COMMIT,'candidate_tree':TREE,'case_count':len(rows),'pass_count':sum(r['pass'] for r in rows),'fail_count':sum(not r['pass'] for r in rows),'status':'PASS' if all(r['pass'] for r in rows) else 'FAIL','rows':rows}
 print(json.dumps(out,indent=2,sort_keys=True))
if __name__=='__main__':main()
