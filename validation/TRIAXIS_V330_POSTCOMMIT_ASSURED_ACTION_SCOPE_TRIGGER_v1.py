from __future__ import annotations
import json, sys
from typing import Any, Callable
sys.path.insert(0, '/mnt/data/TRIAXIS_V330_EXACT_WORK/src')
from triaxis.action_assurance import ACTION_ENVELOPE_CONTRACT_ID, ASSURANCE_ATTESTATION_CONTRACT_ID, STATE_WITNESS_CONTRACT_ID, action_scope_sha256, authorize_action, seal_contract
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy

PROTOCOL_ID='TRIAXIS_V330_POSTCOMMIT_ASSURED_ACTION_SCOPE_TRIGGER_v1'
COMMIT='07e8b1371df806792c48b5ac6a3b89a681d92ef8'
TREE='bbacc5531db957bda96bb217aefd3ee459cf2919'

def state():
 return seal_contract({'contract_id':STATE_WITNESS_CONTRACT_ID,'state_id':'s1','subject_id':'subject:1','object_id':'repo:1','adapter_id':'adapter:1','version':1,'state_sha256':'a'*64,'attestation_level':'AUTHENTICATED','observed_at':5,'valid_until':20,'witness_sha256':''},'witness_sha256')

def policy():
 return seal_policy({'contract_id':POLICY_BUNDLE_CONTRACT_ID,'policy_id':'policy:1','subject_id':'subject:1','issuer_id':'policy:issuer','sequence':1,'minimum_accepted_sequence':1,'state':'ACTIVE','effective_from':1,'valid_until':20,'allowed_capabilities':['WRITE'],'allowed_tools':['git','shell'],'allowed_targets':['repo:1','repo:2'],'max_risk_class':'R2','required_approval_types':[],'supersedes_policy_sha256':None,'policy_sha256':''})

def attestation():
 return seal_contract({'contract_id':ASSURANCE_ATTESTATION_CONTRACT_ID,'attestation_id':'a1','issuer_id':'assurance:1','trust_domain':'domain:1','subject_id':'subject:1','decision_case_sha256':'b'*64,'evidence_report_sha256':'c'*64,'assurance_status':'PASS','synthesis_decision':'ACCEPT','attestation_level':'AUTHENTICATED','issued_at':5,'valid_until':15,'attestation_sha256':''},'attestation_sha256')

def action(nonce='n1', payload='d'*64, tool='git', target='repo:1', trust_att=None):
 v={'contract_id':ACTION_ENVELOPE_CONTRACT_ID,'principal_id':'human:1','intent_id':'intent:1','decision_case_sha256':'b'*64,'evidence_report_sha256':'c'*64,'assurance_attestation':attestation() if trust_att is None else trust_att,'subject_id':'subject:1','object_id':'repo:1','capability':'WRITE','tool_id':tool,'execution_target':target,'payload_sha256':payload,'policy_id':'policy:1','policy_sequence':1,'state_witness':state(),'risk_class':'R2','nonce':nonce,'issued_at':5,'expires_at':15,'approvals':[],'scope_sha256':'','action_sha256':''}
 v['scope_sha256']=action_scope_sha256(v)
 return seal_contract(v,'action_sha256')

def outcome(a, trusted): return authorize_action(a,policy(),6,'gate:1',trusted)['outcome']

def row(cid,desc,fn,expected,pos=False):
 try: actual=fn(); exc=None
 except Exception as e: actual='EXCEPTION'; exc=f'{type(e).__name__}: {e}'
 return {'case_id':cid,'description':desc,'positive_control':pos,'expected_outcome':expected,'actual_outcome':actual,'pass':actual==expected,'exception':exc}

def main():
 shared=attestation()
 rows=[
  row('OA34-P01','Exact attested action positive control',lambda:outcome(action(trust_att=shared),{'assurance:1':'domain:1'}),'ALLOW',True),
  row('OA34-N01','PASS attestation must not be reusable for another payload',lambda:outcome(action(nonce='payload-swap',payload='e'*64,trust_att=shared),{'assurance:1':'domain:1'}),'DENY'),
  row('OA34-N02','PASS attestation must not be reusable for another allowed tool and target',lambda:outcome(action(nonce='route-swap',tool='shell',target='repo:2',trust_att=shared),{'assurance:1':'domain:1'}),'DENY'),
  row('OA34-N03','Set-only issuer registry must not erase trust-domain binding',lambda:outcome(action(nonce='domain-erasure',trust_att=seal_contract({**shared,'trust_domain':'wrong','attestation_sha256':''},'attestation_sha256')),{'assurance:1'}),'DENY'),
 ]
 out={'protocol_id':PROTOCOL_ID,'candidate_commit':COMMIT,'candidate_tree':TREE,'case_count':len(rows),'pass_count':sum(r['pass'] for r in rows),'fail_count':sum(not r['pass'] for r in rows),'status':'PASS' if all(r['pass'] for r in rows) else 'FAIL','rows':rows}
 print(json.dumps(out,indent=2,sort_keys=True))
if __name__=='__main__': main()
