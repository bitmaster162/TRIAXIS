from copy import deepcopy
import json
from tests.test_v300_research_integration import valid_case, reseal
from triaxis.assurance_v1 import validate_assurance_case

cases=[]
def add(name, mutate, expected):
    c=valid_case(risk='R3')
    mutate(c)
    r=validate_assurance_case(reseal(c))
    cases.append({'case':name,'expected':expected,'observed':r['status'],'conformant':r['status']==expected,'reason':r['primary_reason'],'codes':[e['code'] for e in r['errors']]})

add('duplicate_primary', lambda c: c['branches'].append(deepcopy(c['branches'][0])), 'BLOCK')

def same_evidence(c):
    review=next(b for b in c['branches'] if b['pass_type']=='INDEPENDENT_REVIEW')
    review['claims'][0]={'claim_id':'C4','load_bearing':True,'classification':'SOURCE_BACKED','evidence_ids':['E1']}
add('independent_review_reuses_primary_evidence', same_evidence, 'BLOCK')

add('falsification_has_no_test_evidence_binding', lambda c: None, 'BLOCK')
add('devil_not_blind_to_primary', lambda c: None, 'BLOCK')
add('malformed_action_payload_digest', lambda c: c['gate_request'].__setitem__('action_payload_sha256','x'), 'BLOCK')

def stale_evidence(c):
    c['evidence'][0]['observed_at']=1
    c['evidence'][0]['valid_until']=2
    c['intake']['evaluation_tick']=3
add('stale_load_bearing_evidence', stale_evidence, 'BLOCK')

def unverified(c):
    cl=c['branches'][0]['claims'][0]
    cl['evidence_ids']=[]
    cl['classification']='UNVERIFIED_ASSUMPTION'
add('load_bearing_unverified_assumption', unverified, 'ESCALATE')

def duplicate_source(c):
    c['evidence'][1]['source_group']=c['evidence'][0]['source_group']
add('all_evidence_same_correlation_group', duplicate_source, 'BLOCK')

print(json.dumps(cases,ensure_ascii=False,indent=2))
print('PASS',sum(x['conformant'] for x in cases),'FAIL',sum(not x['conformant'] for x in cases))
