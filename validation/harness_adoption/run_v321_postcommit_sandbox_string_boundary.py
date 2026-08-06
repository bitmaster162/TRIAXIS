from __future__ import annotations
import argparse, json
from pathlib import Path
from triaxis.harness_v1 import build_subagent_contract, resolve_harness_config
from triaxis.integrity import canonical_sha256, seal_mapping
D='d'*64

def cfg():
 return resolve_harness_config([{'name':'operator','values':{'capabilities':['read','write','execute'],'tools':[],'targets':[],'data_classes':['PUBLIC'],'mcp_servers':[],'max_context_bytes':1,'max_subagents':2,'max_workflow_fanout':1,'max_rounds':1,'whole_repo_upload':False,'plugin_digests':[],'sandbox_profiles':['sandbox:approved']}}])
def parent(): return {'session_id':'parent','depth':0,'active_child_count':0,'capabilities':['read','write','execute'],'mcp_servers':[]}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
 write=build_subagent_contract(parent(),{'child_session_id':'writer','capability_mode':'read-write','requested_capabilities':['read','write'],'isolation':'worktree','worktree_ref':'worktree:invented','context_manifest_sha256':D},cfg())
 execute=build_subagent_contract(parent(),{'child_session_id':'executor','capability_mode':'execute','requested_capabilities':['read','execute'],'isolation':'none','sandbox_profile':'sandbox:approved','context_manifest_sha256':D},cfg())
 vulnerable=write['status']=='PASS' and execute['status']=='PASS'
 rows=[{'case_id':'SANDBOX_STRING_01','write_contract_status':write['status'],'execute_contract_status':execute['status'],'actual_worktree_receipt':False,'actual_sandbox_receipt':False,'vulnerability_reproduced':vulnerable,'required_fix':'bind child contract to exact repository manifest and sandbox provision receipt'}]
 out={'contract_id':'TRIAXIS_v3.21_POSTCOMMIT_SANDBOX_STRING_BOUNDARY_v1','exact_product_commit':'d18cfc21944a289ae27cad8588e0d85598a01420','status':'FAIL_EXPECTED' if vulnerable else 'NOT_REPRODUCED','rows':rows,'rows_sha256':canonical_sha256(rows),'result_sha256':''}; out=seal_mapping(out,'result_sha256'); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(json.dumps(out,indent=2,sort_keys=True)); return 0 if vulnerable else 1
if __name__=='__main__': raise SystemExit(main())
