from __future__ import annotations
import argparse,json
from pathlib import Path
from typing import Any,Callable
from triaxis.harness_v1 import build_subagent_contract, make_sandbox_provision_receipt, resolve_harness_config, seal_repository_manifest, seal_sandbox_plan
from triaxis.integrity import canonical_sha256,seal_mapping
D='d'*64

def config(): return resolve_harness_config([{'name':'operator','values':{'capabilities':['read','write','execute'],'tools':[],'targets':[],'data_classes':['PUBLIC'],'mcp_servers':[],'max_context_bytes':1,'max_subagents':2,'max_workflow_fanout':1,'max_rounds':1,'whole_repo_upload':False,'plugin_digests':[],'sandbox_profiles':['sandbox:strict']}}])
def parent(): return {'session_id':'parent','depth':0,'active_child_count':0,'capabilities':['read','write','execute'],'mcp_servers':[]}
def repo(child='child:all',worktree='wt:1',observed=2,expires=10,clean=True,writable=True): return seal_repository_manifest({'manifest_id':'rm:1','session_id':child,'observer_id':'repo-observer','observed_at_tick':observed,'expires_at_tick':expires,'repositories':[{'repo_id':'repo:triaxis','root_logical_path':'workspace/triaxis','worktree_ref':worktree,'baseline_commit':'a'*40,'clean':clean,'writable':writable}]})
def sandbox(child='child:all',repositories=None,observed=3,expires=10,network='DENY'):
 p=seal_sandbox_plan({'sandbox_id':'sb:1','profile_id':'sandbox:strict','child_session_id':child,'repository_manifest_sha256':None if repositories is None else repositories['manifest_sha256'],'allowed_capabilities':['read','write','execute'],'network_mode':network,'network_allowlist':[] if network=='DENY' else ['api.example.test:443'],'read_paths':['workspace/triaxis'],'write_paths':['workspace/triaxis'],'env_allowlist':['PATH'],'budgets':{'cpu_seconds':30,'memory_mb':512,'wall_seconds':60,'max_processes':8},'expires_at_tick':expires})
 o={'sandbox_id':p['sandbox_id'],'profile_id':p['profile_id'],'child_session_id':p['child_session_id'],'repository_manifest_sha256':p['repository_manifest_sha256'],'network_mode':p['network_mode'],'network_allowlist':p['network_allowlist'],'read_paths':p['read_paths'],'write_paths':p['write_paths'],'env_allowlist':p['env_allowlist'],'budgets':p['budgets'],'backend_id':'backend:test','state_dir_id':'state:1','pid_namespace_id':'pidns:1','mount_namespace_id':'mntns:1','network_namespace_id':'netns:1'}
 return p,make_sandbox_provision_receipt(p,o,provisioner_id='provisioner:test',observed_at_tick=observed)
def case(i:str,fn:Callable[[],tuple[bool,Any]]):
 try: ok,obs=fn(); return {'case_id':i,'status':'PASS' if ok else 'FAIL','observed':obs}
 except Exception as e: return {'case_id':i,'status':'FAIL','observed':{'exception':type(e).__name__,'message':str(e)}}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args(); rows=[]
 def c1():
  out=build_subagent_contract(parent(),{'child_session_id':'child:w','capability_mode':'read-write','requested_capabilities':['read','write'],'isolation':'worktree','worktree_ref':'wt:w','context_manifest_sha256':D},config(),evaluation_tick=4)
  return out['status']=='BLOCK',{'status':out['status'],'errors':out['errors']}
 rows.append(case('SB01_WRITE_WITHOUT_REPO_RECEIPT',c1))
 def c2():
  r=repo(child='child:w',worktree='wt:other')
  out=build_subagent_contract(parent(),{'child_session_id':'child:w','capability_mode':'read-write','requested_capabilities':['read','write'],'isolation':'worktree','worktree_ref':'wt:w','repository_manifest_sha256':r['manifest_sha256'],'context_manifest_sha256':D},config(),repository_manifest=r,evaluation_tick=4)
  return out['status']=='BLOCK',{'status':out['status'],'errors':out['errors']}
 rows.append(case('SB02_WRONG_WORKTREE',c2))
 def c3():
  r=repo(child='child:w',worktree='wt:w',observed=1,expires=3)
  out=build_subagent_contract(parent(),{'child_session_id':'child:w','capability_mode':'read-write','requested_capabilities':['read','write'],'isolation':'worktree','worktree_ref':'wt:w','repository_manifest_sha256':r['manifest_sha256'],'context_manifest_sha256':D},config(),repository_manifest=r,evaluation_tick=4)
  return out['status']=='BLOCK',{'status':out['status'],'errors':out['errors']}
 rows.append(case('SB03_STALE_REPOSITORY_MANIFEST',c3))
 def c4():
  out=build_subagent_contract(parent(),{'child_session_id':'child:e','capability_mode':'execute','requested_capabilities':['read','execute'],'isolation':'none','sandbox_profile':'sandbox:strict','context_manifest_sha256':D},config(),evaluation_tick=4)
  return out['status']=='BLOCK',{'status':out['status'],'errors':out['errors']}
 rows.append(case('SB04_EXECUTE_WITHOUT_PROVISION_RECEIPT',c4))
 def c5():
  p=seal_sandbox_plan({'sandbox_id':'sb:x','profile_id':'sandbox:strict','child_session_id':'child:e','repository_manifest_sha256':None,'allowed_capabilities':['read','execute'],'network_mode':'DENY','network_allowlist':[],'read_paths':['workspace/triaxis'],'write_paths':[],'env_allowlist':['PATH'],'budgets':{'cpu_seconds':30,'memory_mb':512,'wall_seconds':60,'max_processes':8},'expires_at_tick':10})
  observed={'sandbox_id':'sb:x','profile_id':'sandbox:strict','child_session_id':'child:e','repository_manifest_sha256':None,'network_mode':'ALLOWLIST','network_allowlist':['evil.test:443'],'read_paths':p['read_paths'],'write_paths':p['write_paths'],'env_allowlist':p['env_allowlist'],'budgets':p['budgets'],'backend_id':'b','state_dir_id':'s','pid_namespace_id':'p','mount_namespace_id':'m','network_namespace_id':'n'}
  receipt=make_sandbox_provision_receipt(p,observed,provisioner_id='provisioner:test',observed_at_tick=3)
  return receipt['status']=='BLOCK',{'status':receipt['status'],'errors':receipt['errors']}
 rows.append(case('SB05_OBSERVED_SANDBOX_MISMATCH',c5))
 def c6():
  _,receipt=sandbox(child='child:e',observed=2,expires=3)
  out=build_subagent_contract(parent(),{'child_session_id':'child:e','capability_mode':'execute','requested_capabilities':['read','execute'],'isolation':'none','sandbox_profile':'sandbox:strict','sandbox_receipt_sha256':receipt['receipt_sha256'],'context_manifest_sha256':D},config(),sandbox_receipt=receipt,evaluation_tick=4)
  return out['status']=='BLOCK',{'status':out['status'],'errors':out['errors']}
 rows.append(case('SB06_EXPIRED_SANDBOX_RECEIPT',c6))
 def c7():
  r=repo(); _,receipt=sandbox(repositories=r)
  out=build_subagent_contract(parent(),{'child_session_id':'child:all','capability_mode':'all','requested_capabilities':['read','write','execute'],'isolation':'worktree','worktree_ref':'wt:1','repository_manifest_sha256':r['manifest_sha256'],'sandbox_profile':'sandbox:strict','sandbox_receipt_sha256':receipt['receipt_sha256'],'context_manifest_sha256':D},config(),repository_manifest=r,sandbox_receipt=receipt,evaluation_tick=4)
  return out['status']=='PASS',{'status':out['status'],'subagent_sha256':out['subagent_sha256']}
 rows.append(case('SB07_VALID_ATTESTED_WRITE_EXECUTE',c7))
 passed=sum(x['status']=='PASS' for x in rows); out={'contract_id':'TRIAXIS_v3.22_SANDBOX_PROVISION_CLOSURE_v1','total':len(rows),'passed':passed,'failed':len(rows)-passed,'status':'PASS' if passed==len(rows) else 'FAIL','rows':rows,'rows_sha256':canonical_sha256(rows),'result_sha256':''}; out=seal_mapping(out,'result_sha256'); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(json.dumps({k:out[k] for k in ('status','total','passed','failed','rows_sha256','result_sha256')},indent=2)); return 0 if out['status']=='PASS' else 1
if __name__=='__main__': raise SystemExit(main())
