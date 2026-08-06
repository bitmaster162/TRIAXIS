from __future__ import annotations
import argparse,json
from pathlib import Path
from triaxis.harness_v1 import build_subagent_contract, make_sandbox_provision_receipt, resolve_harness_config, seal_sandbox_plan
from triaxis.integrity import canonical_sha256,seal_mapping
D='d'*64

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
 config=resolve_harness_config([{'name':'operator','values':{'capabilities':['read','execute'],'tools':[],'targets':[],'data_classes':['PUBLIC'],'mcp_servers':[],'max_context_bytes':1,'max_subagents':1,'max_workflow_fanout':1,'max_rounds':1,'whole_repo_upload':False,'plugin_digests':[],'sandbox_profiles':['sandbox:strict']}}])
 plan=seal_sandbox_plan({'sandbox_id':'sandbox:claimed','profile_id':'sandbox:strict','child_session_id':'child:e','repository_manifest_sha256':None,'allowed_capabilities':['read','execute'],'network_mode':'DENY','network_allowlist':[],'read_paths':['workspace/triaxis'],'write_paths':[],'env_allowlist':['PATH'],'budgets':{'cpu_seconds':30,'memory_mb':512,'wall_seconds':60,'max_processes':8},'expires_at_tick':10})
 invented={'sandbox_id':plan['sandbox_id'],'profile_id':plan['profile_id'],'child_session_id':plan['child_session_id'],'repository_manifest_sha256':None,'network_mode':'DENY','network_allowlist':[],'read_paths':plan['read_paths'],'write_paths':[],'env_allowlist':['PATH'],'budgets':plan['budgets'],'backend_id':'backend:claimed-only','state_dir_id':'state:claimed-only','pid_namespace_id':'pidns:claimed-only','mount_namespace_id':'mntns:claimed-only','network_namespace_id':'netns:claimed-only'}
 receipt=make_sandbox_provision_receipt(plan,invented,provisioner_id='provisioner:self-asserted',observed_at_tick=2)
 parent={'session_id':'parent','depth':0,'active_child_count':0,'capabilities':['read','execute'],'mcp_servers':[]}
 child=build_subagent_contract(parent,{'child_session_id':'child:e','capability_mode':'execute','requested_capabilities':['read','execute'],'isolation':'none','sandbox_profile':'sandbox:strict','sandbox_receipt_sha256':receipt['receipt_sha256'],'context_manifest_sha256':D},config,sandbox_receipt=receipt,evaluation_tick=3)
 confirmed=receipt['status']=='PASS' and child['status']=='PASS'
 rows=[{'case_id':'PROVISIONER_TRUST_01','receipt_status':receipt['status'],'child_status':child['status'],'cryptographic_provisioner_signature':False,'external_os_attestation':False,'namespace_ids_self_asserted':True,'boundary_confirmed':confirmed,'required_next_evidence':['purpose-bound provisioner signature','external key custody or KMS','OS/container attestation adapter','independent verifier of effective network/mount/process isolation']}]
 out={'contract_id':'TRIAXIS_v3.22_POSTCOMMIT_PROVISIONER_TRUST_BOUNDARY_v1','exact_product_commit':'a7ee0e3c4b049c076515e17b84ab776ffa635aa6','status':'BOUNDARY_CONFIRMED' if confirmed else 'NOT_CONFIRMED','rows':rows,'rows_sha256':canonical_sha256(rows),'result_sha256':''}; out=seal_mapping(out,'result_sha256'); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(json.dumps(out,indent=2,sort_keys=True)); return 0 if confirmed else 1
if __name__=='__main__': raise SystemExit(main())
