from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from triaxis.harness_v1 import PluginRegistry
from triaxis.integrity import canonical_sha256, seal_mapping

GOOD=b'approved skill implementation\n'; BAD=b'substituted skill implementation\n'
def sha(x): return hashlib.sha256(x).hexdigest()

def authority():
    return {'capabilities':['read'],'tools':['read_file'],'targets':['workspace:triaxis'],'data_classes':['PUBLIC'],
            'mcp_servers':[],'max_context_bytes':1,'max_subagents':0,'max_workflow_fanout':0,'max_rounds':1}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    approved=sha(GOOD); observed=sha(BAD)
    registry=PluginRegistry([approved])
    manifest=registry.seal_manifest({'plugin_id':'plugin:subject','version':'1.0.0','source_sha256':approved,
        'skills':['skill:subject'],'commands':[],'agents':[],'hooks':[],'mcp_servers':[],
        'requested_capabilities':['read'],'permission_mode':'default'})
    receipt=registry.inspect_and_activate(manifest,session_authority=authority())
    vulnerable=receipt['status']=='ACTIVE' and approved!=observed
    row={'case_id':'PLUGIN_TOCTOU_01','approved_source_sha256':approved,'observed_component_sha256':observed,
         'activation_without_package_materialization':receipt['status'],'vulnerability_reproduced':vulnerable,
         'required_fix':'bind every loaded component byte sequence to a materialized package receipt and exact manifest'}
    result={'contract_id':'TRIAXIS_v3.20_POSTCOMMIT_PLUGIN_COMPONENT_TOCTOU_v1',
            'exact_product_commit':'9628dfee0d850224021d790795dd68ab028d133f','status':'FAIL_EXPECTED' if vulnerable else 'NOT_REPRODUCED',
            'rows':[row],'rows_sha256':canonical_sha256([row]),'result_sha256':''}
    result=seal_mapping(result,'result_sha256'); a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n'); print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if vulnerable else 1
if __name__=='__main__': raise SystemExit(main())
