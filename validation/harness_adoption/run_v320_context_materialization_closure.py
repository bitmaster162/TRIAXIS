from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from triaxis.harness_v1 import (
    CapabilityBroker, ToolSpec, assemble_context, materialize_context_receipt,
    resolve_harness_config, seal_tool_request,
)
from triaxis.integrity import canonical_sha256, seal_mapping

GOOD = b'approved bytes\n'
BAD = b'changed after approval\n'


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def cfg():
    return resolve_harness_config([{'name':'operator','values':{
        'capabilities':['read'], 'tools':['read_file'], 'targets':['workspace:triaxis'],
        'data_classes':['PUBLIC'], 'mcp_servers':[], 'max_context_bytes':4096,
        'max_subagents':0, 'max_workflow_fanout':0, 'max_rounds':1,
        'whole_repo_upload':False, 'plugin_digests':[], 'sandbox_profiles':[]
    }}])


def manifest():
    return assemble_context({'session_id':'s','purpose':'exact read','items':[{
        'artifact_id':'file:x','logical_path':'x.txt','source_kind':'FILE',
        'content_sha256':sha(GOOD),'size_bytes':len(GOOD),'data_class':'PUBLIC','explicit_grant':True
    }]}, cfg())


def authority():
    return {'capabilities':['read'],'tools':['read_file'],'targets':['workspace:triaxis'],
            'data_classes':['PUBLIC'],'mcp_servers':[],'max_context_bytes':4096,
            'max_subagents':0,'max_workflow_fanout':0,'max_rounds':1}


def run_case(case_id: str, fn: Callable[[], tuple[bool, Any]]):
    try:
        ok, observed = fn()
        return {'case_id':case_id,'status':'PASS' if ok else 'FAIL','observed':observed}
    except Exception as exc:
        return {'case_id':case_id,'status':'FAIL','observed':{'exception':type(exc).__name__,'message':str(exc)}}


def broker_and_request(receipt_sha: str | None):
    broker=CapabilityBroker(); broker.register(ToolSpec('read_file','read',False,('workspace:triaxis',),4096,('PUBLIC',)))
    request=seal_tool_request({'tool_id':'read_file','target':'workspace:triaxis','input_artifact_ids':['file:x'],
                               'materialization_receipt_sha256':receipt_sha,'payload_sha256':sha(b'read'),'max_output_bytes':4096})
    return broker, request


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path,required=True); args=ap.parse_args()
    rows=[]

    def c1():
        r=materialize_context_receipt(manifest(),{'file:x':BAD},materializer_id='m',observed_at_tick=1)
        return r['status']=='BLOCK', {'status':r['status'],'errors':r['errors']}
    rows.append(run_case('CM01_CHANGED_BYTES_BLOCK',c1))

    def c2():
        b,q=broker_and_request(None)
        out=b.dispatch(q,session_authority=authority(),context_manifest=manifest(),hook_receipt=None,evaluation_tick=2)
        return out['outcome']=='DENY', {'outcome':out['outcome'],'errors':out['errors']}
    rows.append(run_case('CM02_MISSING_RECEIPT_DENY',c2))

    def c3():
        m=manifest(); r=materialize_context_receipt(m,{'file:x':GOOD},materializer_id='m',observed_at_tick=1)
        b,q=broker_and_request(r['receipt_sha256'])
        out=b.dispatch(q,session_authority=authority(),context_manifest=m,materialization_receipt=r,hook_receipt=None,evaluation_tick=2)
        return r['status']=='PASS' and out['outcome']=='ALLOW', {'receipt_status':r['status'],'outcome':out['outcome']}
    rows.append(run_case('CM03_EXACT_BYTES_ALLOW',c3))

    def c4():
        m=manifest(); r=materialize_context_receipt(m,{'file:x':GOOD},materializer_id='m',observed_at_tick=1)
        b,q=broker_and_request('f'*64)
        out=b.dispatch(q,session_authority=authority(),context_manifest=m,materialization_receipt=r,hook_receipt=None,evaluation_tick=2)
        return out['outcome']=='DENY', {'outcome':out['outcome'],'errors':out['errors']}
    rows.append(run_case('CM04_REQUEST_RECEIPT_BINDING',c4))

    def c5():
        m=manifest(); r=materialize_context_receipt(m,{'file:x':GOOD},materializer_id='m',observed_at_tick=9)
        b,q=broker_and_request(r['receipt_sha256'])
        out=b.dispatch(q,session_authority=authority(),context_manifest=m,materialization_receipt=r,hook_receipt=None,evaluation_tick=2)
        return out['outcome']=='DENY', {'outcome':out['outcome'],'errors':out['errors']}
    rows.append(run_case('CM05_FUTURE_RECEIPT_DENY',c5))

    passed=sum(x['status']=='PASS' for x in rows)
    result={'contract_id':'TRIAXIS_v3.20_CONTEXT_MATERIALIZATION_CLOSURE_v1','total':len(rows),'passed':passed,
            'failed':len(rows)-passed,'status':'PASS' if passed==len(rows) else 'FAIL','rows':rows,
            'rows_sha256':canonical_sha256(rows),'result_sha256':''}
    result=seal_mapping(result,'result_sha256')
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:result[k] for k in ('status','total','passed','failed','rows_sha256','result_sha256')},indent=2))
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__': raise SystemExit(main())
