from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from typing import Any, Callable
from triaxis.harness_v1 import PluginRegistry, materialize_plugin_package_receipt
from triaxis.integrity import canonical_sha256, seal_mapping

SKILL=b'approved skill\n'; HOOK=b'approved hook\n'
def sha(x): return hashlib.sha256(x).hexdigest()
def authority(): return {'capabilities':['read'],'tools':['read_file'],'targets':['workspace:triaxis'],'data_classes':['PUBLIC'],'mcp_servers':[],'max_context_bytes':1,'max_subagents':0,'max_workflow_fanout':0,'max_rounds':1}
def manifest():
    return PluginRegistry.seal_manifest({'plugin_id':'plugin:p','version':'2.0.0','source_sha256':'','components':[
        {'component_type':'SKILL','component_id':'skill:p','logical_path':'skills/p.md','content_sha256':sha(SKILL),'size_bytes':len(SKILL)},
        {'component_type':'HOOK','component_id':'PRE_TOOL','logical_path':'hooks/pre.py','content_sha256':sha(HOOK),'size_bytes':len(HOOK)}],
        'skills':['skill:p'],'commands':[],'agents':[],'hooks':['PRE_TOOL'],'mcp_servers':[],'requested_capabilities':['read'],'permission_mode':'default'})
def case(i:str,fn:Callable[[],tuple[bool,Any]]):
    try: ok,obs=fn(); return {'case_id':i,'status':'PASS' if ok else 'FAIL','observed':obs}
    except Exception as e: return {'case_id':i,'status':'FAIL','observed':{'exception':type(e).__name__,'message':str(e)}}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args(); rows=[]
    def c1():
        m=manifest(); r=PluginRegistry([m['source_sha256']]).inspect_and_activate(m,session_authority=authority())
        return r['status']=='QUARANTINED',{'status':r['status'],'errors':r['errors']}
    rows.append(case('PP01_MISSING_RECEIPT',c1))
    def c2():
        m=manifest(); p=materialize_plugin_package_receipt(m,{'skill:p':b'changed\n','PRE_TOOL':HOOK},materializer_id='m',observed_at_tick=1)
        r=PluginRegistry([m['source_sha256']]).inspect_and_activate(m,session_authority=authority(),package_receipt=p,evaluation_tick=2)
        return p['status']=='BLOCK' and r['status']=='QUARANTINED',{'package':p['status'],'activation':r['status']}
    rows.append(case('PP02_CHANGED_COMPONENT',c2))
    def c3():
        m=manifest(); p=materialize_plugin_package_receipt(m,{'skill:p':SKILL},materializer_id='m',observed_at_tick=1)
        return p['status']=='BLOCK',{'status':p['status'],'errors':p['errors']}
    rows.append(case('PP03_MISSING_COMPONENT',c3))
    def c4():
        m=manifest(); p=materialize_plugin_package_receipt(m,{'skill:p':SKILL,'PRE_TOOL':HOOK},materializer_id='m',observed_at_tick=1)
        r=PluginRegistry([m['source_sha256']]).inspect_and_activate(m,session_authority=authority(),package_receipt=p,evaluation_tick=2)
        return p['status']=='PASS' and r['status']=='ACTIVE',{'package':p['status'],'activation':r['status']}
    rows.append(case('PP04_EXACT_PACKAGE_ACTIVE',c4))
    def c5():
        try:
            PluginRegistry.seal_manifest({'plugin_id':'plugin:bad','version':'2','source_sha256':'','components':[
                {'component_type':'SKILL','component_id':'different','logical_path':'skills/x.md','content_sha256':sha(SKILL),'size_bytes':len(SKILL)}],
                'skills':['skill:p'],'commands':[],'agents':[],'hooks':[],'mcp_servers':[],'requested_capabilities':['read'],'permission_mode':'default'})
        except Exception as e:
            return False,{'unexpected_seal_exception':str(e)}
        m=PluginRegistry.seal_manifest({'plugin_id':'plugin:bad','version':'2','source_sha256':'','components':[
            {'component_type':'SKILL','component_id':'different','logical_path':'skills/x.md','content_sha256':sha(SKILL),'size_bytes':len(SKILL)}],
            'skills':['skill:p'],'commands':[],'agents':[],'hooks':[],'mcp_servers':[],'requested_capabilities':['read'],'permission_mode':'default'})
        p=materialize_plugin_package_receipt(m,{'different':SKILL},materializer_id='m',observed_at_tick=1)
        r=PluginRegistry([m['source_sha256']]).inspect_and_activate(m,session_authority=authority(),package_receipt=p,evaluation_tick=2)
        return r['status']=='QUARANTINED',{'status':r['status'],'errors':r['errors']}
    rows.append(case('PP05_DECLARED_INVENTORY_MISMATCH',c5))
    passed=sum(r['status']=='PASS' for r in rows); out={'contract_id':'TRIAXIS_v3.21_PLUGIN_PACKAGE_CLOSURE_v1','total':len(rows),'passed':passed,'failed':len(rows)-passed,'status':'PASS' if passed==len(rows) else 'FAIL','rows':rows,'rows_sha256':canonical_sha256(rows),'result_sha256':''}; out=seal_mapping(out,'result_sha256'); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(json.dumps({k:out[k] for k in ('status','total','passed','failed','rows_sha256','result_sha256')},indent=2)); return 0 if out['status']=='PASS' else 1
if __name__=='__main__': raise SystemExit(main())
