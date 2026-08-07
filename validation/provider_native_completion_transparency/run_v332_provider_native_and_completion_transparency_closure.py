from __future__ import annotations
import json,sys,unittest
from pathlib import Path
from triaxis.integrity import canonical_sha256
PROTOCOL_ID='TRIAXIS_PROVIDER_NATIVE_AND_COMPLETION_TRANSPARENCY_CLOSURE_v3.32'
MODULES=['tests.test_v3_32_provider_native_and_completion_transparency','tests.test_v3_32_provider_native_and_completion_transparency_schemas']
class RecordingResult(unittest.TextTestResult):
    def __init__(self,*a,**k):super().__init__(*a,**k);self.rows=[]
    def addSuccess(self,test):super().addSuccess(test);self.rows.append({'case_id':test.id(),'status':'PASS','error':None})
    def addFailure(self,test,err):super().addFailure(test,err);self.rows.append({'case_id':test.id(),'status':'FAIL','error':self._exc_info_to_string(err,test)})
    def addError(self,test,err):super().addError(test,err);self.rows.append({'case_id':test.id(),'status':'ERROR','error':self._exc_info_to_string(err,test)})
def run():
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in MODULES);r=unittest.TextTestRunner(stream=sys.stderr,verbosity=0,resultclass=RecordingResult).run(suite);rows=sorted(r.rows,key=lambda x:x['case_id'])
    return {'protocol_id':PROTOCOL_ID,'case_count':len(rows),'pass_count':sum(x['status']=='PASS' for x in rows),'fail_count':sum(x['status']!='PASS' for x in rows),'status':'PASS' if r.wasSuccessful() else 'FAIL','rows_sha256':canonical_sha256(rows),'authority_granted':False,'production_qualified':False,'local_reference_complete':True,'real_provider_integration':False,'physical_independence':False,'rows':rows}
def main():
    result=run();p=Path('evidence/TRIAXIS_v3.32_PROVIDER_NATIVE_AND_COMPLETION_TRANSPARENCY_CLOSURE.json');p.parent.mkdir(exist_ok=True);p.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2,sort_keys=True));return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
