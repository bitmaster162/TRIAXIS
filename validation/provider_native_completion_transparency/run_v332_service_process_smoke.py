from __future__ import annotations
import hashlib,json,os,selectors,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from typing import Any

from triaxis.completion_immutable_anchor import FilesystemImmutableCompletionAnchor
from triaxis.completion_transparency_quorum import make_completion_transparency_config, verify_completion_transparency_quorum
from triaxis.crypto_trust import PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,PURPOSE_COMPLETION_TRANSPARENCY,PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY,TrustKeyRegistry,generate_ed25519_keypair,make_trust_key_record
from triaxis.integrity import canonical_sha256
from triaxis.provider_native_idempotency import ProviderNativeIdempotencyError, make_provider_native_policy, verify_provider_native_status
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger,VerifierFreshnessSession

PROVIDER_ID='provider:v332:service-smoke'; PROVIDER_SERVICE_ID='service:provider:v332:service-smoke'; NS='namespace:v332:service-smoke'
ANCHOR_ID='completion-immutable-anchor:v332:service-smoke'; ANCHOR_AUTH='authority:immutable:v332:service-smoke'; ANCHOR_SERVICE='service:immutable:v332:service-smoke'; ANCHOR_SIGNER='signer:immutable:v332:service-smoke'; ANCHOR_DOMAIN='domain:immutable:v332:service-smoke'; RETENTION='retention:v332:service-smoke'

def http(method,url,body=None,token=None):
    data=None if body is None else json.dumps(body).encode(); headers={'Content-Type':'application/json'}
    if token: headers['Authorization']=f'Bearer {token}'
    req=Request(url,data=data,headers=headers,method=method)
    try:
        with urlopen(req,timeout=5) as r:return r.status,json.loads(r.read().decode())
    except HTTPError as e:return e.code,json.loads(e.read().decode())

def start(cmd,env):
    p=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ);ev=sel.select(timeout=10);sel.close()
    if not ev: raise RuntimeError('startup timeout')
    line=p.stdout.readline().strip(); payload=json.loads(line)
    if payload.get('status')!='listening':raise RuntimeError(str(payload))
    return p,payload

def stop(p):
    if p.poll() is None:
        p.terminate()
        try:p.wait(5)
        except subprocess.TimeoutExpired:p.kill();p.wait(5)

def run():
    root=Path.cwd().resolve(); rows=[]; procs=[]
    with tempfile.TemporaryDirectory(prefix='triaxis-v332-smoke-') as td:
        work=Path(td); now=int(time.time()); env0=os.environ.copy();env0['PYTHONPATH']=f'{root / "src"}:{root}';env0.setdefault('TERM','xterm')
        # provider-native service
        pp=generate_ed25519_keypair(); pkey='key:provider-native:v332:smoke'; psigner='signer:provider-native:v332:smoke'; pdomain='domain:provider-native:v332:smoke'; ptoken='provider-native-v332-token'
        penv=env0|{'TRIAXIS_PNI_ROOT':str(work/'provider-native'),'TRIAXIS_PNI_PROVIDER_ID':PROVIDER_ID,'TRIAXIS_PNI_SERVICE_ID':PROVIDER_SERVICE_ID,'TRIAXIS_PNI_NAMESPACE_ID':NS,'TRIAXIS_PNI_KEY_ID':pkey,'TRIAXIS_PNI_SIGNER_ID':psigner,'TRIAXIS_PNI_TRUST_DOMAIN':pdomain,'TRIAXIS_PNI_PRIVATE_KEY_B64':pp['private_key_b64'],'TRIAXIS_PNI_CLIENT_TOKEN':ptoken,'TRIAXIS_PNI_POLICY_ID':'provider-native-policy:v332:smoke','TRIAXIS_PNI_POLICY_VALID_FROM':'0','TRIAXIS_PNI_POLICY_VALID_UNTIL':'4102444800','TRIAXIS_PNI_PORT':'0','TRIAXIS_PNI_RESPONSE_TTL':'30'}
        pproc,pstart=start([sys.executable,'tools/run_provider_native_idempotency.py'],penv);procs.append(pproc)
        preg=TrustKeyRegistry([make_trust_key_record(key_id=pkey,signer_id=psigner,trust_domain=pdomain,public_key_b64=pp['public_key_b64'],purposes=[PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY],valid_from=0,valid_until=4102444800)])
        policy=make_provider_native_policy(policy_id='provider-native-policy:v332:smoke',provider_id=PROVIDER_ID,service_id=PROVIDER_SERVICE_ID,namespace_id=NS,valid_from=0,valid_until=4102444800)
        # immutable anchor in-process, externally signed head for transparency services
        ap=generate_ed25519_keypair(); akey='key:immutable:v332:smoke'
        arec=make_trust_key_record(key_id=akey,signer_id=ANCHOR_SIGNER,trust_domain=ANCHOR_DOMAIN,public_key_b64=ap['public_key_b64'],purposes=[PURPOSE_COMPLETION_IMMUTABLE_ANCHOR],valid_from=0,valid_until=4102444800)
        areg=TrustKeyRegistry([arec]); keys=work/'anchor-keys.json';keys.write_text(json.dumps([arec]))
        anchor=FilesystemImmutableCompletionAnchor(work/'immutable-anchor',anchor_id=ANCHOR_ID,authority_id=ANCHOR_AUTH,service_id=ANCHOR_SERVICE,provider_id=PROVIDER_ID,provider_service_id=PROVIDER_SERVICE_ID,retention_policy_id=RETENTION,key_id=akey,signer_id=ANCHOR_SIGNER,trust_domain=ANCHOR_DOMAIN,private_key_b64=ap['private_key_b64'],minimum_retention_ticks=100,receipt_ttl=30)
        signed_head=anchor.head(now_tick=now)
        tr_rows=[];tr_records=[];tr_services=[]
        for suffix in 'abc':
            pair=generate_ed25519_keypair(); row={'authority_id':f'authority:transparency:v332:{suffix}','service_id':f'service:transparency:v332:{suffix}','signer_id':f'signer:transparency:v332:{suffix}','key_id':f'key:transparency:v332:{suffix}','trust_domain':f'domain:transparency:v332:{suffix}'};tr_rows.append(row);tr_records.append(make_trust_key_record(key_id=row['key_id'],signer_id=row['signer_id'],trust_domain=row['trust_domain'],public_key_b64=pair['public_key_b64'],purposes=[PURPOSE_COMPLETION_TRANSPARENCY],valid_from=0,valid_until=4102444800))
            token=f'transparency-token-{suffix}'
            env=env0|{'TRIAXIS_CTA_DB':str(work/f'transparency-{suffix}.sqlite'),'TRIAXIS_CTA_ANCHOR_KEYS_JSON':str(keys),'TRIAXIS_CTA_AUTHORITY_ID':row['authority_id'],'TRIAXIS_CTA_SERVICE_ID':row['service_id'],'TRIAXIS_CTA_ANCHOR_ID':ANCHOR_ID,'TRIAXIS_CTA_KEY_ID':row['key_id'],'TRIAXIS_CTA_SIGNER_ID':row['signer_id'],'TRIAXIS_CTA_TRUST_DOMAIN':row['trust_domain'],'TRIAXIS_CTA_PRIVATE_KEY_B64':pair['private_key_b64'],'TRIAXIS_CTA_CLIENT_TOKEN':token,'TRIAXIS_CTA_EXPECTED_ANCHOR_AUTHORITY_ID':ANCHOR_AUTH,'TRIAXIS_CTA_EXPECTED_ANCHOR_SERVICE_ID':ANCHOR_SERVICE,'TRIAXIS_CTA_EXPECTED_ANCHOR_SIGNER_ID':ANCHOR_SIGNER,'TRIAXIS_CTA_EXPECTED_ANCHOR_TRUST_DOMAIN':ANCHOR_DOMAIN,'TRIAXIS_CTA_EXPECTED_PROVIDER_ID':PROVIDER_ID,'TRIAXIS_CTA_EXPECTED_PROVIDER_SERVICE_ID':PROVIDER_SERVICE_ID,'TRIAXIS_CTA_EXPECTED_RETENTION_POLICY_ID':RETENTION,'TRIAXIS_CTA_PORT':'0','TRIAXIS_CTA_RESPONSE_TTL':'30'}
            proc,startup=start([sys.executable,'tools/run_completion_transparency_authority.py'],env);procs.append(proc);tr_services.append({'startup':startup,'token':token,'row':row})
        try:
            health=[]
            for startup in [pstart]+[x['startup'] for x in tr_services]:
                code,payload=http('GET',f"http://127.0.0.1:{startup['port']}/healthz"); text=json.dumps(payload).lower(); health.append(code==200 and 'private_key' not in text and 'client_token' not in text)
            rows.append({'case_id':'V332SP01_FOUR_NEW_SERVICES_START_AND_MINIMIZE_SECRETS','process_count':4,'status':'PASS' if len(health)==4 and all(health) else 'FAIL'})
            effect=hashlib.sha256(b'effect-v332-smoke').hexdigest(); payload=hashlib.sha256(b'payload-v332-smoke').hexdigest(); base=f"http://127.0.0.1:{pstart['port']}"
            code,_=http('POST',base+'/v1/effects/begin',{'effect_id':effect,'payload_sha256':payload,'provider_request_id':'req:smoke'},token='wrong')
            rows.append({'case_id':'V332SP02_PROVIDER_MUTATION_REQUIRES_AUTH','status':'PASS' if code==403 else 'FAIL'})
            code,first=http('POST',base+'/v1/effects/begin',{'effect_id':effect,'payload_sha256':payload,'provider_request_id':'req:smoke'},token=ptoken);code2,replay=http('POST',base+'/v1/effects/begin',{'effect_id':effect,'payload_sha256':payload,'provider_request_id':'req:smoke:2'},token=ptoken)
            rows.append({'case_id':'V332SP03_PROVIDER_NATIVE_IDEMPOTENCY_REPLAY_BLOCKS_EFFECT','status':'PASS' if code==200 and code2==200 and first.get('external_effect_permitted') is True and replay.get('external_effect_permitted') is False else 'FAIL'})
            # observe exact signed anchor head in all transparency services; wrong token first
            wrong,_=http('POST',f"http://127.0.0.1:{tr_services[0]['startup']['port']}/v1/checkpoints/observe",{'signed_anchor_head':signed_head},token='wrong')
            all_observe=wrong==403
            for svc in tr_services:
                c,_=http('POST',f"http://127.0.0.1:{svc['startup']['port']}/v1/checkpoints/observe",{'signed_anchor_head':signed_head},token=svc['token']);all_observe=all_observe and c==200
            rows.append({'case_id':'V332SP04_TRANSPARENCY_CHECKPOINT_INSTALL_AUTHENTICATED','status':'PASS' if all_observe else 'FAIL'})
            session=VerifierFreshnessSession.create('verifier:v332:smoke',now-1)
            with SQLiteEpochChallengeLedger(str(work/'challenge.sqlite'),session) as ledger:
                challenge=ledger.issue(now,now+60); responses=[]
                for svc in tr_services[:2]:
                    c,p=http('POST',f"http://127.0.0.1:{svc['startup']['port']}/v1/head/challenge",{'challenge':challenge,'verifier_id':session.verifier_id,'verifier_epoch_sha256':session.epoch_sha256,'requested_at':now}); responses.append(p.get('signed_completion_transparency_response'))
                config=make_completion_transparency_config(config_id='transparency:v332:smoke',authority_set_id='transparency-set:v332:smoke',anchor_id=ANCHOR_ID,threshold=2,authorities=tr_rows,valid_from=0,valid_until=4102444800)
                try:
                    q=verify_completion_transparency_quorum(signed_head,responses,anchor_registry=areg,transparency_registry=TrustKeyRegistry(tr_records),expected_anchor_id=ANCHOR_ID,expected_anchor_authority_id=ANCHOR_AUTH,expected_anchor_service_id=ANCHOR_SERVICE,expected_anchor_signer_id=ANCHOR_SIGNER,expected_anchor_trust_domain=ANCHOR_DOMAIN,expected_provider_id=PROVIDER_ID,expected_provider_service_id=PROVIDER_SERVICE_ID,expected_retention_policy_id=RETENTION,config=config,expected_config_sha256=config['config_sha256'],challenge_ledger=ledger,expected_challenge=challenge,evaluation_tick=int(time.time()),max_response_age=10)
                    ok=q['status']=='PASS'
                except Exception:ok=False
            rows.append({'case_id':'V332SP05_TWO_OF_THREE_HTTP_TRANSPARENCY_QUORUM','status':'PASS' if ok else 'FAIL'})
        finally:
            anchor.close()
            for p in procs:stop(p)
    result={'protocol_id':'TRIAXIS_V332_SERVICE_PROCESS_SMOKE_v1','case_count':len(rows),'pass_count':sum(r['status']=='PASS' for r in rows),'fail_count':sum(r['status']!='PASS' for r in rows),'status':'PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL','rows_sha256':canonical_sha256(rows),'authority_granted':False,'production_qualified':False,'real_provider_integration':False,'physical_independence':False,'rows':rows}
    return result

def main():
    result=run(); path=Path('evidence/TRIAXIS_v3.32_SERVICE_PROCESS_SMOKE.json');path.parent.mkdir(exist_ok=True);path.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2,sort_keys=True));return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
