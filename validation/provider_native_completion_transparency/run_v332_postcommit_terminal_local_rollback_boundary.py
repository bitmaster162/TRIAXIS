from __future__ import annotations
from contextlib import ExitStack
import json,subprocess,tempfile
from pathlib import Path

from tests.test_v3_29_execution_head_quorum_and_completion_witness import B, E, F, make_intent, open_provider, PROVIDER_ID, PROVIDER_SERVICE_ID, PROVIDER_SIGNER_ID, PROVIDER_DOMAIN
from tests.test_v3_30_completion_witness_quorum_and_worm_anchor import provider_outcome
from tests.test_v3_31_availability_closed_and_immutable_anchor import identities_v331, open_immutable_anchor, IMMUTABLE_ANCHOR_ID, IMMUTABLE_AUTHORITY_ID, IMMUTABLE_SERVICE_ID, IMMUTABLE_SIGNER_ID, IMMUTABLE_DOMAIN, RETENTION_POLICY_ID
from tests.test_v3_32_provider_native_and_completion_transparency import NAMESPACE_ID, PN_SIGNER_ID, PN_DOMAIN
from triaxis.completion_transparency_quorum import CompletionTransparencyError, SQLiteCompletionTransparencyAuthority, make_completion_transparency_config, verify_completion_transparency_quorum
from triaxis.crypto_trust import PURPOSE_COMPLETION_TRANSPARENCY, PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY, TrustKeyRegistry, generate_ed25519_keypair, make_trust_key_record
from triaxis.integrity import canonical_sha256
from triaxis.provider_native_idempotency import FilesystemProviderNativeIdempotencyReference, ProviderNativeIdempotencyError, make_provider_native_policy, verify_provider_native_status
from triaxis.provider_transparency_guard import verify_terminal_external_effect_guard
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


def run():
    subject=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    expected='cc02b0a17a2b9edbe83d3d0d970baec533a5c17a'
    if subject!=expected: raise RuntimeError(f'boundary must run on exact RC1 {expected}, got {subject}')
    inherited_path=Path('evidence/TRIAXIS_v3.31_POSTCOMMIT_COORDINATED_COMPLETION_EVIDENCE_ROLLBACK_BOUNDARY.json')
    inherited=json.loads(inherited_path.read_text())
    if inherited.get('status')!='BOUNDARY_CONFIRMED': raise RuntimeError('v3.31 inherited boundary not confirmed')
    rows=[]; ids=identities_v331(); intent=make_intent(); effect_id=intent['effect_id']
    with tempfile.TemporaryDirectory(prefix='triaxis-v332-boundary-') as td:
        root=Path(td)
        # Same provider-native signing identity is used for the current and rolled-back snapshots.
        pair=generate_ed25519_keypair(); key_id='key:provider-native:v332:boundary'
        preg=TrustKeyRegistry([make_trust_key_record(key_id=key_id,signer_id=PN_SIGNER_ID,trust_domain=PN_DOMAIN,public_key_b64=pair['public_key_b64'],purposes=[PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY],valid_from=0,valid_until=100000)])
        policy=make_provider_native_policy(policy_id='provider-native-policy:v332:boundary',provider_id=PROVIDER_ID,service_id=PROVIDER_SERVICE_ID,namespace_id=NAMESPACE_ID,valid_from=0,valid_until=10000)
        current_provider=FilesystemProviderNativeIdempotencyReference(root/'provider-current',provider_id=PROVIDER_ID,service_id=PROVIDER_SERVICE_ID,namespace_id=NAMESPACE_ID,key_id=key_id,signer_id=PN_SIGNER_ID,trust_domain=PN_DOMAIN,private_key_b64=pair['private_key_b64'],response_ttl=100)
        rolled_provider=FilesystemProviderNativeIdempotencyReference(root/'provider-rolled',provider_id=PROVIDER_ID,service_id=PROVIDER_SERVICE_ID,namespace_id=NAMESPACE_ID,key_id=key_id,signer_id=PN_SIGNER_ID,trust_domain=PN_DOMAIN,private_key_b64=pair['private_key_b64'],response_ttl=100)
        current_provider.begin(effect_id=effect_id,payload_sha256=B,provider_request_id='provider-native-request:v332:boundary',now_tick=10)
        current_provider.record_outcome(effect_id=effect_id,state='COMPLETED',provider_response_sha256=E,evidence_sha256=F,now_tick=11)
        session=VerifierFreshnessSession.create('verifier:v332:boundary:provider-current',0);challenge='challenge-provider-current-v332-boundary'
        status=current_provider.signed_status(effect_id=effect_id,payload_sha256=B,challenge=challenge,verifier_id=session.verifier_id,verifier_epoch_sha256=session.epoch_sha256,policy=policy,now_tick=12)
        try:
            verify_provider_native_status(status,registry=preg,current_policy=policy,expected_policy_sha256=policy['policy_sha256'],expected_provider_id=PROVIDER_ID,expected_service_id=PROVIDER_SERVICE_ID,expected_namespace_id=NAMESPACE_ID,expected_signer_id=PN_SIGNER_ID,expected_trust_domain=PN_DOMAIN,expected_effect_id=effect_id,expected_payload_sha256=B,expected_verifier_id=session.verifier_id,expected_verifier_epoch_sha256=session.epoch_sha256,expected_challenge=challenge,evaluation_tick=12)
            blocked=False
        except ProviderNativeIdempotencyError as exc:
            blocked=exc.code=='provider_native_state_blocks_retry'
        rows.append({'case_id':'V332B01_CURRENT_PROVIDER_NATIVE_COMPLETED_BLOCKS_RETRY','observed':'BLOCK' if blocked else 'UNEXPECTED_PASS','status':'PASS' if blocked else 'FAIL'})

        # Same immutable-anchor identity, two snapshots: empty old head and current completed head.
        old_anchor=open_immutable_anchor(root/'anchor-old',ids); current_anchor=open_immutable_anchor(root/'anchor-current',ids)
        with open_provider(':memory:',ids) as p:
            receipt=provider_outcome(p,effect_id=effect_id,request_id='provider-request:v332:boundary',outcome='COMPLETED',begin_tick=5,outcome_tick=6)
            current_anchor.store_provider_outcome(receipt,provider_registry=ids['provider_registry'],expected_provider_signer_id=PROVIDER_SIGNER_ID,expected_provider_trust_domain=PROVIDER_DOMAIN,evaluation_tick=6,retention_until_tick=500)
        old_head=old_anchor.head(now_tick=12); current_head=current_anchor.head(now_tick=12)

        tr_rows=[];tr_records=[];current_auth=[];old_auth=[]
        for suffix in 'abc':
            kp=generate_ed25519_keypair(); row={'authority_id':f'authority:transparency:v332:boundary:{suffix}','service_id':f'service:transparency:v332:boundary:{suffix}','signer_id':f'signer:transparency:v332:boundary:{suffix}','key_id':f'key:transparency:v332:boundary:{suffix}','trust_domain':f'domain:transparency:v332:boundary:{suffix}'};tr_rows.append(row);tr_records.append(make_trust_key_record(key_id=row['key_id'],signer_id=row['signer_id'],trust_domain=row['trust_domain'],public_key_b64=kp['public_key_b64'],purposes=[PURPOSE_COMPLETION_TRANSPARENCY],valid_from=0,valid_until=100000))
            cur=SQLiteCompletionTransparencyAuthority(root/f'cur-{suffix}.sqlite',authority_id=row['authority_id'],service_id=row['service_id'],anchor_id=IMMUTABLE_ANCHOR_ID,key_id=row['key_id'],signer_id=row['signer_id'],trust_domain=row['trust_domain'],private_key_b64=kp['private_key_b64'],response_ttl=100)
            old=SQLiteCompletionTransparencyAuthority(root/f'old-{suffix}.sqlite',authority_id=row['authority_id'],service_id=row['service_id'],anchor_id=IMMUTABLE_ANCHOR_ID,key_id=row['key_id'],signer_id=row['signer_id'],trust_domain=row['trust_domain'],private_key_b64=kp['private_key_b64'],response_ttl=100)
            cur.observe_verified_head(current_head['inner_contract'],observed_at=12);old.observe_verified_head(old_head['inner_contract'],observed_at=12);current_auth.append(cur);old_auth.append(old)
        treg=TrustKeyRegistry(tr_records);config=make_completion_transparency_config(config_id='transparency:v332:boundary',authority_set_id='transparency-set:v332:boundary',anchor_id=IMMUTABLE_ANCHOR_ID,threshold=2,authorities=tr_rows,valid_from=0,valid_until=10000)
        def tq(responders,tag):
            s=VerifierFreshnessSession.create(f'verifier:v332:boundary:{tag}',0); ledger=SQLiteEpochChallengeLedger(str(root/f'ch-{tag}.sqlite'),s); ch=ledger.issue(1,100);responses=[a.signed_response(challenge=ch,verifier_id=s.verifier_id,verifier_epoch_sha256=s.epoch_sha256,requested_at=1,now_tick=12) for a in responders]
            kwargs=dict(anchor_registry=ids['immutable_registry'],transparency_registry=treg,expected_anchor_id=IMMUTABLE_ANCHOR_ID,expected_anchor_authority_id=IMMUTABLE_AUTHORITY_ID,expected_anchor_service_id=IMMUTABLE_SERVICE_ID,expected_anchor_signer_id=IMMUTABLE_SIGNER_ID,expected_anchor_trust_domain=IMMUTABLE_DOMAIN,expected_provider_id=PROVIDER_ID,expected_provider_service_id=PROVIDER_SERVICE_ID,expected_retention_policy_id=RETENTION_POLICY_ID,config=config,expected_config_sha256=config['config_sha256'],challenge_ledger=ledger,expected_challenge=ch,evaluation_tick=12,max_response_age=5)
            return s,ledger,ch,responses,kwargs
        # Provider rollback alone is insufficient when current transparency remembers a newer completion anchor head.
        s,l,ch,responses,kwargs=tq(current_auth[:2],'newer-veto')
        try: verify_completion_transparency_quorum(old_head,responses,**kwargs);veto=False
        except CompletionTransparencyError as exc:veto=exc.code=='completion_transparency_newer_minority_veto'
        l.close();rows.append({'case_id':'V332B02_PROVIDER_AND_ANCHOR_ROLLBACK_BLOCKED_BY_CURRENT_TRANSPARENCY','observed':'NEWER_HEAD_VETO' if veto else 'UNEXPECTED_PASS','status':'PASS' if veto else 'FAIL'})
        # Two rolled-back authorities cannot erase a current minority if that minority is present.
        s,l,ch,responses,kwargs=tq([old_auth[0],old_auth[1],current_auth[2]],'minority-veto')
        try: verify_completion_transparency_quorum(old_head,responses,**kwargs);veto2=False
        except CompletionTransparencyError as exc:veto2=exc.code=='completion_transparency_newer_minority_veto'
        l.close();rows.append({'case_id':'V332B03_CURRENT_TRANSPARENCY_MINORITY_VETOES_ROLLED_THRESHOLD','observed':'NEWER_MINORITY_VETO' if veto2 else 'UNEXPECTED_PASS','status':'PASS' if veto2 else 'FAIL'})
        # Terminal local boundary: current minority unavailable, threshold + provider + inherited v3.31 evidence all rolled back.
        ps=VerifierFreshnessSession.create('verifier:v332:boundary:provider-rolled',0);pch='challenge-provider-rolled-v332-boundary';pstatus=rolled_provider.signed_status(effect_id=effect_id,payload_sha256=B,challenge=pch,verifier_id=ps.verifier_id,verifier_epoch_sha256=ps.epoch_sha256,policy=policy,now_tick=12)
        pn_kwargs=dict(registry=preg,current_policy=policy,expected_policy_sha256=policy['policy_sha256'],expected_provider_id=PROVIDER_ID,expected_service_id=PROVIDER_SERVICE_ID,expected_namespace_id=NAMESPACE_ID,expected_signer_id=PN_SIGNER_ID,expected_trust_domain=PN_DOMAIN,expected_effect_id=effect_id,expected_payload_sha256=B,expected_verifier_id=ps.verifier_id,expected_verifier_epoch_sha256=ps.epoch_sha256,expected_challenge=pch,evaluation_tick=12)
        s,l,ch,responses,kwargs=tq(old_auth[:2],'terminal-old-threshold')
        try:
            final=verify_terminal_external_effect_guard(v331_guard_result={'status':'PASS','authority_granted':False,'inherited_boundary_evidence_sha256':canonical_sha256(inherited)},separate_authorization_valid=True,signed_provider_status=pstatus,provider_status_kwargs=pn_kwargs,signed_local_anchor_head=old_head,signed_transparency_responses=responses,transparency_kwargs=kwargs)
            terminal_pass=final.get('status')=='PASS' and final.get('external_effect_permitted') is True
        except Exception: terminal_pass=False
        l.close();rows.append({'case_id':'V332B04_COORDINATED_ROLLBACK_OF_ALL_LOCAL_EVIDENCE_DOMAINS_REVIVES_EFFECT','observed':'OLD_PERMISSIVE_VIEW_RESTORED' if terminal_pass else 'BLOCK','status':'FAIL_EXPECTED' if terminal_pass else 'UNEXPECTED_BLOCK'})
        for a in current_auth+old_auth:a.close()
        old_anchor.close();current_anchor.close()
    good=all(r['status']=='PASS' for r in rows[:3]) and rows[3]['status']=='FAIL_EXPECTED'
    return {'protocol_id':'TRIAXIS_v3.32_POSTCOMMIT_TERMINAL_LOCAL_ROLLBACK_BOUNDARY_v1','subject_commit':subject,'inherited_v331_boundary_status':inherited.get('status'),'case_count':len(rows),'status':'BOUNDARY_CONFIRMED' if good else 'BOUNDARY_NOT_CONFIRMED','rows_sha256':canonical_sha256(rows),'local_reference_complete':True,'production_qualified':False,'exactly_once_established':False,'physical_independence':False,'real_provider_integration':False,'rows':rows}

def main():
    result=run();p=Path('evidence/TRIAXIS_v3.32_POSTCOMMIT_TERMINAL_LOCAL_ROLLBACK_BOUNDARY.json');p.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2,sort_keys=True));return 0 if result['status']=='BOUNDARY_CONFIRMED' else 1
if __name__=='__main__':raise SystemExit(main())
