"""TRIAXIS v3.17 operator-pinned quorum of external gossip-head authorities."""
from __future__ import annotations
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from .crypto_trust import PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT, PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY, TrustKeyRegistry, verify_contract_envelope
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .policy_head_authority import PolicyHeadAuthorityError
from .policy_transparency_floor import SQLitePolicyTransparencyGossipStore
from .policy_transparency_gossip_head import GOSSIP_CHECKPOINT_CONTRACT_ID, GOSSIP_HEAD_RESPONSE_CONTRACT_ID, export_gossip_state
from .trust_registry_quorum import SQLiteEpochChallengeLedger

GOSSIP_HEAD_QUORUM_CONFIG_CONTRACT_ID="TRIAXIS_POLICY_TRANSPARENCY_GOSSIP_HEAD_QUORUM_CONFIG_v1"

def _is_sha256(v:Any)->bool: return isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v)

def make_gossip_head_quorum_config(*,config_id:str,authority_set_id:str,store_id:str,threshold:int,authorities:Sequence[Mapping[str,str]],valid_from:int,valid_until:int)->dict[str,Any]:
    rows=[{k:str(x[k]) for k in ('authority_id','service_id','signer_id','key_id','trust_domain')} for x in authorities]
    rows.sort(key=lambda x:(x['signer_id'],x['key_id']))
    return seal_mapping({'contract_id':GOSSIP_HEAD_QUORUM_CONFIG_CONTRACT_ID,'config_id':config_id,'authority_set_id':authority_set_id,'store_id':store_id,'threshold':threshold,'authorities':rows,'valid_from':valid_from,'valid_until':valid_until,'config_sha256':''},'config_sha256')

def validate_gossip_head_quorum_config(value:Any,evaluation_tick:int|None=None)->dict[str,Any]:
    errors=[]
    if not isinstance(value,Mapping): return {'status':'BLOCK','errors':[{'code':'invalid_type','path':'config','message':'mapping required'}]}
    try: c=materialize_json(value)
    except Exception as exc: return {'status':'BLOCK','errors':[{'code':'materialization_failed','path':'config','message':type(exc).__name__}]}
    if c.get('contract_id')!=GOSSIP_HEAD_QUORUM_CONFIG_CONTRACT_ID: errors.append({'code':'invalid_contract_id','path':'config.contract_id','message':GOSSIP_HEAD_QUORUM_CONFIG_CONTRACT_ID})
    if not verify_sealed_mapping(c,'config_sha256'): errors.append({'code':'digest_mismatch','path':'config.config_sha256','message':'canonical digest mismatch'})
    for f in ('config_id','authority_set_id','store_id'):
        if not isinstance(c.get(f),str) or not c.get(f): errors.append({'code':f'invalid_{f}','path':f'config.{f}','message':'non-empty string required'})
    rows=c.get('authorities'); threshold=c.get('threshold')
    if type(threshold) is not int or threshold<2: errors.append({'code':'invalid_threshold','path':'config.threshold','message':'integer >= 2 required'})
    if not isinstance(rows,list) or not rows: rows=[]; errors.append({'code':'invalid_authorities','path':'config.authorities','message':'non-empty array required'})
    seen={f:set() for f in ('authority_id','service_id','signer_id','key_id')}; domains=set()
    for i,row in enumerate(rows):
        if not isinstance(row,dict): errors.append({'code':'invalid_authority','path':f'config.authorities[{i}]','message':'object required'}); continue
        for f in ('authority_id','service_id','signer_id','key_id','trust_domain'):
            v=row.get(f)
            if not isinstance(v,str) or not v: errors.append({'code':f'invalid_{f}','path':f'config.authorities[{i}].{f}','message':'non-empty string required'})
        for f in seen:
            if row.get(f) in seen[f]: errors.append({'code':f'duplicate_{f}','path':f'config.authorities[{i}].{f}','message':str(row.get(f))})
            seen[f].add(row.get(f))
        domains.add(row.get('trust_domain'))
    if type(threshold) is int and len(rows)<threshold: errors.append({'code':'threshold_exceeds_members','path':'config.threshold','message':str(threshold)})
    if type(threshold) is int and len(domains)<threshold: errors.append({'code':'insufficient_domain_diversity','path':'config.authorities','message':str(len(domains))})
    vf,vu=c.get('valid_from'),c.get('valid_until')
    if type(vf) is not int or type(vu) is not int or vf<0 or vu<=vf: errors.append({'code':'invalid_validity_window','path':'config','message':'valid_from < valid_until required'})
    if evaluation_tick is not None and type(vf) is int and type(vu) is int and not (vf<=evaluation_tick<vu): errors.append({'code':'config_not_current','path':'config','message':str(evaluation_tick)})
    return {'status':'PASS' if not errors else 'BLOCK','errors':errors,'config':c}

def enforce_external_gossip_head_quorum(*,gossip_store:SQLitePolicyTransparencyGossipStore,store_id:str,signed_checkpoint:Mapping[str,Any],signed_head_responses:Sequence[Mapping[str,Any]],checkpoint_registry:TrustKeyRegistry,authority_registry:TrustKeyRegistry,expected_checkpoint_signer_id:str,expected_checkpoint_trust_domain:str,quorum_config:Mapping[str,Any],expected_quorum_config_sha256:str,challenge_ledger:SQLiteEpochChallengeLedger,expected_challenge:str,evaluation_tick:int,max_response_age:int=5)->dict[str,Any]:
    cfgv=validate_gossip_head_quorum_config(quorum_config,evaluation_tick)
    if cfgv['status']!='PASS': raise PolicyHeadAuthorityError('invalid_gossip_head_quorum_config',str(cfgv['errors']))
    cfg=cfgv['config']
    if cfg['config_sha256']!=expected_quorum_config_sha256: raise PolicyHeadAuthorityError('gossip_head_quorum_config_substitution',cfg['config_sha256'])
    if cfg['store_id']!=store_id: raise PolicyHeadAuthorityError('gossip_head_quorum_store_mismatch',cfg['store_id'])
    cpv=verify_contract_envelope(signed_checkpoint,registry=checkpoint_registry,evaluation_tick=evaluation_tick,expected_purpose=PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT,expected_digest_field='checkpoint_sha256',expected_inner_contract_id=GOSSIP_CHECKPOINT_CONTRACT_ID,expected_signer_id=expected_checkpoint_signer_id,expected_trust_domain=expected_checkpoint_trust_domain)
    if cpv['status']!='PASS': raise PolicyHeadAuthorityError('invalid_local_gossip_checkpoint',str(cpv['errors']))
    cp=cpv['inner_contract']; challenge=challenge_ledger.inspect_issued(expected_challenge,evaluation_tick)
    members={x['signer_id']:x for x in cfg['authorities']}; groups=defaultdict(list); seen={}; seen_keys=set(); invalid=[]
    for i,signed in enumerate(signed_head_responses):
        hv=verify_contract_envelope(signed,registry=authority_registry,evaluation_tick=evaluation_tick,expected_purpose=PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY,expected_digest_field='response_sha256',expected_inner_contract_id=GOSSIP_HEAD_RESPONSE_CONTRACT_ID)
        if hv['status']!='PASS': invalid.append((i,'signature')); continue
        signer=hv['verified_signer']; row=members.get(signer.signer_id)
        if row is None or signer.key_id!=row['key_id'] or signer.trust_domain!=row['trust_domain']: invalid.append((i,'identity')); continue
        h=hv['inner_contract']
        if h['authority_id']!=row['authority_id'] or h['service_id']!=row['service_id'] or h['store_id']!=store_id: invalid.append((i,'binding')); continue
        if h['verifier_id']!=challenge_ledger.session.verifier_id or h['verifier_epoch_sha256']!=challenge_ledger.session.epoch_sha256 or h['challenge_sha256']!=challenge['challenge_sha256'] or h['requested_at']!=challenge['issued_at']: invalid.append((i,'challenge')); continue
        if evaluation_tick-h['issued_at']>max_response_age: invalid.append((i,'age')); continue
        statement=(h['checkpoint_sequence'],h['checkpoint_sha256'],h['gossip_sequence'],h['gossip_state_sha256'],h['pins_root_sha256'],h['verifier_id'],h['verifier_epoch_sha256'],h['challenge_sha256'],h['requested_at'])
        prev=seen.get(signer.signer_id)
        if prev is not None:
            if prev!=statement: raise PolicyHeadAuthorityError('gossip_head_authority_equivocation',signer.signer_id)
            continue
        if signer.key_id in seen_keys: raise PolicyHeadAuthorityError('duplicate_gossip_head_authority_key',signer.key_id)
        seen[signer.signer_id]=statement; seen_keys.add(signer.key_id); groups[statement].append(row)
    threshold=cfg['threshold']; quorums=[]
    for st,rows in groups.items():
        if len(rows)>=threshold and all(len({r[f] for r in rows})>=threshold for f in ('authority_id','service_id','signer_id','key_id','trust_domain')): quorums.append((st,rows))
    if not quorums: raise PolicyHeadAuthorityError('gossip_head_authority_quorum_not_met',f'threshold={threshold} valid={len(seen)} invalid={len(invalid)}')
    if len(quorums)>1: raise PolicyHeadAuthorityError('multiple_gossip_head_authority_quorums',str(len(quorums)))
    st,rows=quorums[0]
    for field,expected in zip(('checkpoint_sequence','checkpoint_sha256','gossip_sequence','gossip_state_sha256','pins_root_sha256'),st[:5]):
        if cp[field]!=expected: raise PolicyHeadAuthorityError('gossip_head_checkpoint_mismatch',field)
    local=export_gossip_state(gossip_store,store_id=store_id)
    if local['gossip_sequence']!=cp['gossip_sequence'] or local['state_sha256']!=cp['gossip_state_sha256'] or local['pins_root_sha256']!=cp['pins_root_sha256']: raise PolicyHeadAuthorityError('local_gossip_state_rollback_detected',f"local={local['gossip_sequence']} checkpoint={cp['gossip_sequence']}")
    challenge_ledger.consume(expected_challenge,evaluation_tick)
    return {'status':'PASS','gossip_state':local,'checkpoint':cp,'quorum':{'config_id':cfg['config_id'],'config_sha256':cfg['config_sha256'],'threshold':threshold,'members':rows}}

__all__=['GOSSIP_HEAD_QUORUM_CONFIG_CONTRACT_ID','make_gossip_head_quorum_config','validate_gossip_head_quorum_config','enforce_external_gossip_head_quorum']
