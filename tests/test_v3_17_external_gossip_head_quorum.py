from __future__ import annotations
from contextlib import ExitStack
import tempfile, unittest
from pathlib import Path
from tests.test_v3_16_external_gossip_head import ExternalGossipHeadFixture
from triaxis.crypto_trust import PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY, TrustKeyRegistry, generate_ed25519_keypair, make_trust_key_record
from triaxis.policy_head_authority import PolicyHeadAuthorityError
from triaxis.policy_transparency_gossip_head import SQLiteGossipCheckpointIssuer, SQLiteGossipHeadAuthority
from triaxis.policy_transparency_gossip_head_quorum import enforce_external_gossip_head_quorum, make_gossip_head_quorum_config, validate_gossip_head_quorum_config
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

class GossipHeadQuorumFixture:
    def __init__(self):
        self.base=ExternalGossipHeadFixture(); self.authorities=[]; records=[]
        for s in ('a','b','c'):
            pair=generate_ed25519_keypair(); row={'authority_id':f'gossip-head-authority:{s}','service_id':f'gossip-head-service:{s}','key_id':f'key:gossip-head:{s}:1','signer_id':f'gossip-head-signer:{s}','trust_domain':f'domain:gossip-head:{s}','pair':pair}
            self.authorities.append(row); records.append(make_trust_key_record(key_id=row['key_id'],signer_id=row['signer_id'],trust_domain=row['trust_domain'],public_key_b64=pair['public_key_b64'],purposes=[PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY],valid_from=1,valid_until=1000))
        self.registry=TrustKeyRegistry(records)
        self.config=make_gossip_head_quorum_config(config_id='gossip-head-quorum:main',authority_set_id='gossip-head-set:primary',store_id=self.base.store_id,threshold=2,authorities=self.config_rows(),valid_from=1,valid_until=200)
        self.counter=0
    def config_rows(self): return [{k:r[k] for k in ('authority_id','service_id','signer_id','key_id','trust_domain')} for r in self.authorities]
    def checkpoints(self,stack,root):
        low=self.base.populate(stack,root/'low',2); high=self.base.populate(stack,root/'high',3)
        issuer1=self.base.issuer(stack,root/'issuer',low); cp1=issuer1.issue(issued_at=10,valid_until=100); issuer1.close()
        issuer2=stack.enter_context(SQLiteGossipCheckpointIssuer(root/'issuer'/'issuer.db',gossip_store=high,store_id=self.base.store_id,verifier_id='verifier:main',private_key_b64=self.base.checkpoint_pair['private_key_b64'],**self.base.checkpoint_identity)); cp2=issuer2.issue(issued_at=11,valid_until=100)
        return low,high,cp1,cp2
    def service(self,stack,root,index):
        row=self.authorities[index]; path=root/f'authority-{index}.db'
        return stack.enter_context(SQLiteGossipHeadAuthority(path,authority_id=row['authority_id'],service_id=row['service_id'],checkpoint_registry=self.base.checkpoint_registry,expected_checkpoint_signer_id=self.base.checkpoint_identity['signer_id'],expected_checkpoint_trust_domain=self.base.checkpoint_identity['trust_domain'],key_id=row['key_id'],signer_id=row['signer_id'],trust_domain=row['trust_domain'],private_key_b64=row['pair']['private_key_b64']))
    def verify(self,stack,root,gossip,cp,services,*,config=None,expected_digest=None):
        self.counter+=1; session=VerifierFreshnessSession.create(f'verifier:quorum:{self.counter}',20)
        ledger=stack.enter_context(SQLiteEpochChallengeLedger(root/f'q-{self.counter}.db',session)); challenge=ledger.issue(20,40)
        heads=[s.issue_head(store_id=self.base.store_id,challenge=challenge,verifier_id=session.verifier_id,verifier_epoch_sha256=session.epoch_sha256,requested_at=20,issued_at=21,valid_until=40) for s in services]
        return enforce_external_gossip_head_quorum(gossip_store=gossip,store_id=self.base.store_id,signed_checkpoint=cp,signed_head_responses=heads,checkpoint_registry=self.base.checkpoint_registry,authority_registry=self.registry,expected_checkpoint_signer_id=self.base.checkpoint_identity['signer_id'],expected_checkpoint_trust_domain=self.base.checkpoint_identity['trust_domain'],quorum_config=config or self.config,expected_quorum_config_sha256=expected_digest or self.config['config_sha256'],challenge_ledger=ledger,expected_challenge=challenge,evaluation_tick=21)

class GossipHeadQuorumTests(unittest.TestCase):
    def setUp(self): self.fx=GossipHeadQuorumFixture()
    def test_two_of_three_current_authorities_accept(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); _,high,cp1,cp2=self.fx.checkpoints(stack,root); services=[self.fx.service(stack,root,i) for i in range(3)]
            for s in services:
                s.install(cp1,12); s.install(cp2,13)
            result=self.fx.verify(stack,root,high,cp2,services[:2])
        self.assertEqual(len(result['quorum']['members']),2)
    def test_one_rolled_back_authority_cannot_override_two_current(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); _,high,cp1,cp2=self.fx.checkpoints(stack,root); services=[self.fx.service(stack,root,i) for i in range(3)]
            services[0].install(cp1,12); services[1].install(cp1,12); services[1].install(cp2,13); services[2].install(cp1,12); services[2].install(cp2,13)
            result=self.fx.verify(stack,root,high,cp2,services)
        self.assertEqual(result['checkpoint']['checkpoint_sha256'],cp2['inner_contract']['checkpoint_sha256'])
    def test_split_view_without_threshold_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); _,high,cp1,cp2=self.fx.checkpoints(stack,root); a=self.fx.service(stack,root,0); b=self.fx.service(stack,root,1); a.install(cp1,12); b.install(cp1,12); b.install(cp2,13)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:self.fx.verify(stack,root,high,cp2,[a,b])
        self.assertEqual(cm.exception.code,'gossip_head_authority_quorum_not_met')
    def test_duplicate_single_authority_does_not_form_quorum(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); _,high,cp1,cp2=self.fx.checkpoints(stack,root); a=self.fx.service(stack,root,0); a.install(cp1,12); a.install(cp2,13)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:self.fx.verify(stack,root,high,cp2,[a,a])
        self.assertEqual(cm.exception.code,'gossip_head_authority_quorum_not_met')
    def test_quorum_config_cannot_be_substituted(self):
        lower=make_gossip_head_quorum_config(config_id='gossip-head-quorum:main',authority_set_id='gossip-head-set:primary',store_id=self.fx.base.store_id,threshold=2,authorities=self.fx.config_rows(),valid_from=1,valid_until=200)
        strict=make_gossip_head_quorum_config(config_id='gossip-head-quorum:main',authority_set_id='gossip-head-set:primary',store_id=self.fx.base.store_id,threshold=3,authorities=self.fx.config_rows(),valid_from=1,valid_until=200)
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); _,high,cp1,cp2=self.fx.checkpoints(stack,root); services=[self.fx.service(stack,root,i) for i in range(2)]
            for s in services:
                s.install(cp1,12); s.install(cp2,13)
            with self.assertRaises(PolicyHeadAuthorityError) as cm:self.fx.verify(stack,root,high,cp2,services,config=lower,expected_digest=strict['config_sha256'])
        self.assertEqual(cm.exception.code,'gossip_head_quorum_config_substitution')
    def test_threshold_requires_distinct_trust_domains(self):
        rows=self.fx.config_rows(); rows[1]['trust_domain']=rows[0]['trust_domain']
        config=make_gossip_head_quorum_config(config_id='bad',authority_set_id='bad',store_id=self.fx.base.store_id,threshold=3,authorities=rows,valid_from=1,valid_until=200)
        result=validate_gossip_head_quorum_config(config,21)
        self.assertEqual(result['status'],'BLOCK'); self.assertIn('insufficient_domain_diversity',{e['code'] for e in result['errors']})
if __name__=='__main__': unittest.main()
