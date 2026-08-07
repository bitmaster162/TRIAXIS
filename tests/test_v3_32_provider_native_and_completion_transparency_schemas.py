from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from jsonschema import Draft202012Validator

from tests.test_v3_29_execution_head_quorum_and_completion_witness import B, make_intent
from tests.test_v3_31_availability_closed_and_immutable_anchor import identities_v331, open_immutable_anchor
from tests.test_v3_32_provider_native_and_completion_transparency import provider_native_fixture, transparency_fixture
from triaxis.completion_transparency_quorum import verify_completion_transparency_quorum
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

class V332SchemaTests(unittest.TestCase):
    def validate(self,name:str,value:dict)->None:
        schema=json.loads(Path('schemas',name).read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_provider_policy_schema(self):
        with tempfile.TemporaryDirectory() as td:
            _,_,_,policy=provider_native_fixture(td)
            self.validate('triaxis_provider_native_idempotency_policy_v1.schema.json',policy)

    def test_provider_event_schema(self):
        intent=make_intent()
        with tempfile.TemporaryDirectory() as td:
            _,_,provider,_=provider_native_fixture(td)
            result=provider.begin(effect_id=intent['effect_id'],payload_sha256=B,provider_request_id='req:schema',now_tick=1)
            self.validate('triaxis_provider_native_idempotency_event_v1.schema.json',result['signed_event']['inner_contract'])

    def test_provider_head_schema(self):
        with tempfile.TemporaryDirectory() as td:
            _,_,provider,_=provider_native_fixture(td)
            self.validate('triaxis_provider_native_idempotency_head_v1.schema.json',provider.signed_head(now_tick=1)['inner_contract'])

    def test_provider_status_schema(self):
        intent=make_intent()
        with tempfile.TemporaryDirectory() as td:
            _,_,provider,policy=provider_native_fixture(td)
            session=VerifierFreshnessSession.create('verifier:v332:schema:provider',0)
            signed=provider.signed_status(effect_id=intent['effect_id'],payload_sha256=B,challenge='challenge-provider-schema-0001',verifier_id=session.verifier_id,verifier_epoch_sha256=session.epoch_sha256,policy=policy,now_tick=1)
            self.validate('triaxis_provider_native_idempotency_status_v1.schema.json',signed['inner_contract'])

    def _transparency(self):
        ids=identities_v331(); td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup)
        anchor=open_immutable_anchor(f'{td.name}/anchor',ids); self.addCleanup(anchor.close)
        head=anchor.head(now_tick=10)
        rows,registry,authorities,config=transparency_fixture(ids,td.name)
        for a in authorities:
            self.addCleanup(a.close); a.observe_verified_head(head['inner_contract'],observed_at=10)
        session=VerifierFreshnessSession.create('verifier:v332:schema:transparency',0)
        ledger=SQLiteEpochChallengeLedger(':memory:',session); self.addCleanup(ledger.close)
        challenge=ledger.issue(1,100)
        responses=[a.signed_response(challenge=challenge,verifier_id=session.verifier_id,verifier_epoch_sha256=session.epoch_sha256,requested_at=1,now_tick=10) for a in authorities[:2]]
        result=verify_completion_transparency_quorum(head,responses,anchor_registry=ids['immutable_registry'],transparency_registry=registry,expected_anchor_id='completion-immutable-anchor:v331',expected_anchor_authority_id='authority:completion-immutable-anchor:v331',expected_anchor_service_id='service:completion-immutable-anchor:v331',expected_anchor_signer_id='signer:completion-immutable-anchor:v331',expected_anchor_trust_domain='domain:completion-immutable-anchor:v331',expected_provider_id='provider:v329:reference',expected_provider_service_id='service:provider:v329',expected_retention_policy_id='retention:completion:v331:high-risk',config=config,expected_config_sha256=config['config_sha256'],challenge_ledger=ledger,expected_challenge=challenge,evaluation_tick=10)
        return config,responses,result

    def test_transparency_config_schema(self):
        config,_,_=self._transparency(); self.validate('triaxis_completion_transparency_quorum_config_v1.schema.json',config)
    def test_transparency_response_schema(self):
        _,responses,_=self._transparency(); self.validate('triaxis_completion_transparency_response_v1.schema.json',responses[0]['inner_contract'])
    def test_transparency_witness_schema(self):
        _,_,result=self._transparency(); self.validate('triaxis_completion_transparency_quorum_witness_v1.schema.json',result['quorum_witness'])

if __name__=='__main__': unittest.main()
