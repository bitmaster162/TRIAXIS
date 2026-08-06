from __future__ import annotations
import json, tempfile, unittest
from contextlib import ExitStack
from pathlib import Path
from jsonschema import Draft202012Validator
from tests.test_v3_16_external_gossip_head import ExternalGossipHeadFixture
from triaxis.policy_transparency_gossip_head import export_gossip_state

class ExternalGossipHeadSchemaTests(unittest.TestCase):
    def test_schemas_accept_reference_contracts_and_trust_purposes(self):
        fx=ExternalGossipHeadFixture()
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp); gossip=fx.populate(stack,root/"current",2)
            issuer=fx.issuer(stack,root/"current",gossip); cp=issuer.issue(issued_at=10,valid_until=100)
            authority=fx.authority(stack,root); authority.install(cp,10)
            from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession
            session=VerifierFreshnessSession.create("verifier:schema",11)
            ledger=stack.enter_context(SQLiteEpochChallengeLedger(root/"schema.db",session)); challenge=ledger.issue(11,30)
            head=authority.issue_head(store_id=fx.store_id,challenge=challenge,verifier_id=session.verifier_id,verifier_epoch_sha256=session.epoch_sha256,requested_at=11,issued_at=12,valid_until=30)
            contracts=[
                ("triaxis_policy_transparency_gossip_state_v1.schema.json", export_gossip_state(gossip,store_id=fx.store_id)),
                ("triaxis_policy_transparency_gossip_checkpoint_v1.schema.json", cp["inner_contract"]),
                ("triaxis_policy_transparency_gossip_head_response_v1.schema.json", head["inner_contract"]),
            ]
        for name,value in contracts:
            schema=json.loads((Path("schemas")/name).read_text()); Draft202012Validator.check_schema(schema); Draft202012Validator(schema).validate(value)
        trust=json.loads(Path("schemas/triaxis_ed25519_trust_key_v1.schema.json").read_text())
        purposes=trust["properties"]["purposes"]["items"]["enum"]
        self.assertIn("POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT",purposes)
        self.assertIn("POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY",purposes)
if __name__=="__main__": unittest.main()
