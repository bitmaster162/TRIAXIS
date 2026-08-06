import json, unittest
from pathlib import Path
from jsonschema import Draft202012Validator
from tests.test_v3_17_external_gossip_head_quorum import GossipHeadQuorumFixture
class GossipHeadQuorumSchemaTests(unittest.TestCase):
 def test_schema_accepts_reference_config(self):
  schema=json.loads(Path('schemas/triaxis_policy_transparency_gossip_head_quorum_config_v1.schema.json').read_text())
  Draft202012Validator.check_schema(schema); Draft202012Validator(schema).validate(GossipHeadQuorumFixture().config)
if __name__=='__main__':unittest.main()
