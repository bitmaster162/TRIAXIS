import unittest
from validation.TRIAXIS_EXTERNAL_GOSSIP_HEAD_QUORUM_TRIGGER_v1 import run_trigger
class V317TriggerTests(unittest.TestCase):
 def test_trigger(self):
  x=run_trigger();self.assertEqual(x['status'],'PASS');self.assertEqual(x['pass_count'],x['case_count'])
if __name__=='__main__':unittest.main()
