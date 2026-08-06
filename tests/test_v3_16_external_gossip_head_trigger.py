import unittest
from validation.TRIAXIS_EXTERNAL_GOSSIP_HEAD_TRIGGER_v1 import run_trigger
class V316TriggerTests(unittest.TestCase):
    def test_trigger_closes_all_cases(self):
        result=run_trigger(); self.assertEqual(result["status"],"PASS"); self.assertEqual(result["pass_count"],result["case_count"])
if __name__=="__main__": unittest.main()
