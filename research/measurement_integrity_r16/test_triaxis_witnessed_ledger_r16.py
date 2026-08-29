import json,tempfile,unittest
from pathlib import Path
from triaxis_witnessed_ledger_r16 import *

def receipt(i):
    return {"schema":"example","transaction_id":f"t{i}","value":i}

class T(unittest.TestCase):
  def test_genesis_append_candidate(self):
    l=new_ledger("e")
    nl,c=append_candidate(l,receipt(1),None,witness_target="github:path")
    self.assertEqual(c["sequence"],1)
    self.assertEqual(c["ledger_count"],1)
    self.assertEqual(c["ledger_sha256"],ledger_hash_obj(nl))

  def test_confirm_exact_external(self):
    l=new_ledger("e")
    nl,c=append_candidate(l,receipt(1),None,witness_target="github:path")
    r=confirm_external_witness(nl,c,json.loads(json.dumps(c)))
    self.assertEqual(r["status"],"PASS")
    self.assertEqual(r["ledger"]["latest_witness"]["sequence"],1)

  def test_rollback_detected(self):
    l=new_ledger("e")
    nl,c=append_candidate(l,receipt(1),None,witness_target="github:path")
    confirmed=confirm_external_witness(nl,c,c)["ledger"]
    rolled=new_ledger("e")
    r=verify_prior_state(rolled,c)
    self.assertEqual(r["status"],"FAIL")
    self.assertEqual(r["state"],"LOCAL_ROLLBACK_DETECTED")

  def test_local_ahead_without_witness_fails(self):
    l=new_ledger("e")
    nl,c=append_candidate(l,receipt(1),None,witness_target="github:path")
    r=verify_prior_state(nl,None)
    self.assertEqual(r["status"],"FAIL")
    self.assertEqual(r["state"],"LOCAL_AHEAD_UNWITNESSED")

  def test_witness_fork_fails(self):
    l=new_ledger("e")
    nl,c=append_candidate(l,receipt(1),None,witness_target="github:path")
    bad=json.loads(json.dumps(c)); bad["ledger_sha256"]="0"*64
    r=confirm_external_witness(nl,c,bad)
    self.assertEqual(r["status"],"FAIL")

  def test_second_append_requires_prior_witness(self):
    l=new_ledger("e")
    l1,c1=append_candidate(l,receipt(1),None,witness_target="github:path")
    confirmed=confirm_external_witness(l1,c1,c1)["ledger"]
    l2,c2=append_candidate(confirmed,receipt(2),c1,witness_target="github:path")
    self.assertEqual(c2["sequence"],2)
    self.assertEqual(c2["previous_witness_sha256"],witness_sha(c1))
    self.assertEqual(c2["ledger_count"],2)

  def test_old_witness_against_new_ledger_fails(self):
    l=new_ledger("e")
    l1,c1=append_candidate(l,receipt(1),None,witness_target="github:path")
    confirmed=confirm_external_witness(l1,c1,c1)["ledger"]
    l2,c2=append_candidate(confirmed,receipt(2),c1,witness_target="github:path")
    r=verify_prior_state(l2,c1)
    self.assertEqual(r["status"],"FAIL")
    self.assertEqual(r["state"],"LOCAL_AHEAD_UNWITNESSED")

  def test_cli_end_to_end(self):
    import subprocess, sys
    with tempfile.TemporaryDirectory() as td:
      d=Path(td)
      ledger=d/"ledger.json"; rec=d/"receipt.json"; cand=d/"candidate.json"; fresh=d/"fresh.json"
      rec.write_text(json.dumps(receipt(1))+"\n")
      cmd=[sys.executable,str(Path(__file__).with_name("triaxis_witnessed_ledger_r16.py"))]
      p=subprocess.run(cmd+["new",str(ledger),"--epoch","e"],capture_output=True,text=True)
      self.assertEqual(p.returncode,0,p.stdout+p.stderr)
      p=subprocess.run(cmd+["append-candidate",str(ledger),str(rec),"--witness-target","github:x","--candidate-out",str(cand)],capture_output=True,text=True)
      self.assertEqual(p.returncode,0,p.stdout+p.stderr)
      fresh.write_bytes(cand.read_bytes())
      p=subprocess.run(cmd+["confirm",str(ledger),str(cand),str(fresh)],capture_output=True,text=True)
      self.assertEqual(p.returncode,0,p.stdout+p.stderr)
      p=subprocess.run(cmd+["verify-prior",str(ledger),"--witness",str(fresh)],capture_output=True,text=True)
      self.assertEqual(p.returncode,0,p.stdout+p.stderr)

  def test_cli_confirm_mismatch_fails(self):
    import subprocess, sys
    with tempfile.TemporaryDirectory() as td:
      d=Path(td)
      ledger=d/"ledger.json"; rec=d/"receipt.json"; cand=d/"candidate.json"; fresh=d/"fresh.json"
      rec.write_text(json.dumps(receipt(1))+"\n")
      cmd=[sys.executable,str(Path(__file__).with_name("triaxis_witnessed_ledger_r16.py"))]
      self.assertEqual(subprocess.run(cmd+["new",str(ledger),"--epoch","e"],capture_output=True).returncode,0)
      self.assertEqual(subprocess.run(cmd+["append-candidate",str(ledger),str(rec),"--witness-target","github:x","--candidate-out",str(cand)],capture_output=True).returncode,0)
      bad=json.loads(cand.read_text()); bad["ledger_sha256"]="0"*64
      fresh.write_text(json.dumps(bad)+"\n")
      p=subprocess.run(cmd+["confirm",str(ledger),str(cand),str(fresh)],capture_output=True,text=True)
      self.assertEqual(p.returncode,2)

if __name__=="__main__": unittest.main(verbosity=2)
