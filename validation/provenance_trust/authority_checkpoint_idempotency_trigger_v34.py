"""Post-product unknown-outcome retry trigger for exact TRIAXIS v2.40."""
from __future__ import annotations
import argparse, json, tempfile
from pathlib import Path
from typing import Any, Callable, Mapping
from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope

PROTOCOL_ID="TRIAXIS_AUTHORITY_CHECKPOINT_IDEMPOTENCY_TRIGGER_v3.4_RECOVERY"
CANDIDATE_COMMIT="b16e203b8cf8280e09c5b897d5edf7dd87e760f1"
CANDIDATE_TREE="51749687a5e5b11e09e59d106277287134b35ba0"
NS="triaxis:test:idempotency"

def root(): return build_snapshot_authority_root(valid_until=200)
def bundle(tick:int,run_id:str="main"):
 return _bind(build_valid_analysis_bundle_v5(run_id=f"idem-{run_id}-{tick}",control_profile="A3",evaluation_tick=tick),REVIEW_REF)
def envelope(b:Mapping[str,Any],tick:int,seq:int,parent):
 return seal_snapshot_envelope(build_trust_fixture_v2(b,evaluation_tick=tick).snapshot,sequence=seq,previous_envelope_sha256=parent,issued_at=tick,valid_until=200)
def chain(run_id:str="main"):
 b1=bundle(5,"base");e1=envelope(b1,5,1,None);g=ProvenanceTrustStateGuard(authority_roots=[root()]);s=AuthorityAnalysisSession(trust_guard=g)
 if s.validate(b1,trust_envelope=e1,trusted_evaluation_tick=5).get("status")!="PASS": raise AssertionError("genesis")
 c1=g.checkpoint.as_dict();b2=bundle(6,run_id);e2=envelope(b2,6,2,e1["envelope_sha256"])
 if s.validate(b2,trust_envelope=e2,trusted_evaluation_tick=6).get("status")!="PASS": raise AssertionError("successor")
 return {"c1":c1,"e1":e1,"c2":g.checkpoint.as_dict(),"e2":e2}
def commit(st,c,e,prev): return st.commit(checkpoint_receipt=c,trust_envelope=e,authority_roots=[root()],expected_previous_head=prev)
def err(fn):
 try: fn()
 except CheckpointStoreError as e: return "BLOCK",[e.code]
 except Exception as e: return "EXCEPTION",[type(e).__name__]
 return "PASS",[]
def ok(v,code): return ("PASS",[]) if v else ("FAIL",[code])
def fixture(path:Path):
 ch=chain();st=SQLiteCheckpointStore(path,namespace=NS);h1=commit(st,ch["c1"],ch["e1"],None);h2=commit(st,ch["c2"],ch["e2"],h1);return ch,st,h1,h2

def genesis_retry():
 with tempfile.TemporaryDirectory() as td:
  ch=chain();st=SQLiteCheckpointStore(Path(td)/"s.db",namespace=NS);h=commit(st,ch["c1"],ch["e1"],None)
  try: again=commit(st,ch["c1"],ch["e1"],None)
  except CheckpointStoreError as e:return "BLOCK",[e.code]
  return ok(again==h and len(st.history())==1,"genesis_retry_not_idempotent")
def successor_retry():
 with tempfile.TemporaryDirectory() as td:
  ch,st,h1,h2=fixture(Path(td)/"s.db")
  try: again=commit(st,ch["c2"],ch["e2"],h1)
  except CheckpointStoreError as e:return "BLOCK",[e.code]
  return ok(again==h2 and len(st.history())==2,"successor_retry_not_idempotent")
def reopen_retry():
 with tempfile.TemporaryDirectory() as td:
  path=Path(td)/"s.db";ch,st,h1,h2=fixture(path);st.close();st=SQLiteCheckpointStore(path,namespace=NS)
  try: again=commit(st,ch["c2"],ch["e2"],h1)
  except CheckpointStoreError as e:return "BLOCK",[e.code]
  return ok(again==h2 and len(st.history())==2,"reopen_retry_not_idempotent")
def second_handle_retry():
 with tempfile.TemporaryDirectory() as td:
  path=Path(td)/"s.db";ch,st,h1,h2=fixture(path);other=SQLiteCheckpointStore(path,namespace=NS)
  try: again=commit(other,ch["c2"],ch["e2"],h1)
  except CheckpointStoreError as e:return "BLOCK",[e.code]
  return ok(again==h2 and len(other.history())==2,"second_handle_retry_not_idempotent")
def exact_wrong_predecessor():
 with tempfile.TemporaryDirectory() as td:
  ch,st,_,_=fixture(Path(td)/"s.db");return err(lambda:commit(st,ch["c2"],ch["e2"],"f"*64))
def competing_successor():
 with tempfile.TemporaryDirectory() as td:
  path=Path(td)/"s.db";ch,st,h1,_=fixture(path);alt=chain("alternate");before=st.get_current();hist=st.history()
  status,codes=err(lambda:commit(st,alt["c2"],alt["e2"],h1))
  if st.get_current()!=before or st.history()!=hist:return "FAIL",["competing_successor_mutated_state"]
  return status,codes

def row(cid,desc,check:Callable[[],tuple[str,list[str]]],es,ec,pc):
 try:a,c=check();x=None
 except Exception as e:a,c,x="EXCEPTION",[],f"{type(e).__name__}: {e}"
 return {"protocol_id":PROTOCOL_ID,"candidate_commit":CANDIDATE_COMMIT,"candidate_tree":CANDIDATE_TREE,"case_id":cid,"family":"checkpoint_idempotency","description":desc,"positive_control":pc,"expected_status":es,"actual_status":a,"expected_error_codes":sorted(ec),"actual_error_codes":sorted(c),"exception":x,"pass":a==es and sorted(c)==sorted(ec) and x is None}
def run_trigger():
 ch=chain()
 def control_store():
  with tempfile.TemporaryDirectory() as td:
   _,st,h1,h2=fixture(Path(td)/"s.db");return ok(h1==ch["c1"]["checkpoint_sha256"] and h2==ch["c2"]["checkpoint_sha256"],"commit_control")
 def control_load():
  with tempfile.TemporaryDirectory() as td:
   _,st,_,h2=fixture(Path(td)/"s.db");g=st.load_guard(authority_roots=[root()],expected_checkpoint_sha256=h2);return ok(g.checkpoint.as_dict()==ch["c2"],"load_control")
 def control_history():
  with tempfile.TemporaryDirectory() as td:
   _,st,_,_=fixture(Path(td)/"s.db");return ok([x["receipt"]["sequence"] for x in st.history()]==[1,2],"history_control")
 def control_stale():
  with tempfile.TemporaryDirectory() as td:
   _,st,_,_=fixture(Path(td)/"s.db");return err(lambda:commit(st,ch["c2"],ch["e2"],"0"*64))
 rows=[
  row("ID34-P01","Genesis and successor commit normally",control_store,"PASS",[],True),
  row("ID34-P02","Exact durable head reopens normally",control_load,"PASS",[],True),
  row("ID34-P03","History remains ordered and complete",control_history,"PASS",[],True),
  row("ID34-P04","A stale non-exact writer remains blocked",control_stale,"BLOCK",["checkpoint_store_cas_mismatch"],True),
  row("ID34-N01","Exact genesis retry reconciles as already committed",genesis_retry,"PASS",[],False),
  row("ID34-N02","Exact successor retry reconciles as already committed",successor_retry,"PASS",[],False),
  row("ID34-N03","Exact retry remains idempotent after clean reopen",reopen_retry,"PASS",[],False),
  row("ID34-N04","A second store handle reconciles the exact committed successor",second_handle_retry,"PASS",[],False),
  row("ID34-N05","Exact current pair with a false predecessor claim is blocked",exact_wrong_predecessor,"BLOCK",["checkpoint_store_cas_mismatch"],False),
  row("ID34-N06","Different successor from the same predecessor is blocked state-neutrally",competing_successor,"BLOCK",["checkpoint_store_cas_mismatch"],False),
 ]
 p=sum(r["pass"] for r in rows);pc=sum(r["positive_control"] for r in rows);pp=sum(r["positive_control"] and r["pass"] for r in rows)
 return {"protocol_id":PROTOCOL_ID,"candidate_commit":CANDIDATE_COMMIT,"candidate_tree":CANDIDATE_TREE,"case_count":len(rows),"pass_count":p,"fail_count":len(rows)-p,"positive_control_count":pc,"positive_control_pass_count":pp,"status":"PASS" if p==len(rows) else "FAIL","rows_sha256":canonical_sha256(rows),"rows":rows}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--jsonl",type=Path);ap.add_argument("--summary",type=Path);a=ap.parse_args();r=run_trigger()
 if a.jsonl:a.jsonl.parent.mkdir(parents=True,exist_ok=True);a.jsonl.write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in r["rows"]),encoding="utf-8")
 s={k:v for k,v in r.items() if k!="rows"}
 if a.summary:a.summary.parent.mkdir(parents=True,exist_ok=True);a.summary.write_text(json.dumps(s,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print(json.dumps(s,indent=2,sort_keys=True));return 0 if r["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
