"""Post-product crash-atomicity trigger for exact TRIAXIS v2.41."""
from __future__ import annotations
import argparse, json, os, subprocess, sys, tempfile
from pathlib import Path
from typing import Any, Callable, Mapping
from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope
PROTOCOL_ID="TRIAXIS_AUTHORITY_CHECKPOINT_CRASH_ATOMICITY_TRIGGER_v3.5_RECOVERY"
CANDIDATE_COMMIT="9ef3a3850278a45eddfc15361f0e9955cb746d70"
CANDIDATE_TREE="f487f5bec1185077f447e092be389a6d7ea93a59"
NS="triaxis:test:crash"
EXIT_BY_POINT={"after_history":71,"after_current_update":72,"after_commit":73}
def root():return build_snapshot_authority_root(valid_until=200)
def bundle(t):return _bind(build_valid_analysis_bundle_v5(run_id=f"crash-{t}",control_profile="A3",evaluation_tick=t),REVIEW_REF)
def env(b,t,s,p):return seal_snapshot_envelope(build_trust_fixture_v2(b,evaluation_tick=t).snapshot,sequence=s,previous_envelope_sha256=p,issued_at=t,valid_until=200)
def chain():
 b1=bundle(5);e1=env(b1,5,1,None);g=ProvenanceTrustStateGuard(authority_roots=[root()]);session=AuthorityAnalysisSession(trust_guard=g)
 if session.validate(b1,trust_envelope=e1,trusted_evaluation_tick=5).get("status")!="PASS":raise AssertionError("genesis")
 c1=g.checkpoint.as_dict();b2=bundle(6);e2=env(b2,6,2,e1["envelope_sha256"])
 if session.validate(b2,trust_envelope=e2,trusted_evaluation_tick=6).get("status")!="PASS":raise AssertionError("successor")
 return {"c1":c1,"e1":e1,"c2":g.checkpoint.as_dict(),"e2":e2}
def commit(st,c,e,prev):return st.commit(checkpoint_receipt=c,trust_envelope=e,authority_roots=[root()],expected_previous_head=prev)
class CrashProxy:
 def __init__(self,inner,point):self.inner=inner;self.point=point
 def execute(self,sql,params=()):
  result=self.inner.execute(sql,params);norm=" ".join(str(sql).split()).upper()
  hit=(self.point=="after_history" and norm.startswith("INSERT INTO CHECKPOINT_HISTORY")) or (self.point=="after_current_update" and norm.startswith("UPDATE CHECKPOINT_CURRENT")) or (self.point=="after_commit" and norm=="COMMIT")
  if hit:os._exit(EXIT_BY_POINT[self.point])
  return result
 def __getattr__(self,name):return getattr(self.inner,name)
def worker(args):
 data=json.loads(Path(args.chain).read_text());st=SQLiteCheckpointStore(args.database,namespace=NS);st._conn=CrashProxy(st._conn,args.point)
 if args.mode=="genesis":commit(st,data["c1"],data["e1"],None)
 else:commit(st,data["c2"],data["e2"],data["c1"]["checkpoint_sha256"])
 return 99
def spawn(path,chain_path,mode,point):
 cp=subprocess.run([sys.executable,str(Path(__file__).resolve()),"--worker","--database",str(path),"--chain",str(chain_path),"--mode",mode,"--point",point],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env={**os.environ,"PYTHONPATH":os.environ.get("PYTHONPATH","src:.")})
 return cp.returncode,cp.stdout,cp.stderr
def inspect(path):
 with SQLiteCheckpointStore(path,namespace=NS) as st:return st.get_current(),st.history()
def crash_case(mode,point,expected):
 with tempfile.TemporaryDirectory(prefix="triaxis-v35-") as td:
  p=Path(td);db=p/"state.sqlite3";data=chain();cp=p/"chain.json";cp.write_text(json.dumps(data,sort_keys=True),encoding="utf-8")
  if mode=="successor":
   with SQLiteCheckpointStore(db,namespace=NS) as st:commit(st,data["c1"],data["e1"],None)
  rc,_,_=spawn(db,cp,mode,point)
  if rc!=EXIT_BY_POINT[point]:return "FAIL",[f"unexpected_worker_exit_{rc}"]
  current,hist=inspect(db)
  if expected=="empty":ok=current is None and hist==[]
  elif expected=="genesis":ok=current is not None and current["receipt"]==data["c1"] and [x["receipt"]["sequence"] for x in hist]==[1]
  else:ok=current is not None and current["receipt"]==data["c2"] and [x["receipt"]["sequence"] for x in hist]==[1,2]
  return ("PASS",[]) if ok else ("FAIL",["crash_recovery_mixed_state"])
def after_commit_retry():
 with tempfile.TemporaryDirectory(prefix="triaxis-v35-") as td:
  p=Path(td);db=p/"state.sqlite3";data=chain();cp=p/"chain.json";cp.write_text(json.dumps(data,sort_keys=True),encoding="utf-8")
  with SQLiteCheckpointStore(db,namespace=NS) as st:commit(st,data["c1"],data["e1"],None)
  rc,_,_=spawn(db,cp,"successor","after_commit")
  if rc!=73:return "FAIL",[f"unexpected_worker_exit_{rc}"]
  with SQLiteCheckpointStore(db,namespace=NS) as st:
   h=commit(st,data["c2"],data["e2"],data["c1"]["checkpoint_sha256"])
   return ("PASS",[]) if h==data["c2"]["checkpoint_sha256"] and len(st.history())==2 else ("FAIL",["post_commit_retry_failed"])
def normal_control():
 with tempfile.TemporaryDirectory() as td:
  d=chain();
  with SQLiteCheckpointStore(Path(td)/"s.db",namespace=NS) as st:
   h1=commit(st,d["c1"],d["e1"],None);h2=commit(st,d["c2"],d["e2"],h1);return ("PASS",[]) if h2==d["c2"]["checkpoint_sha256"] else ("FAIL",["normal_commit_failed"])
def reopen_control():
 with tempfile.TemporaryDirectory() as td:
  p=Path(td)/"s.db";d=chain();st=SQLiteCheckpointStore(p,namespace=NS);h=commit(st,d["c1"],d["e1"],None);st.close();st=SQLiteCheckpointStore(p,namespace=NS);g=st.load_guard(authority_roots=[root()],expected_checkpoint_sha256=h);st.close();return ("PASS",[]) if g.checkpoint.as_dict()==d["c1"] else ("FAIL",["reopen_failed"])
def idem_control():
 with tempfile.TemporaryDirectory() as td:
  d=chain();
  with SQLiteCheckpointStore(Path(td)/"s.db",namespace=NS) as st:
   h=commit(st,d["c1"],d["e1"],None);a=commit(st,d["c1"],d["e1"],None);return ("PASS",[]) if h==a and len(st.history())==1 else ("FAIL",["idempotency_failed"])
def cas_control():
 with tempfile.TemporaryDirectory() as td:
  d=chain();
  with SQLiteCheckpointStore(Path(td)/"s.db",namespace=NS) as st:
   commit(st,d["c1"],d["e1"],None)
   try:commit(st,d["c2"],d["e2"],"0"*64)
   except CheckpointStoreError as e:return "BLOCK",[e.code]
   return "PASS",[]
def row(cid,desc,fn:Callable[[],tuple[str,list[str]]],es,ec,pc):
 try:a,c=fn();x=None
 except Exception as e:a,c,x="EXCEPTION",[],f"{type(e).__name__}: {e}"
 return {"protocol_id":PROTOCOL_ID,"candidate_commit":CANDIDATE_COMMIT,"candidate_tree":CANDIDATE_TREE,"case_id":cid,"family":"checkpoint_crash_atomicity","description":desc,"positive_control":pc,"expected_status":es,"actual_status":a,"expected_error_codes":sorted(ec),"actual_error_codes":sorted(c),"exception":x,"pass":a==es and sorted(c)==sorted(ec) and x is None}
def run_trigger():
 rows=[row("CA35-P01","Normal genesis and successor commit",normal_control,"PASS",[],True),row("CA35-P02","Clean reopen authenticates durable genesis",reopen_control,"PASS",[],True),row("CA35-P03","Exact replay remains idempotent",idem_control,"PASS",[],True),row("CA35-P04","Stale writer remains blocked",cas_control,"BLOCK",["checkpoint_store_cas_mismatch"],True),row("CA35-N01","Genesis crash after history insert recovers empty state",lambda:crash_case("genesis","after_history","empty"),"PASS",[],False),row("CA35-N02","Successor crash after history insert recovers exact genesis",lambda:crash_case("successor","after_history","genesis"),"PASS",[],False),row("CA35-N03","Successor crash after current update but before commit recovers genesis",lambda:crash_case("successor","after_current_update","genesis"),"PASS",[],False),row("CA35-N04","Crash immediately after commit recovers exact successor",lambda:crash_case("successor","after_commit","successor"),"PASS",[],False),row("CA35-N05","After-commit unknown outcome reconciles exact retry",after_commit_retry,"PASS",[],False)]
 p=sum(r["pass"] for r in rows);pc=sum(r["positive_control"] for r in rows);pp=sum(r["positive_control"] and r["pass"] for r in rows)
 return {"protocol_id":PROTOCOL_ID,"candidate_commit":CANDIDATE_COMMIT,"candidate_tree":CANDIDATE_TREE,"case_count":len(rows),"pass_count":p,"fail_count":len(rows)-p,"positive_control_count":pc,"positive_control_pass_count":pp,"status":"PASS" if p==len(rows) else "FAIL","rows_sha256":canonical_sha256(rows),"rows":rows}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--jsonl",type=Path);ap.add_argument("--summary",type=Path);ap.add_argument("--worker",action="store_true");ap.add_argument("--database",type=Path);ap.add_argument("--chain",type=Path);ap.add_argument("--mode",choices=["genesis","successor"]);ap.add_argument("--point",choices=sorted(EXIT_BY_POINT));a=ap.parse_args()
 if a.worker:return worker(a)
 r=run_trigger();
 if a.jsonl:a.jsonl.parent.mkdir(parents=True,exist_ok=True);a.jsonl.write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in r["rows"]),encoding="utf-8")
 s={k:v for k,v in r.items() if k!="rows"}
 if a.summary:a.summary.parent.mkdir(parents=True,exist_ok=True);a.summary.write_text(json.dumps(s,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print(json.dumps(s,indent=2,sort_keys=True));return 0 if r["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
