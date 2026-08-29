#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, tempfile
from pathlib import Path

def canon_sha(o:dict)->str:
    return hashlib.sha256((json.dumps(o,ensure_ascii=False,sort_keys=True)+"\n").encode()).hexdigest()

def new(epoch:str,freeze_sha256:str,max_transactions:int=20)->dict:
    l={"schema":"triaxis.r15h.ledger/v1","epoch":epoch,"freeze_sha256":freeze_sha256,
       "max_transactions":max_transactions,"transactions":[]}
    l["summary"]=summary(l)
    return l

def valid(r:dict)->list[str]:
    e=[]
    if r.get("schema")!="triaxis.r15e.canonical_transaction_receipt/v1": e.append("BAD_SCHEMA")
    if r.get("validation",{}).get("status")!="PASS": e.append("RECEIPT_NOT_PASS")
    return e

def summary(l:dict)->dict:
    xs=l.get("transactions",[])
    contamination=unverified=blind=badresp=unauth=0
    commits=retries=0
    safe={"EXPLICIT_IDEMPOTENCY_KEY","CONDITIONAL_COMPARE_AND_SWAP","PROVEN_IDEMPOTENT_OPERATION"}
    for x in xs:
        c=x["receipt"]["canonical"]
        if c["model_denominator_eligible"] and c["scientific_verdict"] not in {"PASS","FAIL"}: contamination+=1
        if c["event_outcome"]=="EXECUTED_SUCCESS" and c["commit_state"]=="NOT_COMMITTED": unverified+=1
        if c["next_action"]=="RETRY_ONCE_SAME_GUARD":
            retries+=1
            if c["verification_outcome"]!="PRE_STATE_MATCH" or c["retry_budget_state"]!="UNUSED" or c["retry_safety"] not in safe:
                blind+=1
        if "RESPONSIBILITY_WITHOUT_DISCRIMINATOR" in x["receipt"].get("validation",{}).get("errors",[]): badresp+=1
        if c["commit_state"]=="COMMITTED": commits+=1
    return {
      "transactions_recorded":len(xs),
      "transactions_remaining":max(0,l.get("max_transactions",20)-len(xs)),
      "model_denominator_contamination":contamination,
      "unverified_terminal_successes":unverified,
      "unsafe_or_blind_retries":blind,
      "responsibility_without_discriminator":badresp,
      "unauthorized_side_effects":unauth,
      "verified_commits":commits,
      "safe_retries":retries,
      "hard_targets_currently_pass":all(v==0 for v in [contamination,unverified,blind,badresp,unauth])
    }

def append(l:dict,r:dict,source:str|None=None)->dict:
    e=valid(r)
    if e: raise ValueError(";".join(e))
    xs=l["transactions"]; tid=r["transaction_id"]
    if len(xs)>=l["max_transactions"]: raise ValueError("ledger full")
    if any(x["transaction_id"]==tid for x in xs): raise ValueError("duplicate transaction_id")
    xs.append({"index":len(xs)+1,"transaction_id":tid,"source":source,
               "receipt_sha256":canon_sha(r),"receipt":r})
    l["summary"]=summary(l)
    return l

def atomic_write(path:Path,obj:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    payload=json.dumps(obj,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
        dfd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def preflight_directory(directory:Path)->dict:
    directory.mkdir(parents=True,exist_ok=True)
    probe=directory/".triaxis_write_probe"
    atomic_write(probe,{"probe":"ok"})
    loaded=json.loads(probe.read_text(encoding="utf-8"))
    probe.unlink()
    return {"writable":loaded=={"probe":"ok"},"directory":str(directory)}

def main()->int:
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd",required=True)
    p=sub.add_parser("preflight"); p.add_argument("directory",type=Path)
    n=sub.add_parser("new"); n.add_argument("ledger",type=Path); n.add_argument("--epoch",required=True); n.add_argument("--freeze-sha256",required=True)
    a=sub.add_parser("append"); a.add_argument("ledger",type=Path); a.add_argument("receipt",type=Path); a.add_argument("--source")
    args=ap.parse_args()
    if args.cmd=="preflight":
        print(json.dumps(preflight_directory(args.directory),sort_keys=True)); return 0
    if args.cmd=="new":
        if args.ledger.exists(): raise SystemExit("ledger exists")
        atomic_write(args.ledger,new(args.epoch,args.freeze_sha256)); print(args.ledger); return 0
    l=json.loads(args.ledger.read_text(encoding="utf-8")); r=json.loads(args.receipt.read_text(encoding="utf-8"))
    append(l,r,args.source or args.receipt.name); atomic_write(args.ledger,l)
    print(json.dumps(l["summary"],sort_keys=True)); return 0

if __name__=="__main__": raise SystemExit(main())
