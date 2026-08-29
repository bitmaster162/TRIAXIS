#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, tempfile
from pathlib import Path

LEDGER_SCHEMA="triaxis.r16b.witnessed_ledger/v1"
WITNESS_SCHEMA="triaxis.r16b.external_witness/v1"

def canonical_json_bytes(obj:dict)->bytes:
    return (json.dumps(obj,ensure_ascii=False,indent=2,sort_keys=True)+"\n").encode("utf-8")

def sha256_bytes(b:bytes)->str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(p:Path)->str:
    return sha256_bytes(p.read_bytes())

def atomic_write(path:Path,obj:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    payload=canonical_json_bytes(obj)
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=str(path.parent))
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
        dfd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def ledger_count(l:dict)->int:
    return len(l.get("transactions",[]))

def witnessed_state(l:dict)->dict:
    """State covered by the external witness.

    Local witness bookkeeping is intentionally excluded to avoid self-reference.
    """
    return {
      "schema":l.get("schema"),
      "epoch":l.get("epoch"),
      "transactions":l.get("transactions",[]),
    }

def ledger_hash_obj(l:dict)->str:
    return sha256_bytes(canonical_json_bytes(witnessed_state(l)))

def new_ledger(epoch:str)->dict:
    return {
      "schema":LEDGER_SCHEMA,
      "epoch":epoch,
      "transactions":[],
      "latest_witness":{"sequence":0,"ledger_count":0,"ledger_sha256":None,"witness_sha256":None},
      "pending_witness":None,
    }

def witness_sha(w:dict)->str:
    return sha256_bytes(canonical_json_bytes(w))

def make_witness_candidate(ledger:dict, *, sequence:int, previous_witness_sha256:str|None, witness_target:str)->dict:
    return {
      "schema":WITNESS_SCHEMA,
      "epoch":ledger["epoch"],
      "sequence":sequence,
      "ledger_count":ledger_count(ledger),
      "ledger_sha256":ledger_hash_obj(ledger),
      "previous_witness_sha256":previous_witness_sha256,
      "witness_target":witness_target,
    }

def verify_prior_state(ledger:dict, witness:dict|None)->dict:
    count=ledger_count(ledger)
    local_hash=ledger_hash_obj(ledger)
    if count==0 and witness is None:
        return {"status":"PASS","state":"GENESIS","errors":[]}

    if witness is None:
        return {"status":"FAIL","state":"LOCAL_AHEAD_UNWITNESSED","errors":["MISSING_EXTERNAL_WITNESS"]}

    errors=[]
    if witness.get("schema")!=WITNESS_SCHEMA: errors.append("BAD_WITNESS_SCHEMA")
    if witness.get("epoch")!=ledger.get("epoch"): errors.append("EPOCH_MISMATCH")
    wc=witness.get("ledger_count")
    wh=witness.get("ledger_sha256")
    if not isinstance(wc,int): errors.append("BAD_WITNESS_COUNT")
    if wc is not None:
        if count < wc: errors.append("LOCAL_ROLLBACK_BEHIND_WITNESS")
        elif count > wc: errors.append("LOCAL_AHEAD_OF_WITNESS")
    if wh!=local_hash: errors.append("LEDGER_HASH_MISMATCH")

    if errors:
        state="LOCAL_ROLLBACK_DETECTED" if "LOCAL_ROLLBACK_BEHIND_WITNESS" in errors else (
              "LOCAL_AHEAD_UNWITNESSED" if "LOCAL_AHEAD_OF_WITNESS" in errors else "WITNESS_FORK_OR_MISMATCH")
        return {"status":"FAIL","state":state,"errors":errors,
                "local_count":count,"witness_count":wc,"local_sha256":local_hash,"witness_sha256":wh}
    return {"status":"PASS","state":"WITNESSED","errors":[],
            "local_count":count,"witness_count":wc,"local_sha256":local_hash}

def append_candidate(ledger:dict, receipt:dict, prior_witness:dict|None, *, witness_target:str)->tuple[dict,dict]:
    if ledger.get("pending_witness") is not None:
        raise ValueError("pending external witness must be confirmed or reconciled first")
    prior=verify_prior_state(ledger,prior_witness)
    if prior["status"]!="PASS":
        raise ValueError("prior state not witnessed: "+",".join(prior["errors"]))

    txid=receipt.get("transaction_id")
    if not isinstance(txid,str) or not txid:
        raise ValueError("receipt transaction_id required")
    if any(x.get("transaction_id")==txid for x in ledger["transactions"]):
        raise ValueError("duplicate transaction_id")

    out=json.loads(json.dumps(ledger))
    out["transactions"].append({
      "index":len(out["transactions"])+1,
      "transaction_id":txid,
      "receipt_sha256":sha256_bytes(canonical_json_bytes(receipt)),
      "receipt":receipt,
    })
    prior_sha=witness_sha(prior_witness) if prior_witness else None
    sequence=(prior_witness.get("sequence",0)+1) if prior_witness else 1

    # IMPORTANT: witness hash must cover the stable ledger bytes without a self-referential pending field.
    out["latest_witness"]={
      "sequence":prior_witness.get("sequence",0) if prior_witness else 0,
      "ledger_count":prior_witness.get("ledger_count",0) if prior_witness else 0,
      "ledger_sha256":prior_witness.get("ledger_sha256") if prior_witness else None,
      "witness_sha256":prior_sha,
    }
    out["pending_witness"]=None
    candidate=make_witness_candidate(out,sequence=sequence,previous_witness_sha256=prior_sha,witness_target=witness_target)
    return out,candidate

def confirm_external_witness(ledger:dict, candidate:dict, fresh_external:dict)->dict:
    errors=[]
    if candidate!=fresh_external: errors.append("EXTERNAL_WITNESS_NOT_EXACT_CANDIDATE")
    if candidate.get("ledger_count")!=ledger_count(ledger): errors.append("CANDIDATE_COUNT_MISMATCH")
    if candidate.get("ledger_sha256")!=ledger_hash_obj(ledger): errors.append("CANDIDATE_HASH_MISMATCH")
    if errors:
        return {"status":"FAIL","state":"WITNESS_FORK_OR_MISMATCH","errors":errors}

    out=json.loads(json.dumps(ledger))
    out["latest_witness"]={
      "sequence":candidate["sequence"],
      "ledger_count":candidate["ledger_count"],
      "ledger_sha256":candidate["ledger_sha256"],
      "witness_sha256":witness_sha(candidate),
    }
    out["pending_witness"]=None
    return {"status":"PASS","state":"WITNESSED","errors":[],"ledger":out}

def main()->int:
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd",required=True)

    n=sub.add_parser("new")
    n.add_argument("ledger",type=Path); n.add_argument("--epoch",required=True)

    a=sub.add_parser("append-candidate")
    a.add_argument("ledger",type=Path); a.add_argument("receipt",type=Path)
    a.add_argument("--prior-witness",type=Path); a.add_argument("--witness-target",required=True)
    a.add_argument("--candidate-out",type=Path,required=True)

    v=sub.add_parser("verify-prior")
    v.add_argument("ledger",type=Path); v.add_argument("--witness",type=Path)

    c=sub.add_parser("confirm")
    c.add_argument("ledger",type=Path); c.add_argument("candidate",type=Path); c.add_argument("fresh_external",type=Path)

    args=ap.parse_args()
    if args.cmd=="new":
        atomic_write(args.ledger,new_ledger(args.epoch)); print(args.ledger); return 0
    l=json.loads(args.ledger.read_text(encoding="utf-8"))
    if args.cmd=="verify-prior":
        w=json.loads(args.witness.read_text(encoding="utf-8")) if args.witness else None
        r=verify_prior_state(l,w); print(json.dumps(r,sort_keys=True)); return 0 if r["status"]=="PASS" else 2
    if args.cmd=="append-candidate":
        r=json.loads(args.receipt.read_text(encoding="utf-8"))
        w=json.loads(args.prior_witness.read_text(encoding="utf-8")) if args.prior_witness else None
        nl,cand=append_candidate(l,r,w,witness_target=args.witness_target)
        atomic_write(args.ledger,nl); atomic_write(args.candidate_out,cand)
        print(json.dumps({"ledger_sha256":sha256_file(args.ledger),"candidate_sha256":sha256_file(args.candidate_out)},sort_keys=True)); return 0
    cand=json.loads(args.candidate.read_text(encoding="utf-8"))
    fresh=json.loads(args.fresh_external.read_text(encoding="utf-8"))
    result=confirm_external_witness(l,cand,fresh)
    print(json.dumps({k:v for k,v in result.items() if k!="ledger"},sort_keys=True))
    if result["status"]=="PASS":
        atomic_write(args.ledger,result["ledger"]); return 0
    return 2

if __name__=="__main__": raise SystemExit(main())
