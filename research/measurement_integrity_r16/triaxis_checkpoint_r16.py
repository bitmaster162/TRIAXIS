#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

SCHEMA="triaxis.r16a.external_ledger_checkpoint/v1"

def sha256_file(path:Path)->str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def ledger_count(path:Path)->int:
    obj=json.loads(path.read_text(encoding="utf-8"))
    s=obj.get("summary",{})
    for key in ("transactions_recorded","events_recorded"):
        if isinstance(s.get(key),int):
            return s[key]
    raise ValueError("ledger summary lacks transaction/event count")

def make_checkpoint(ledger:Path, *, epoch:str, sequence:int, previous_checkpoint_sha256:str|None=None, witness:str)->dict:
    if sequence < 1: raise ValueError("sequence must be >=1")
    return {
      "schema":SCHEMA,
      "epoch":epoch,
      "sequence":sequence,
      "ledger_sha256":sha256_file(ledger),
      "ledger_count":ledger_count(ledger),
      "previous_checkpoint_sha256":previous_checkpoint_sha256,
      "witness":witness,
    }

def verify(ledger:Path, checkpoint:dict, previous_checkpoint:dict|None=None)->dict:
    errors=[]
    if checkpoint.get("schema")!=SCHEMA: errors.append("BAD_CHECKPOINT_SCHEMA")
    actual_sha=sha256_file(ledger)
    actual_count=ledger_count(ledger)
    if actual_sha!=checkpoint.get("ledger_sha256"): errors.append("LEDGER_HASH_MISMATCH")
    if actual_count!=checkpoint.get("ledger_count"): errors.append("LEDGER_COUNT_MISMATCH")

    if previous_checkpoint is not None:
        prev_sha=hashlib.sha256(
            (json.dumps(previous_checkpoint,ensure_ascii=False,sort_keys=True)+"\n").encode("utf-8")
        ).hexdigest()
        if checkpoint.get("previous_checkpoint_sha256")!=prev_sha:
            errors.append("PREVIOUS_CHECKPOINT_HASH_MISMATCH")
        if checkpoint.get("sequence")!=previous_checkpoint.get("sequence",0)+1:
            errors.append("NON_MONOTONIC_SEQUENCE")
        if checkpoint.get("ledger_count",0)<previous_checkpoint.get("ledger_count",0):
            errors.append("LEDGER_COUNT_ROLLBACK")

    return {
      "status":"PASS" if not errors else "FAIL",
      "errors":errors,
      "actual_ledger_sha256":actual_sha,
      "actual_ledger_count":actual_count,
      "checkpoint_ledger_sha256":checkpoint.get("ledger_sha256"),
      "checkpoint_ledger_count":checkpoint.get("ledger_count"),
      "checkpoint_sequence":checkpoint.get("sequence"),
    }

def canonical_checkpoint_sha256(checkpoint:dict)->str:
    return hashlib.sha256(
        (json.dumps(checkpoint,ensure_ascii=False,sort_keys=True)+"\n").encode("utf-8")
    ).hexdigest()

def main()->int:
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd",required=True)
    m=sub.add_parser("make")
    m.add_argument("ledger",type=Path); m.add_argument("-o","--output",type=Path,required=True)
    m.add_argument("--epoch",required=True); m.add_argument("--sequence",type=int,required=True)
    m.add_argument("--previous-checkpoint-sha256"); m.add_argument("--witness",required=True)
    v=sub.add_parser("verify")
    v.add_argument("ledger",type=Path); v.add_argument("checkpoint",type=Path); v.add_argument("--previous",type=Path)
    a=ap.parse_args()
    if a.cmd=="make":
        c=make_checkpoint(a.ledger,epoch=a.epoch,sequence=a.sequence,
                          previous_checkpoint_sha256=a.previous_checkpoint_sha256,witness=a.witness)
        a.output.write_text(json.dumps(c,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(canonical_checkpoint_sha256(c)); return 0
    c=json.loads(a.checkpoint.read_text(encoding="utf-8"))
    p=json.loads(a.previous.read_text(encoding="utf-8")) if a.previous else None
    out=verify(a.ledger,c,p); print(json.dumps(out,ensure_ascii=False,sort_keys=True))
    return 0 if out["status"]=="PASS" else 2

if __name__=="__main__": raise SystemExit(main())
