#!/usr/bin/env python3
import argparse, hashlib, json, os, subprocess, sys, time
from pathlib import Path
import requests

HERE=Path(__file__).resolve().parent
API="https://openrouter.ai/api/v1/chat/completions"
MODEL_DEFAULT="meta-llama/llama-3.2-3b-instruct:free"
ARMS={
  "H00_DIRECT": "Solve each case as accurately as possible from the supplied question. Follow the output format exactly.",
  "H01_SELF_CRITIQUE": "Solve each case. Then perform one concise self-check for arithmetic error or unsupported assumption. Correct only a concrete defect. Follow the output format exactly.",
  "H09_MVT_PROPOSER_VERIFIER": "For each case, propose an answer, then verify the load-bearing inference and strongest plausible failure. If a concrete defect is found, correct once; otherwise retain. Stop after one bounded verification cycle. Follow the output format exactly.",
  "H13_EBRC_DUAL_STATE": "For each case, separate what is supported by the supplied evidence from what is not. Make only a bounded commitment supported by the minimal witness; do not turn unresolved evidence into a stronger factual claim. Follow the output format exactly.",
  "H14_WMX_EBRC": "For each case, compress the question into a small known/unknown/decisive ledger, make the smallest evidence-supported commitment, correct only a concrete verifier-exposed defect, and stop when another reasoning pass cannot change the answer. Follow the output format exactly."
}

# Mechanism-hidden common contract. It exposes only the representational possibility of null;
# it does NOT state when null should be used, does not mention missing information,
# answerability, uncertainty, abstention, epistemic state, or UMWP mutation semantics.
CONTRACT={
  "output":"JSONL only",
  "fields":["case_id","answer","reason"],
  "field_types":{"case_id":"string","answer":"JSON number or null","reason":"short string"},
  "rules":["Return exactly one row per supplied case.","Do not add fields or prose outside JSONL."]
}

BANNED_COMMON=[
  "missing information","missing quantities","unknown","range","point estimate",
  "abstain","answerable","unanswerable","epistemic","resolved","unresolved"
]

def sha256_path(p: Path):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()

def parse_jsonl(text):
    text=text.replace("```jsonl","").replace("```json","").replace("```","")
    rows=[]
    for line in text.splitlines():
        line=line.strip()
        if not line: continue
        try:
            x=json.loads(line)
        except Exception:
            continue
        if isinstance(x,dict) and "case_id" in x:
            rows.append(x)
    return rows

def call(key,model,protocol,cases,timeout):
    payload={
      "model":model,
      "temperature":0,
      "max_tokens":1800,
      "messages":[
        {"role":"system","content":protocol},
        {"role":"user","content":json.dumps({"contract":CONTRACT,"cases":cases},ensure_ascii=False)}
      ]
    }
    r=requests.post(API,headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"},json=payload,timeout=timeout)
    r.raise_for_status()
    body=r.json()
    return body["choices"][0]["message"]["content"], body.get("usage") or {}

def run_arm(key,model,arm,batch_size,timeout,outdir):
    subject=json.loads((HERE/"UMWP20_SUBJECT.json").read_text(encoding="utf-8"))
    protocol=ARMS[arm]
    rows=[]
    usage={"prompt_tokens":0,"completion_tokens":0,"total_tokens":0,"calls":0}
    raw=outdir/"raw"; raw.mkdir(parents=True,exist_ok=True)
    for i in range(0,len(subject["cases"]),batch_size):
        batch=subject["cases"][i:i+batch_size]
        text,u=call(key,model,protocol,batch,timeout)
        usage["calls"] += 1
        for k in ("prompt_tokens","completion_tokens","total_tokens"):
            v=u.get(k)
            if isinstance(v,(int,float)): usage[k] += int(v)
        (raw/f"{arm}_batch_{i//batch_size+1:02d}.txt").write_text(text,encoding="utf-8")
        got=parse_jsonl(text)
        wanted={x["case_id"] for x in batch}
        ids=[x.get("case_id") for x in got]
        if len(ids)!=len(set(ids)): raise RuntimeError(f"{arm}: duplicate case_id in batch {i//batch_size+1}")
        got=[x for x in got if x.get("case_id") in wanted]
        missing=wanted-{x["case_id"] for x in got}
        if missing: raise RuntimeError(f"{arm}: missing {sorted(missing)}; raw saved")
        rows.extend(got)
        time.sleep(0.25)
    result=outdir/f"{arm}.jsonl"
    result.write_text("\n".join(json.dumps(x,ensure_ascii=False) for x in rows)+"\n",encoding="utf-8")
    score=outdir/f"{arm}_SCORE.json"
    subprocess.run([sys.executable,str(HERE/"score_umwp20_hidden_v02.py"),str(HERE/"UMWP20_PRIVATE_ORACLE.json"),str(result),str(score)],check=True)
    return {"metrics":json.loads(score.read_text(encoding="utf-8"))["metrics"],"usage":usage}

def validate_only():
    subject=json.loads((HERE/"UMWP20_SUBJECT.json").read_text(encoding="utf-8"))
    oracle=json.loads((HERE/"UMWP20_PRIVATE_ORACLE.json").read_text(encoding="utf-8"))["oracle"]
    assert len(subject["cases"])==20 and len(oracle)==20
    ids=[x["case_id"] for x in subject["cases"]]
    assert len(ids)==len(set(ids))==20
    assert set(ids)=={x["case_id"] for x in oracle}
    assert sum(bool(x["answerable"]) for x in oracle)==10
    common=json.dumps(CONTRACT,ensure_ascii=False).lower()
    for term in BANNED_COMMON:
        assert term not in common, f"common contract leaks mechanism term: {term}"
    h00=ARMS["H00_DIRECT"].lower()
    for term in BANNED_COMMON:
        assert term not in h00, f"H00 leaks mechanism term: {term}"
    receipt={
      "status":"PASS",
      "cases":20,
      "answerable":10,
      "unanswerable":10,
      "arms":list(ARMS),
      "common_contract_mechanism_terms_absent":True,
      "h00_mechanism_terms_absent":True,
      "subject_sha256":sha256_path(HERE/"UMWP20_SUBJECT.json"),
      "oracle_sha256":sha256_path(HERE/"UMWP20_PRIVATE_ORACLE.json"),
      "runner_sha256":sha256_path(Path(__file__).resolve())
    }
    (HERE/"VALIDATION_RECEIPT.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(receipt,indent=2))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--model",default=MODEL_DEFAULT)
    ap.add_argument("--arms",nargs="*",default=list(ARMS))
    ap.add_argument("--batch-size",type=int,default=5)
    ap.add_argument("--timeout",type=int,default=120)
    ap.add_argument("--resume",action="store_true")
    ap.add_argument("--validate-only",action="store_true")
    args=ap.parse_args()
    if args.validate_only:
        validate_only(); return
    bad=[a for a in args.arms if a not in ARMS]
    if bad: raise SystemExit(f"Unknown arms: {bad}")
    key=os.environ.get("OPENROUTER_API_KEY")
    if not key: raise SystemExit("Set OPENROUTER_API_KEY; it is never written to disk.")
    outdir=HERE/"results"/args.model.replace("/","_").replace(":","_")
    outdir.mkdir(parents=True,exist_ok=True)
    summary={"schema":"triaxis.evolution_hidden_v02.result/v1","model":args.model,"arms":{},"contract":CONTRACT}
    for arm in args.arms:
        sp=outdir/f"{arm}_SCORE.json"
        if args.resume and sp.exists():
            record={"metrics":json.loads(sp.read_text(encoding="utf-8"))["metrics"],"usage":{"status":"UNKNOWN_ON_RESUME_WITHOUT_USAGE_RECEIPT"}}
        else:
            print("==",arm,"==")
            record=run_arm(key,args.model,arm,args.batch_size,args.timeout,outdir)
        summary["arms"][arm]=record
    summary["ranking"]=sorted(
      [{"arm":a,**{k:r["metrics"][k] for k in ["overall_final_accuracy","answerable_accuracy","unanswerable_null_accuracy","overanswer_rate_on_unanswerable","pair_integrity_rate"]},"usage":r.get("usage",{})} for a,r in summary["arms"].items()],
      key=lambda x:(x["overall_final_accuracy"],x["pair_integrity_rate"],x["unanswerable_null_accuracy"],x["answerable_accuracy"]),reverse=True
    )
    (outdir/"EVOLUTION_HIDDEN_V02_SUMMARY.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(summary["ranking"],ensure_ascii=False,indent=2))

if __name__=="__main__": main()
