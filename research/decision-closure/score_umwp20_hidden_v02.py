#!/usr/bin/env python3
import json,sys
from pathlib import Path
if len(sys.argv)!=4:
    raise SystemExit("usage: score_umwp20_hidden_v02.py ORACLE.json MODEL.jsonl OUT.json")
oracle=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["oracle"]
rows=[json.loads(x) for x in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines() if x.strip()]
by={r.get("case_id"):r for r in rows}

def normnum(x):
    if x is None:return None
    if isinstance(x,bool):return None
    try:return float(str(x).strip().replace(",",""))
    except:return None

scores=[]; missing=[]
for o in oracle:
    r=by.get(o["case_id"])
    if not r:
        missing.append(o["case_id"]); continue
    a=normnum(r.get("answer"))
    if o["answerable"]:
        ref=normnum(o["reference_answer"])
        final_correct=a is not None and ref is not None and abs(a-ref)<=1e-9
        null_correct=False
        overanswer=False
        false_null=a is None
    else:
        final_correct=a is None
        null_correct=a is None
        overanswer=a is not None
        false_null=False
    scores.append({
      "case_id":o["case_id"],"umwp_id":o["umwp_id"],"answerable":o["answerable"],
      "relevant_id":o.get("relevant_id"),"final_correct":final_correct,
      "null_correct":null_correct,"overanswer":overanswer,"false_null":false_null
    })

def rate(key,ss=None):
    ss=scores if ss is None else ss
    return sum(bool(x[key]) for x in ss)/len(ss) if ss else None
ans=[x for x in scores if x["answerable"]]
un=[x for x in scores if not x["answerable"]]
correct_by_umwp={x["umwp_id"]:x["final_correct"] for x in scores}
pairs=[]
for x in un:
    rid=x.get("relevant_id")
    if rid is not None and rid in correct_by_umwp:
        pairs.append(bool(x["final_correct"] and correct_by_umwp[rid]))
metrics={
 "overall_final_accuracy":rate("final_correct"),
 "answerable_accuracy":rate("final_correct",ans),
 "unanswerable_null_accuracy":rate("final_correct",un),
 "overanswer_rate_on_unanswerable":rate("overanswer",un),
 "false_null_rate_on_answerable":rate("false_null",ans),
 "pair_integrity_rate":sum(pairs)/len(pairs) if pairs else None,
 "pair_count":len(pairs)
}
res={"schema":"umwp20.hidden_v02.score/v1","received":len(rows),"missing":missing,"metrics":metrics,"scores":scores}
Path(sys.argv[3]).write_text(json.dumps(res,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
print(json.dumps(metrics,ensure_ascii=False))
