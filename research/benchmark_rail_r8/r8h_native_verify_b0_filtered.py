import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

SELECTED = ("abc391_d", "abc338_b", "abc357_b")
TIMEOUT = 6
DATASET = "livecodebench/code_generation_lite"
CONFIG = "release_v6"
SPLIT = "test"


def fetch_one(qid: str) -> dict:
    params = urllib.parse.urlencode({
        "dataset": DATASET,
        "config": CONFIG,
        "split": SPLIT,
        "where": f'"question_id"=\'{qid}\'',
        "offset": 0,
        "length": 10,
    })
    url = "https://datasets-server.huggingface.co/filter?" + params
    req = urllib.request.Request(url, headers={"User-Agent": "TRIAXIS-R8H/1.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        payload = json.load(response)
    rows = payload.get("rows") or []
    matches = []
    for item in rows:
        row = item.get("row") if isinstance(item, dict) else None
        if isinstance(row, dict) and str(row.get("question_id")) == qid:
            matches.append(row)
    if len(matches) != 1:
        raise RuntimeError(f"FILTER_CARDINALITY:{qid}:{len(matches)}")
    return matches[0]


def classify(result_list, metadata):
    if result_list and all(r is True or r == 1 for r in result_list):
        return "PASS"
    flat = []
    def walk(value):
        if isinstance(value, (list, tuple)):
            for item in value:
                walk(item)
        else:
            flat.append(value)
    walk(result_list)
    if any(x == -3 for x in flat): return "TLE"
    if any(x == -4 for x in flat): return "RE"
    if any(x == -2 for x in flat): return "WA"
    if any(x == -1 for x in flat): return "CE_OR_TIMEOUT"
    return "FAIL"


def main():
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    freeze = json.loads((repo_root / "research/benchmark_rail_r8/R8H_B0_OUTPUT_FREEZE_2026-08-13.json").read_text(encoding="utf-8"))
    solutions = freeze["solutions"]
    assert set(solutions) == set(SELECTED)

    lcb = pathlib.Path(os.environ["LCB_REPO"]).resolve()
    sys.path.insert(0, str(lcb))
    from lcb_runner.benchmarks.code_generation import CodeGenerationProblem
    from lcb_runner.evaluation.compute_code_generation_metrics import check_correctness

    public_results = []
    for qid in SELECTED:
        row = fetch_one(qid)
        problem = CodeGenerationProblem(**row)
        sample = problem.get_evaluation_sample()
        result_list, metadata = check_correctness(sample, solutions[qid], timeout=TIMEOUT, debug=False)
        total = len(result_list)
        passed = sum(1 for r in result_list if r is True or r == 1)
        public_results.append({
            "task_id": qid,
            "reward": 1.0 if total > 0 and passed == total else 0.0,
            "passed": passed,
            "total": total,
            "error_class": classify(result_list, metadata),
        })
        del row, problem, sample, metadata, result_list

    out = {
        "schema": "triaxis.r8h.native_b0_result/v3-filtered",
        "evidence_class": "REAL_HELDOUT_TASKS_NATIVE_VERIFIER_CURRENT_SESSION_NONINDEPENDENT_MODEL",
        "data_access": "Hugging Face Dataset Server server-side filter by frozen question_id",
        "livecodebench_commit": os.environ.get("LCB_COMMIT"),
        "release": CONFIG,
        "evaluator_details_disclosed": False,
        "results": public_results,
        "passed_tasks": sum(int(r["reward"] == 1.0) for r in public_results),
        "total_tasks": len(public_results),
    }
    print("===R8H_SANITIZED_NATIVE_RESULT_BEGIN===")
    print(json.dumps(out, indent=2, sort_keys=True))
    print("===R8H_SANITIZED_NATIVE_RESULT_END===")


if __name__ == "__main__":
    main()
