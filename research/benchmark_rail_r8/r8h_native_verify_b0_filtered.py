import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

import duckdb

SELECTED = ("abc391_d", "abc338_b", "abc357_b")
TIMEOUT = 6
DATASET = "livecodebench/code_generation_lite"
CONFIG = "release_v6"
SPLIT = "test"


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def fetch_selected_rows():
    manifest_url = "https://datasets-server.huggingface.co/parquet?" + urllib.parse.urlencode({"dataset": DATASET})
    req = urllib.request.Request(manifest_url, headers={"User-Agent": "TRIAXIS-R8H/1.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        payload = json.load(response)
    urls = [
        item["url"] for item in payload.get("parquet_files", [])
        if item.get("config") == CONFIG and item.get("split") == SPLIT and item.get("url")
    ]
    if not urls:
        raise RuntimeError("NO_RELEASE_V6_PARQUET_URLS")

    con = duckdb.connect(database=":memory:")
    con.execute("INSTALL httpfs")
    con.execute("LOAD httpfs")
    url_list = "[" + ",".join(sql_string(url) for url in urls) + "]"
    id_list = ",".join(sql_string(qid) for qid in SELECTED)
    query = f"SELECT * FROM read_parquet({url_list}, union_by_name=true) WHERE question_id IN ({id_list})"
    cursor = con.execute(query)
    columns = [desc[0] for desc in cursor.description]
    rows = [dict(zip(columns, values)) for values in cursor.fetchall()]
    by_id = {str(row.get("question_id")): row for row in rows}
    if set(by_id) != set(SELECTED):
        raise RuntimeError(f"PARQUET_CARDINALITY:{sorted(by_id)}")
    return by_id, len(urls)


def classify(result_list):
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

    rows, shard_count = fetch_selected_rows()
    public_results = []
    for qid in SELECTED:
        problem = CodeGenerationProblem(**rows[qid])
        sample = problem.get_evaluation_sample()
        result_list, metadata = check_correctness(sample, solutions[qid], timeout=TIMEOUT, debug=False)
        total = len(result_list)
        passed = sum(1 for r in result_list if r is True or r == 1)
        public_results.append({
            "task_id": qid,
            "reward": 1.0 if total > 0 and passed == total else 0.0,
            "passed": passed,
            "total": total,
            "error_class": classify(result_list),
        })
        del problem, sample, result_list, metadata
    del rows

    out = {
        "schema": "triaxis.r8h.native_b0_result/v4-parquet",
        "evidence_class": "REAL_HELDOUT_TASKS_NATIVE_VERIFIER_CURRENT_SESSION_NONINDEPENDENT_MODEL",
        "data_access": "official HF parquet manifest + DuckDB HTTP range reads/predicate pushdown",
        "parquet_shard_count": shard_count,
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
