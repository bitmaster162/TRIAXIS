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
BASE = "https://datasets-server.huggingface.co"
EXPECTED_RELEASE_ROWS = 1055


def get_json(path, params):
    url = BASE + path + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "TRIAXIS-R8H/1.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        payload = response.read()
        headers = {k.lower(): v for k, v in response.headers.items()}
    return json.loads(payload), headers


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


def extract_release_rows(size_obj):
    candidates = []
    for key in ("size", "configs", "splits", "dataset"):
        value = size_obj.get(key) if isinstance(size_obj, dict) else None
        if isinstance(value, list):
            candidates.extend(value)
    # Recursive search for release_v6/test objects with num_rows.
    stack = [size_obj]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            cfg = value.get("config") or value.get("config_name")
            split = value.get("split") or value.get("split_name") or value.get("name")
            n = value.get("num_rows") or value.get("num_examples")
            if cfg == CONFIG and split == SPLIT and isinstance(n, int):
                return n
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return None


def fetch_rows():
    splits, split_headers = get_json("/splits", {"dataset": DATASET})
    advertised = {
        (str(x.get("config")), str(x.get("split")))
        for x in splits.get("splits", [])
        if isinstance(x, dict)
    }
    if (CONFIG, SPLIT) not in advertised:
        raise RuntimeError(f"DATASET_SERVER_SPLIT_NOT_ADVERTISED:{sorted(advertised)}")

    size_obj, size_headers = get_json("/size", {"dataset": DATASET})
    release_rows = extract_release_rows(size_obj)
    if release_rows is not None and release_rows != EXPECTED_RELEASE_ROWS:
        raise RuntimeError(f"DATASET_SERVER_RELEASE_ROW_COUNT_MISMATCH:{release_rows}:{EXPECTED_RELEASE_ROWS}")

    rows = {}
    header_receipts = []
    for qid in SELECTED:
        where = f'"question_id"=\'{qid}\''
        obj, headers = get_json(
            "/filter",
            {
                "dataset": DATASET,
                "config": CONFIG,
                "split": SPLIT,
                "where": where,
                "offset": 0,
                "length": 2,
            },
        )
        hits = obj.get("rows", [])
        if len(hits) != 1:
            raise RuntimeError(f"DATASET_SERVER_FILTER_CARDINALITY:{qid}:{len(hits)}")
        row = hits[0].get("row") if isinstance(hits[0], dict) else None
        if not isinstance(row, dict) or str(row.get("question_id")) != qid:
            raise RuntimeError(f"DATASET_SERVER_ROW_ID_MISMATCH:{qid}")
        rows[qid] = row
        header_receipts.append(
            {
                "task_id": qid,
                "etag": headers.get("etag"),
                "x-revision": headers.get("x-revision"),
                "x-request-id": headers.get("x-request-id"),
            }
        )
    return rows, release_rows, header_receipts


def main():
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    freeze = json.loads(
        (repo_root / "research/benchmark_rail_r8/R8H_B0_OUTPUT_FREEZE_2026-08-13.json").read_text(encoding="utf-8")
    )
    if freeze.get("status") != "FROZEN_BEFORE_NATIVE_VERIFIER":
        raise RuntimeError("B0_FREEZE_STATUS_INVALID")
    solutions = freeze["solutions"]
    if set(solutions) != set(SELECTED):
        raise RuntimeError("B0_FROZEN_TASK_SET_MISMATCH")

    lcb = pathlib.Path(os.environ["LCB_REPO"]).resolve()
    sys.path.insert(0, str(lcb))
    from lcb_runner.benchmarks.code_generation import CodeGenerationProblem
    from lcb_runner.evaluation.compute_code_generation_metrics import check_correctness

    rows, release_rows, header_receipts = fetch_rows()
    public_results = []
    for qid in SELECTED:
        problem = CodeGenerationProblem(**rows[qid])
        sample = problem.get_evaluation_sample()
        result_list, metadata = check_correctness(sample, solutions[qid], timeout=TIMEOUT, debug=False)
        total = len(result_list)
        passed = sum(1 for r in result_list if r is True or r == 1)
        public_results.append(
            {
                "task_id": qid,
                "reward": 1.0 if total > 0 and passed == total else 0.0,
                "passed": passed,
                "total": total,
                "error_class": classify(result_list),
            }
        )
        del problem, sample, result_list, metadata

    out = {
        "schema": "triaxis.r8h.native_b0_result/v7-dataset-server",
        "evidence_class": "PROVISIONAL_REAL_HELDOUT_NATIVE_VERIFIER_PENDING_PINNED_DATA_CROSSCHECK",
        "data_access": "Hugging Face Dataset Server filter with official config=release_v6",
        "dataset": DATASET,
        "config": CONFIG,
        "split": SPLIT,
        "release_row_count_if_reported": release_rows,
        "server_header_receipts": header_receipts,
        "livecodebench_commit": os.environ.get("LCB_COMMIT"),
        "b0_freeze_commit": "b975656f11d89e86ef3fbfa30f139310ca6c980e",
        "selected_task_ids": list(SELECTED),
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
