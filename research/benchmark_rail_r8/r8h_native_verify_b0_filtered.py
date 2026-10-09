import hashlib
import json
import os
import pathlib
import sys
import urllib.request

SELECTED = ("abc391_d", "abc338_b", "abc357_b")
TIMEOUT = 6
HF_DATASET_HEAD = "0fe84c3912ea0c4d4a78037083943e8f0c4dd505"
HF_BASE = f"https://huggingface.co/datasets/livecodebench/code_generation_lite/resolve/{HF_DATASET_HEAD}"
SHARDS = [
    ("test6.jsonl", "bb4c364f71921c4495a6ad15abe1a927350b720009f4933e2e71f8af0f6fd1f5", 134303240),
    ("test5.jsonl", "7f77571c2a6df0c2a72a3277650309f67e01e0008e18117e624633df53f81214", 557699297),
    ("test4.jsonl", "d711138ddaebfcf5f8ec6a4283ee677298c0f5c5d374a235af92aaf0584510da", 1204644685),
    ("test3.jsonl", "28ed26cc83363ce3f1fe2d5fad9f8393077beb1907b167a31bd3b32f80801b79", 623360766),
    ("test2.jsonl", "095df7c5daf15f882c51a9deb84085cff1e073495a5dbcf95015a564d485f3a3", 713377060),
    ("test.jsonl", "2bd02b38beb48e8c46b5b9987095d999ff38cd8efc255ea5d58974317c48f63f", 1252609773),
]


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def retrieve_selected_rows():
    remaining = set(SELECTED)
    found = {}
    audit = []
    temp = pathlib.Path("r8h_lfs_temp")
    temp.mkdir(exist_ok=True)

    for filename, expected_sha, expected_size in SHARDS:
        if not remaining:
            break
        path = temp / filename
        url = f"{HF_BASE}/{filename}?download=true"
        req = urllib.request.Request(url, headers={"User-Agent": "TRIAXIS-R8H/1.0"})
        with urllib.request.urlopen(req, timeout=120) as response, path.open("wb") as out:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)

        actual_size = path.stat().st_size
        actual_sha = sha256_file(path)
        if actual_size != expected_size:
            raise RuntimeError(f"LFS_SIZE_MISMATCH:{filename}:{actual_size}:{expected_size}")
        if actual_sha != expected_sha:
            raise RuntimeError(f"LFS_SHA_MISMATCH:{filename}:{actual_sha}:{expected_sha}")

        matched_here = []
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            for line in handle:
                if not remaining:
                    break
                # Cheap prefilter avoids parsing almost every huge JSON row.
                if not any(qid in line for qid in remaining):
                    continue
                row = json.loads(line)
                qid = str(row.get("question_id"))
                if qid in remaining:
                    found[qid] = row
                    remaining.remove(qid)
                    matched_here.append(qid)

        audit.append({
            "file": filename,
            "sha256": actual_sha,
            "size": actual_size,
            "matched_frozen_ids": sorted(matched_here),
        })
        path.unlink(missing_ok=True)

    if remaining:
        raise RuntimeError(f"FROZEN_IDS_NOT_FOUND:{sorted(remaining)}")
    return found, audit


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

    rows, shard_audit = retrieve_selected_rows()
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
        "schema": "triaxis.r8h.native_b0_result/v5-lfs",
        "evidence_class": "REAL_HELDOUT_TASKS_NATIVE_VERIFIER_CURRENT_SESSION_NONINDEPENDENT_MODEL",
        "data_access": "pinned HF dataset git head + staged direct LFS shard retrieval",
        "hf_dataset_head": HF_DATASET_HEAD,
        "shard_audit": shard_audit,
        "livecodebench_commit": os.environ.get("LCB_COMMIT"),
        "release": "release_v6",
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
