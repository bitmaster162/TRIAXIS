import json
import os
import pathlib
import sys

SELECTED = {"abc391_d", "abc338_b", "abc357_b"}
TIMEOUT = 6


def classify(result_list, metadata):
    if result_list and all(r is True or r == 1 for r in result_list):
        return "PASS"
    # Do not expose hidden input/output from metadata.
    codes = []
    if isinstance(metadata, dict):
        for value in metadata.values():
            if isinstance(value, dict) and "error_code" in value:
                codes.append(value.get("error_code"))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "error_code" in item:
                        codes.append(item.get("error_code"))
        if "error_code" in metadata:
            codes.append(metadata.get("error_code"))
    flat = []
    def walk(v):
        if isinstance(v, (list, tuple)):
            for x in v: walk(x)
        else: flat.append(v)
    walk(result_list)
    if any(x == -3 for x in flat) or -3 in codes:
        return "TLE"
    if any(x == -4 for x in flat) or -4 in codes:
        return "RE"
    if any(x == -1 for x in flat) or -1 in codes:
        return "CE_OR_TIMEOUT"
    if any(x == -2 for x in flat) or -2 in codes:
        return "WA"
    return "FAIL"


def main():
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    freeze_path = repo_root / "research/benchmark_rail_r8/R8H_B0_OUTPUT_FREEZE_2026-08-13.json"
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    solutions = freeze["solutions"]
    assert set(solutions) == SELECTED

    lcb = pathlib.Path(os.environ["LCB_REPO"]).resolve()
    sys.path.insert(0, str(lcb))
    from datasets import load_dataset
    from lcb_runner.benchmarks.code_generation import CodeGenerationProblem
    from lcb_runner.evaluation.compute_code_generation_metrics import check_correctness

    # Streaming avoids materializing the complete benchmark payload locally.
    ds = load_dataset(
        "livecodebench/code_generation_lite",
        split="test",
        version_tag="release_v6",
        trust_remote_code=True,
        streaming=True,
    )

    found = {}
    for row in ds:
        qid = str(row.get("question_id"))
        if qid in SELECTED:
            found[qid] = dict(row)
            if len(found) == len(SELECTED):
                break
    if set(found) != SELECTED:
        raise RuntimeError(f"Selected task IDs not found: {sorted(SELECTED-set(found))}")

    public = []
    for qid in sorted(SELECTED):
        problem = CodeGenerationProblem(**found[qid])
        sample = problem.get_evaluation_sample()
        # Hidden tests remain only inside this process.
        result_list, metadata = check_correctness(
            sample,
            solutions[qid],
            timeout=TIMEOUT,
            debug=False,
        )
        total = len(result_list)
        passed = sum(1 for r in result_list if r is True or r == 1)
        public.append({
            "task_id": qid,
            "reward": 1.0 if total > 0 and passed == total else 0.0,
            "passed": passed,
            "total": total,
            "error_class": classify(result_list, metadata),
        })

    out = {
        "schema": "triaxis.r8h.native_b0_result/v1",
        "evidence_class": "REAL_HELDOUT_TASKS_NATIVE_VERIFIER_CURRENT_SESSION_NONINDEPENDENT_MODEL",
        "livecodebench_commit": os.environ.get("LCB_COMMIT"),
        "release": "release_v6",
        "hidden_test_details_disclosed": False,
        "results": public,
        "passed_tasks": sum(int(r["reward"] == 1.0) for r in public),
        "total_tasks": len(public),
    }
    print("===R8H_SANITIZED_NATIVE_RESULT_BEGIN===")
    print(json.dumps(out, indent=2, sort_keys=True))
    print("===R8H_SANITIZED_NATIVE_RESULT_END===")


if __name__ == "__main__":
    main()
