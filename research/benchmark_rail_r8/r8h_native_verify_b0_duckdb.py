import json
import os
import pathlib
import sys

import duckdb

SELECTED = ("abc391_d", "abc338_b", "abc357_b")
TIMEOUT = 6
PARQUET_SNAPSHOT = "d44be6b144381afa49392b1f0eb424a64a4d8a10"
EXPECTED_RELEASE_ROWS = 1055
PARQUET_URLS = [
    f"https://huggingface.co/datasets/livecodebench/code_generation_lite/resolve/{PARQUET_SNAPSHOT}/release_v6/test-{i:05d}-of-00009.parquet?download=true"
    for i in range(9)
]


def sql_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def make_con():
    pathlib.Path("/tmp/r8h_duckdb").mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(database=":memory:")
    con.execute("INSTALL httpfs")
    con.execute("LOAD httpfs")
    con.execute("SET threads=1")
    con.execute("SET preserve_insertion_order=false")
    con.execute("SET memory_limit='3GB'")
    con.execute("SET temp_directory='/tmp/r8h_duckdb'")
    con.execute("SET enable_http_metadata_cache=true")
    return con


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


def locate_shards():
    ids_sql = ",".join(sql_quote(q) for q in SELECTED)
    mapping = {}
    total_rows = 0
    con = make_con()
    try:
        for idx, url in enumerate(PARQUET_URLS):
            u = sql_quote(url)
            total_rows += int(con.execute(f"SELECT count(*) FROM read_parquet({u})").fetchone()[0])
            hits = con.execute(
                f"SELECT question_id FROM read_parquet({u}) WHERE question_id IN ({ids_sql})"
            ).fetchall()
            for (qid,) in hits:
                qid = str(qid)
                if qid in mapping:
                    raise RuntimeError(f"FROZEN_ID_DUPLICATE_ACROSS_SHARDS:{qid}")
                mapping[qid] = idx
    finally:
        con.close()

    if total_rows != EXPECTED_RELEASE_ROWS:
        raise RuntimeError(f"RELEASE_ROW_COUNT_MISMATCH:{total_rows}:{EXPECTED_RELEASE_ROWS}")
    if set(mapping) != set(SELECTED):
        raise RuntimeError(f"FROZEN_IDS_NOT_LOCATED:{sorted(mapping)}")
    return mapping, total_rows


def materialize_selected(mapping):
    by_shard = {}
    for qid, idx in mapping.items():
        by_shard.setdefault(idx, []).append(qid)

    found = {}
    for idx, qids in sorted(by_shard.items()):
        con = make_con()
        try:
            ids_sql = ",".join(sql_quote(q) for q in qids)
            u = sql_quote(PARQUET_URLS[idx])
            cur = con.execute(
                f"SELECT * FROM read_parquet({u}) WHERE question_id IN ({ids_sql})"
            )
            columns = [d[0] for d in cur.description]
            for row in cur.fetchall():
                obj = dict(zip(columns, row))
                qid = str(obj.get("question_id"))
                if qid in found:
                    raise RuntimeError(f"FROZEN_ID_DUPLICATE_MATERIALIZED:{qid}")
                found[qid] = obj
        finally:
            con.close()

    if set(found) != set(SELECTED):
        raise RuntimeError(f"FROZEN_IDS_MATERIALIZE_MISMATCH:{sorted(found)}")
    return found


def fetch_rows():
    mapping, total_rows = locate_shards()
    rows = materialize_selected(mapping)
    return rows, total_rows, mapping


def main():
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    freeze_path = repo_root / "research/benchmark_rail_r8/R8H_B0_OUTPUT_FREEZE_2026-08-13.json"
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    if freeze.get("status") != "FROZEN_BEFORE_NATIVE_VERIFIER":
        raise RuntimeError("B0_FREEZE_STATUS_INVALID")
    solutions = freeze["solutions"]
    if set(solutions) != set(SELECTED):
        raise RuntimeError("B0_FROZEN_TASK_SET_MISMATCH")

    lcb = pathlib.Path(os.environ["LCB_REPO"]).resolve()
    sys.path.insert(0, str(lcb))
    from lcb_runner.benchmarks.code_generation import CodeGenerationProblem
    from lcb_runner.evaluation.compute_code_generation_metrics import check_correctness

    rows, total_release_rows, mapping = fetch_rows()
    public_results = []
    for qid in SELECTED:
        problem = CodeGenerationProblem(**rows[qid])
        sample = problem.get_evaluation_sample()
        result_list, metadata = check_correctness(
            sample, solutions[qid], timeout=TIMEOUT, debug=False
        )
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
        "schema": "triaxis.r8h.native_b0_result/v6b-duckdb-shard-local",
        "evidence_class": "REAL_HELDOUT_TASKS_NATIVE_VERIFIER_CURRENT_SESSION_NONINDEPENDENT_MODEL",
        "data_access": "official pinned release_v6 parquet snapshot + shard-local DuckDB HTTP range",
        "parquet_snapshot": PARQUET_SNAPSHOT,
        "release": "release_v6",
        "release_row_count": total_release_rows,
        "matched_shards": {qid: mapping[qid] for qid in SELECTED},
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
