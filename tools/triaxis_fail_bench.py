#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from triaxis.fail_bench import compare_full_to_mvt, score_rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Score TRIAXIS-FAIL-BENCH JSONL results")
    parser.add_argument("results", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.results.read_text(encoding="utf-8").splitlines() if line.strip()]
    report = score_rows(rows)
    try:
        report["project_verdict"] = compare_full_to_mvt(report)
    except ValueError as exc:
        report["project_verdict"] = {"verdict": "INCOMPLETE", "reason": str(exc)}
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
