#!/usr/bin/env python3
"""Run a frozen TRIAXIS projection against a commit-sealed holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from triaxis.projection import evaluate_candidate  # noqa: E402
from oracle import evaluate_oracle  # noqa: E402


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--results-jsonl", required=True)
    args = parser.parse_args()

    cases_path = Path(args.cases)
    cases = load_jsonl(cases_path)
    results = []
    summary = Counter()
    family_summary: dict[str, Counter] = defaultdict(Counter)

    for case in cases:
        candidate = evaluate_candidate(args.version, case)
        expected = evaluate_oracle(case)
        passed = candidate["status"] == expected["status"] and candidate["primary_reason"] == expected["primary_reason"]
        outcome = "PASS" if passed else "FAIL"
        summary[outcome] += 1
        family_summary[case["family"]][outcome] += 1
        results.append(
            {
                "case_id": case["case_id"],
                "template_name": case["template_name"],
                "family": case["family"],
                "expected": expected,
                "candidate": candidate,
                "outcome": outcome,
            }
        )

    out_jsonl = Path(args.results_jsonl)
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for row in results:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")

    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    case_hash = hashlib.sha256(cases_path.read_bytes()).hexdigest()
    result_hash = hashlib.sha256(out_jsonl.read_bytes()).hexdigest()

    lines = [
        f"# TRIAXIS Holdout Report — {args.version}",
        "",
        f"- Cases: `{cases_path.name}`",
        f"- Case payload SHA-256: `{case_hash}`",
        f"- Results SHA-256: `{result_hash}`",
        f"- PASS: **{summary['PASS']}**",
        f"- FAIL: **{summary['FAIL']}**",
        "",
        "## Family summary",
        "",
        "| Family | PASS | FAIL |",
        "|---|---:|---:|",
    ]
    for family in sorted(family_summary):
        counts = family_summary[family]
        lines.append(f"| {family} | {counts['PASS']} | {counts['FAIL']} |")

    failures = [row for row in results if row["outcome"] == "FAIL"]
    lines.extend(["", "## Failures", ""])
    if not failures:
        lines.append("No mismatches in this holdout.")
    else:
        for row in failures:
            lines.extend(
                [
                    f"### {row['case_id']} — {row['template_name']}",
                    "",
                    f"- Family: `{row['family']}`",
                    f"- Expected: `{row['expected']['status']} / {row['expected']['primary_reason']}`",
                    f"- Candidate: `{row['candidate']['status']} / {row['candidate']['primary_reason']}`",
                    "",
                ]
            )

    lines.extend(
        [
            "## Scope limitation",
            "",
            "This is a commit-sealed deterministic conformance holdout. It is not an independent LLM benchmark and does not validate the generative Audit/Devil/Angel/Synthesizer passes.",
            "",
        ]
    )
    report.write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps({"version": args.version, "pass": summary["PASS"], "fail": summary["FAIL"], "case_sha256": case_hash, "result_sha256": result_hash}, sort_keys=True))
    raise SystemExit(0 if summary["FAIL"] == 0 else 2)


if __name__ == "__main__":
    main()
