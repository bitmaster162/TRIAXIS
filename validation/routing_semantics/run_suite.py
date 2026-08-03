#!/usr/bin/env python3
"""Evaluate exact routing-semantic expectations."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from triaxis.projection import evaluate_candidate  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    cases_path = Path(args.cases)
    rows = [json.loads(line) for line in cases_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    totals = Counter()
    families: dict[str, Counter] = defaultdict(Counter)
    results = []

    for row in rows:
        decision = evaluate_candidate(args.version, row["scenario"])
        ok = (
            decision["status"] == row["expected_status"]
            and decision["primary_reason"] == row["expected_reason"]
        )
        outcome = "PASS" if ok else "FAIL"
        totals[outcome] += 1
        families[row["family"]][outcome] += 1
        results.append(
            {
                "case_id": row["case_id"],
                "template_name": row["template_name"],
                "family": row["family"],
                "expected_status": row["expected_status"],
                "expected_reason": row["expected_reason"],
                "decision": decision,
                "outcome": outcome,
            }
        )

    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in results), encoding="utf-8")

    lines = [
        f"# TRIAXIS Routing Semantics Report — {args.version}",
        "",
        f"- Cases SHA-256: `{hashlib.sha256(cases_path.read_bytes()).hexdigest()}`",
        f"- Results SHA-256: `{hashlib.sha256(results_path.read_bytes()).hexdigest()}`",
        f"- PASS: **{totals['PASS']}**",
        f"- FAIL: **{totals['FAIL']}**",
        "",
        "## Family summary",
        "",
        "| Family | PASS | FAIL |",
        "|---|---:|---:|",
    ]
    for family in sorted(families):
        lines.append(f"| {family} | {families[family]['PASS']} | {families[family]['FAIL']} |")

    failures = [row for row in results if row["outcome"] == "FAIL"]
    lines.extend(["", "## Failures", ""])
    if not failures:
        lines.append("No routing-semantic violations detected in this batch.")
    else:
        for row in failures:
            decision = row["decision"]
            lines.extend(
                [
                    f"### {row['case_id']} — {row['template_name']}",
                    "",
                    f"- Family: `{row['family']}`",
                    f"- Expected: `{row['expected_status']} / {row['expected_reason']}`",
                    f"- Actual: `{decision['status']} / {decision['primary_reason']}`",
                    "",
                ]
            )

    lines.extend(
        [
            "",
            "## Scope",
            "",
            "Commit-bound deterministic structured-node validation; not independent assurance and not natural-language extraction validation.",
            "",
        ]
    )
    Path(args.report).write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"version": args.version, "pass": totals["PASS"], "fail": totals["FAIL"]}, sort_keys=True))
    raise SystemExit(0 if totals["FAIL"] == 0 else 2)


if __name__ == "__main__":
    main()
