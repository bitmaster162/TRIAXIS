#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from triaxis.projection import evaluate_ingress  # noqa: E402


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
        try:
            decision = evaluate_ingress(args.version, row["record"])
            crashed = False
        except Exception as exc:  # exact crash receipt is part of the evidence
            decision = {"status": "CRASH", "primary_reason": type(exc).__name__, "error": str(exc)}
            crashed = True
        passed = (
            not crashed
            and decision.get("status") == row["expected_status"]
            and decision.get("primary_reason") == row["expected_reason"]
        )
        outcome = "PASS" if passed else "FAIL"
        totals[outcome] += 1
        families[row["family"]][outcome] += 1
        results.append({
            "case_id": row["case_id"],
            "template_name": row["template_name"],
            "family": row["family"],
            "expected": {"status": row["expected_status"], "primary_reason": row["expected_reason"]},
            "decision": decision,
            "outcome": outcome,
        })

    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in results), encoding="utf-8")
    lines = [
        f"# TRIAXIS Composition/State Report — {args.version}", "",
        f"- Cases SHA-256: `{hashlib.sha256(cases_path.read_bytes()).hexdigest()}`",
        f"- Results SHA-256: `{hashlib.sha256(results_path.read_bytes()).hexdigest()}`",
        f"- PASS: **{totals['PASS']}**",
        f"- FAIL: **{totals['FAIL']}**", "",
        "## Family summary", "", "| Family | PASS | FAIL |", "|---|---:|---:|",
    ]
    for family in sorted(families):
        lines.append(f"| {family} | {families[family]['PASS']} | {families[family]['FAIL']} |")
    lines.extend(["", "## Failures", ""])
    failures = [row for row in results if row["outcome"] == "FAIL"]
    if not failures:
        lines.append("All composition/state expectations were satisfied.")
    else:
        for row in failures:
            d = row["decision"]
            lines.extend([
                f"### {row['case_id']} — {row['template_name']}", "",
                f"- Family: `{row['family']}`",
                f"- Expected: `{row['expected']['status']} / {row['expected']['primary_reason']}`",
                f"- Observed: `{d.get('status')} / {d.get('primary_reason')}`", "",
            ])
    Path(args.report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"version": args.version, "pass": totals["PASS"], "fail": totals["FAIL"]}, sort_keys=True))
    raise SystemExit(0 if totals["FAIL"] == 0 else 2)


if __name__ == "__main__":
    main()
