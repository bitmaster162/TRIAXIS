#!/usr/bin/env python3
"""Evaluate metamorphic relations against a frozen TRIAXIS projection."""

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

RESTRICTIVENESS = {
    "ALLOW": 0,
    "ALLOW_WITH_LIMITS": 1,
    "HOLD": 2,
    "HUMAN_DECISION_REQUIRED": 2,
    "BLOCK": 3,
}


def relation_passes(row: dict, base: dict, mutant: dict) -> tuple[bool, str]:
    relation = row["relation"]
    expected_reason = row.get("expected_reason")
    if relation == "MUST_BLOCK":
        ok = mutant["status"] == "BLOCK" and (expected_reason is None or mutant["primary_reason"] == expected_reason)
        return ok, f"expected BLOCK/{expected_reason}, got {mutant['status']}/{mutant['primary_reason']}"
    if relation == "MUTANT_MUST_ALLOW":
        ok = mutant["status"] in {"ALLOW", "ALLOW_WITH_LIMITS"}
        return ok, f"expected allow after repair, got {mutant['status']}/{mutant['primary_reason']}"
    if relation == "SAME_DECISION":
        ok = (base["status"], base["primary_reason"]) == (mutant["status"], mutant["primary_reason"])
        return ok, f"base {base['status']}/{base['primary_reason']} vs mutant {mutant['status']}/{mutant['primary_reason']}"
    if relation == "NOT_LESS_RESTRICTIVE":
        ok = RESTRICTIVENESS[mutant["status"]] >= RESTRICTIVENESS[base["status"]]
        return ok, f"base rank {RESTRICTIVENESS[base['status']]} > mutant rank {RESTRICTIVENESS[mutant['status']]}"
    raise ValueError(f"Unknown relation: {relation}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    cases_path = Path(args.cases)
    rows = [json.loads(line) for line in cases_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    results = []
    totals = Counter()
    families: dict[str, Counter] = defaultdict(Counter)

    for row in rows:
        base = evaluate_candidate(args.version, row["base"])
        mutant = evaluate_candidate(args.version, row["mutant"])
        ok, detail = relation_passes(row, base, mutant)
        outcome = "PASS" if ok else "FAIL"
        totals[outcome] += 1
        families[row["family"]][outcome] += 1
        results.append(
            {
                "case_id": row["case_id"],
                "template_name": row["template_name"],
                "family": row["family"],
                "relation": row["relation"],
                "expected_reason": row.get("expected_reason"),
                "base_decision": base,
                "mutant_decision": mutant,
                "outcome": outcome,
                "detail": detail,
            }
        )

    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in results), encoding="utf-8")

    lines = [
        f"# TRIAXIS Metamorphic Report — {args.version}",
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
        lines.append("No metamorphic violations detected in this batch.")
    else:
        for row in failures:
            lines.extend(
                [
                    f"### {row['case_id']} — {row['template_name']}",
                    "",
                    f"- Family: `{row['family']}`",
                    f"- Relation: `{row['relation']}`",
                    f"- Base: `{row['base_decision']['status']} / {row['base_decision']['primary_reason']}`",
                    f"- Mutant: `{row['mutant_decision']['status']} / {row['mutant_decision']['primary_reason']}`",
                    f"- Detail: {row['detail']}",
                    "",
                ]
            )

    lines.extend(["", "## Scope", "", "Frozen-candidate deterministic metamorphic validation; not independent LLM assurance.", ""])
    Path(args.report).write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"version": args.version, "pass": totals["PASS"], "fail": totals["FAIL"]}, sort_keys=True))
    raise SystemExit(0 if totals["FAIL"] == 0 else 2)


if __name__ == "__main__":
    main()
