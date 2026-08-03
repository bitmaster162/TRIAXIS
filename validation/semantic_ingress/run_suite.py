#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from triaxis.projection import evaluate_candidate  # noqa: E402

try:  # absent in the frozen v2.8 candidate
    from triaxis.projection import evaluate_ingress  # type: ignore[attr-defined]  # noqa: E402
except ImportError:  # pragma: no cover - exercised by R1 baseline run
    evaluate_ingress = None


_SEVERITY = {"ALLOW": 0, "ALLOW_WITH_LIMITS": 1, "HUMAN_DECISION_REQUIRED": 2, "BLOCK": 3}


def _legacy_direct_structured(version: str, record: dict[str, Any]) -> dict[str, Any]:
    """Model the v2.8 boundary: semantic receipt ignored, scenarios trusted."""

    decisions = [evaluate_candidate(version, node["scenario"]) for node in record.get("nodes", []) if isinstance(node, dict) and isinstance(node.get("scenario"), dict)]
    if not decisions:
        return {"status": "ALLOW", "primary_reason": "CONDITIONS_SATISFIED", "reasons": [], "controls": ["LEGACY_DIRECT_STRUCTURED"]}
    worst = max(decisions, key=lambda d: _SEVERITY.get(str(d.get("status")), 99))
    return dict(worst) | {"legacy_semantic_ingress_bypass": True}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    cases_path = Path(args.cases)
    cases = [json.loads(line) for line in cases_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    totals = Counter()
    families: dict[str, Counter] = defaultdict(Counter)
    results = []

    for case in cases:
        try:
            if evaluate_ingress is None or args.version in {"2.8-RC1", "2.8-RC2"}:
                decision = _legacy_direct_structured(args.version, case["record"])
            else:
                decision = evaluate_ingress(args.version, case["record"])
            crashed = False
        except Exception as exc:
            decision = {"status": "CRASH", "primary_reason": type(exc).__name__, "error": str(exc)}
            crashed = True
        passed = (
            not crashed
            and decision.get("status") == case["expected_status"]
            and decision.get("primary_reason") == case["expected_reason"]
        )
        outcome = "PASS" if passed else "FAIL"
        totals[outcome] += 1
        families[case["family"]][outcome] += 1
        results.append({
            "case_id": case["case_id"],
            "template_name": case["template_name"],
            "family": case["family"],
            "expected": {"status": case["expected_status"], "primary_reason": case["expected_reason"]},
            "decision": decision,
            "outcome": outcome,
        })

    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in results), encoding="utf-8")

    lines = [
        f"# TRIAXIS Semantic Ingress Report — {args.version}", "",
        f"- Cases SHA-256: `{hashlib.sha256(cases_path.read_bytes()).hexdigest()}`",
        f"- Results SHA-256: `{hashlib.sha256(results_path.read_bytes()).hexdigest()}`",
        f"- PASS: **{totals['PASS']}**", f"- FAIL: **{totals['FAIL']}**", "",
        "## Family summary", "", "| Family | PASS | FAIL |", "|---|---:|---:|",
    ]
    for family in sorted(families):
        lines.append(f"| {family} | {families[family]['PASS']} | {families[family]['FAIL']} |")
    lines.extend(["", "## Failures", ""])
    failures = [row for row in results if row["outcome"] == "FAIL"]
    if not failures:
        lines.append("All sampled semantic-ingress expectations were satisfied.")
    else:
        for row in failures:
            d = row["decision"]
            lines.extend([
                f"### {row['case_id']} — {row['template_name']}", "",
                f"- Family: `{row['family']}`",
                f"- Expected: `{row['expected']['status']} / {row['expected']['primary_reason']}`",
                f"- Observed: `{d.get('status')} / {d.get('primary_reason')}`", "",
            ])
    lines.extend([
        "", "## Scope", "",
        "Semantic-ingress receipt integrity and conservative explicit-action backstop only. This suite does not establish general natural-language understanding or independent validation.", "",
    ])
    Path(args.report).write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"version": args.version, "pass": totals["PASS"], "fail": totals["FAIL"]}, sort_keys=True))
    raise SystemExit(0 if totals["FAIL"] == 0 else 2)


if __name__ == "__main__":
    main()
