"""Read-only TRIAXIS canon-profile conformance validator.

This module validates a bounded project-specific projection of the external
Memory Canon. It does not authorize actions, mutate provider/runtime state,
merge code, deploy, trade, move capital, or promote research/draft evidence to
production current.

The profile is deliberately a *conformance lens*, not an authority source.
Repository/source/test evidence remains authoritative for TRIAXIS behavior.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any, Mapping

VALID_STATUSES = frozenset(
    {
        "VERIFIED_MAIN",
        "VERIFIED_PROCESS",
        "PARTIAL_MAIN",
        "PARTIAL_RESEARCH",
        "RESEARCH_ONLY",
        "RESEARCH_ONLY_PARTIAL",
        "GAP",
        "GAP_OR_OUTSIDE",
        "OUTSIDE_TRIAXIS_CORE",
    }
)

RESEARCH_STATUSES = frozenset(
    {"PARTIAL_RESEARCH", "RESEARCH_ONLY", "RESEARCH_ONLY_PARTIAL"}
)


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def validate_canon_profile(
    profile: Mapping[str, Any], *, observed_main_sha: str
) -> dict[str, Any]:
    """Validate one read-only canon profile against an exact TRIAXIS main SHA.

    A baseline mismatch is a first-class HOLD rather than a warning.  The
    result never grants apply/merge/deploy/effect authority.
    """

    if not isinstance(profile, Mapping):
        return {
            "status": "HOLD_PROFILE_INVALID",
            "errors": [_error("invalid_type", "profile", "mapping required")],
            "usable_for_apply": False,
        }

    obj = deepcopy(dict(profile))
    errors: list[dict[str, str]] = []

    if obj.get("profile_id") != "TRIAXIS_CANON_PROFILE_R1":
        errors.append(
            _error("invalid_profile_id", "profile_id", "TRIAXIS_CANON_PROFILE_R1 required")
        )
    if obj.get("mode") != "READ_ONLY_CONFORMANCE_PROFILE":
        errors.append(
            _error("invalid_mode", "mode", "READ_ONLY_CONFORMANCE_PROFILE required")
        )

    expected_main_sha = obj.get("baseline_main_sha")
    if not isinstance(expected_main_sha, str) or len(expected_main_sha) != 40:
        errors.append(
            _error("invalid_baseline", "baseline_main_sha", "40-character git SHA required")
        )

    if errors:
        return {
            "status": "HOLD_PROFILE_INVALID",
            "errors": errors,
            "usable_for_apply": False,
        }

    if observed_main_sha != expected_main_sha:
        return {
            "status": "HOLD_BASELINE_DRIFT",
            "expected_main_sha": expected_main_sha,
            "observed_main_sha": observed_main_sha,
            "errors": [],
            "usable_for_apply": False,
        }

    selected = obj.get("selected_decisions")
    entries = obj.get("entries")
    if not isinstance(selected, list) or not all(isinstance(x, str) for x in selected):
        errors.append(
            _error("invalid_selected_decisions", "selected_decisions", "list[str] required")
        )
        selected = []
    if not isinstance(entries, list):
        errors.append(_error("invalid_entries", "entries", "list required"))
        entries = []

    if len(selected) != len(set(selected)):
        errors.append(
            _error("duplicate_selected_decision", "selected_decisions", "decision IDs must be unique")
        )

    entry_ids: list[str] = []
    status_counts: Counter[str] = Counter()
    research_only: list[str] = []
    gaps: list[str] = []
    outside: list[str] = []

    for index, entry in enumerate(entries):
        path = f"entries[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(_error("invalid_entry", path, "mapping required"))
            continue
        decision_id = entry.get("decision_id")
        status = entry.get("status")
        evidence = entry.get("evidence")
        assertion = entry.get("assertion")

        if not isinstance(decision_id, str) or not decision_id.startswith("D"):
            errors.append(_error("invalid_decision_id", f"{path}.decision_id", "D### required"))
            continue
        entry_ids.append(decision_id)
        if status not in VALID_STATUSES:
            errors.append(_error("unknown_status", f"{path}.status", "unknown conformance status"))
            continue
        status_counts[status] += 1

        if not isinstance(evidence, str) or not evidence.strip():
            errors.append(_error("missing_evidence", f"{path}.evidence", "evidence anchor required"))
        if not isinstance(assertion, str) or not assertion.strip():
            errors.append(_error("missing_assertion", f"{path}.assertion", "bounded assertion required"))

        evidence_lower = evidence.lower() if isinstance(evidence, str) else ""
        if status == "VERIFIED_MAIN" and (
            "research/" in evidence_lower or "open draft" in evidence_lower
        ):
            errors.append(
                _error(
                    "non_main_evidence_promoted",
                    f"{path}.status",
                    "research/draft evidence cannot satisfy VERIFIED_MAIN",
                )
            )

        if status in RESEARCH_STATUSES:
            research_only.append(decision_id)
        if status in {"GAP", "GAP_OR_OUTSIDE"}:
            gaps.append(decision_id)
        if status == "OUTSIDE_TRIAXIS_CORE":
            outside.append(decision_id)

    if len(entry_ids) != len(set(entry_ids)):
        errors.append(_error("duplicate_entry", "entries", "entry decision IDs must be unique"))
    if set(entry_ids) != set(selected):
        errors.append(
            _error(
                "selection_entry_mismatch",
                "entries",
                "entries must match selected_decisions exactly",
            )
        )

    status = "PASS_CANON_PROFILE_READ_ONLY" if not errors else "HOLD_PROFILE_INVALID"
    return {
        "status": status,
        "profile_id": obj.get("profile_id"),
        "baseline_main_sha": expected_main_sha,
        "selected_decisions": len(selected),
        "counts": dict(sorted(status_counts.items())),
        "research_only_or_partial": sorted(research_only),
        "gaps": sorted(gaps),
        "outside_triaxis_core": sorted(outside),
        "errors": errors,
        "usable_for_apply": False,
        "authority": {
            "merge": "DENY",
            "deploy": "DENY",
            "provider_effect": "DENY",
            "trading": "DENY",
            "capital": "DENY",
            "canon_promotion": "DENY",
        },
    }


__all__ = [
    "RESEARCH_STATUSES",
    "VALID_STATUSES",
    "validate_canon_profile",
]
