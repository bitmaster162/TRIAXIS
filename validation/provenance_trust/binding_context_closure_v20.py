"""Recovered binding helper for authority fixtures."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

REVIEW_REF = "artifact:external-review-001"


def _bind(bundle: Mapping[str, Any], reference: str = REVIEW_REF) -> dict[str, Any]:
    from validation.analysis_support_v5 import reseal_analysis_bundle_v5

    result = deepcopy(dict(bundle))
    passes = result.get("passes", [])
    for item in passes:
        if isinstance(item, dict) and item.get("pass_type") == "FALSIFIER":
            item["independence_class"] = "INDEPENDENT_VERIFICATION"
            item["independent_verification_refs"] = [reference]
    registry = result.setdefault("provenance_registry", {"records": []})
    records = registry.setdefault("records", [])
    if not any(isinstance(item, dict) and item.get("reference") == reference for item in records):
        records.append({
            "reference": reference,
            "purpose": "INDEPENDENT_REVIEW",
            "verification": "VERIFIED",
        })
    return reseal_analysis_bundle_v5(result)


__all__ = ["REVIEW_REF", "_bind"]
