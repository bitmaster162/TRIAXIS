"""TRIAXIS v3.2 deterministic Evidence Broker.

The broker does not decide whether prose is true.  It verifies the structure,
subject binding, temporal validity, declared provenance, correlation and
minimum evidence-independence requirements of a claim/evidence package.

Security-critical facts may only be treated as verified when at least one
fresh source is delivered by an authenticated authoritative adapter.  A model
output or a second URL that copies the same upstream material does not create
independence.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from .integrity import materialize_json, seal_mapping, verify_sealed_mapping

EVIDENCE_PACKAGE_CONTRACT_ID = "TRIAXIS_EVIDENCE_PACKAGE_v1"
SOURCE_RECORD_CONTRACT_ID = "TRIAXIS_SOURCE_RECORD_v1"
CLAIM_RECORD_CONTRACT_ID = "TRIAXIS_CLAIM_RECORD_v1"
EVIDENCE_REPORT_CONTRACT_ID = "TRIAXIS_EVIDENCE_REPORT_v1"

SOURCE_TYPES = frozenset(
    {
        "PRIMARY_SOURCE",
        "SECONDARY_SOURCE",
        "TEST_ARTIFACT",
        "AUTHORITATIVE_ADAPTER",
        "MODEL_OUTPUT",
        "HUMAN_ATTESTATION",
    }
)
POLARITIES = frozenset({"SUPPORTS", "CONTRADICTS", "NEUTRAL"})
CLAIM_KINDS = frozenset({"FACTUAL", "POLICY", "PREDICTION", "NORMATIVE", "STATE_FACT"})
ATTESTATION_LEVELS = (
    "UNATTESTED",
    "DECLARED",
    "AUTHENTICATED",
    "HARDWARE_ROOTED",
)
CLAIM_STATUSES = frozenset(
    {
        "VERIFIED",
        "UNVERIFIED",
        "UNVERIFIED_AUTHORITY",
        "CORRELATED",
        "STALE",
        "FUTURE_DATED",
        "CONTESTED",
        "REFUTED",
    }
)


def seal_contract(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    return seal_mapping(value, digest_field)


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _sealed(
    value: Any,
    contract_id: str,
    digest_field: str,
    path: str,
    errors: list[dict[str, str]],
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(_error("invalid_type", path, "object required"))
        return None
    obj = dict(value)
    if obj.get("contract_id") != contract_id:
        errors.append(_error("invalid_contract_id", f"{path}.contract_id", f"expected {contract_id}"))
    if not verify_sealed_mapping(obj, digest_field):
        errors.append(_error("digest_mismatch", f"{path}.{digest_field}", "canonical digest mismatch"))
    return obj


class _UnionFind:
    def __init__(self, values: list[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        root_left, root_right = self.find(left), self.find(right)
        if root_left == root_right:
            return
        winner, loser = sorted((root_left, root_right))
        self.parent[loser] = winner


def _attestation_at_least(actual: Any, required: Any) -> bool:
    if actual not in ATTESTATION_LEVELS or required not in ATTESTATION_LEVELS:
        return False
    return ATTESTATION_LEVELS.index(actual) >= ATTESTATION_LEVELS.index(required)


def validate_evidence_package(value: Any) -> dict[str, Any]:
    """Validate and adjudicate a sealed evidence package.

    Structural failures return ``BLOCK``.  A structurally valid package returns
    ``ESCALATE`` when any load-bearing claim is not ``VERIFIED``.  Only a package
    whose load-bearing claims are fresh, subject-bound and sufficiently
    independent returns ``PASS``.
    """

    if not isinstance(value, Mapping):
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_EVIDENCE_CONTRACT",
            "errors": [_error("invalid_type", "package", "mapping required")],
            "error_count": 1,
        }
    try:
        package = materialize_json(value)
    except Exception as exc:  # deterministic error surface
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_EVIDENCE_CONTRACT",
            "errors": [_error("materialization_failed", "package", type(exc).__name__)],
            "error_count": 1,
        }
    if not isinstance(package, dict):
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_EVIDENCE_CONTRACT",
            "errors": [_error("invalid_type", "package", "object required")],
            "error_count": 1,
        }

    errors: list[dict[str, str]] = []
    if package.get("contract_id") != EVIDENCE_PACKAGE_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "package.contract_id", "unexpected package contract"))
    if not verify_sealed_mapping(package, "package_sha256"):
        errors.append(_error("digest_mismatch", "package.package_sha256", "package digest mismatch"))
    tick = package.get("evaluation_tick")
    if type(tick) is not int or tick < 0:
        errors.append(_error("invalid_evaluation_tick", "package.evaluation_tick", "integer >= 0 required"))
        tick = None

    sources: dict[str, dict[str, Any]] = {}
    source_order: list[str] = []
    raw_sources = package.get("sources")
    if not isinstance(raw_sources, list):
        errors.append(_error("invalid_type", "package.sources", "array required"))
    else:
        for index, raw in enumerate(raw_sources):
            path = f"package.sources[{index}]"
            source = _sealed(raw, SOURCE_RECORD_CONTRACT_ID, "source_sha256", path, errors)
            if source is None:
                continue
            source_id = source.get("source_id")
            if not isinstance(source_id, str) or not source_id:
                errors.append(_error("missing_required", f"{path}.source_id", "source_id required"))
                continue
            if source_id in sources:
                errors.append(_error("duplicate_source_id", f"{path}.source_id", source_id))
                continue
            sources[source_id] = source
            source_order.append(source_id)
            for field in ("subject_id", "source_group", "publisher_id"):
                if not isinstance(source.get(field), str) or not source.get(field):
                    errors.append(_error("missing_required", f"{path}.{field}", f"{field} required"))
            if source.get("source_type") not in SOURCE_TYPES:
                errors.append(_error("invalid_source_type", f"{path}.source_type", "unknown source type"))
            if source.get("polarity") not in POLARITIES:
                errors.append(_error("invalid_polarity", f"{path}.polarity", "invalid polarity"))
            if source.get("attestation_level") not in ATTESTATION_LEVELS:
                errors.append(_error("invalid_attestation_level", f"{path}.attestation_level", "invalid attestation level"))
            if not _is_sha256(source.get("content_sha256")):
                errors.append(_error("invalid_content_digest", f"{path}.content_sha256", "lowercase SHA-256 required"))
            observed_at = source.get("observed_at")
            valid_until = source.get("valid_until")
            if type(observed_at) is not int or observed_at < 0:
                errors.append(_error("invalid_observed_at", f"{path}.observed_at", "integer >= 0 required"))
            if valid_until is not None and (type(valid_until) is not int or valid_until < 0):
                errors.append(_error("invalid_valid_until", f"{path}.valid_until", "integer >= 0 or null required"))
            upstream_ids = source.get("upstream_ids")
            if not isinstance(upstream_ids, list) or not all(isinstance(item, str) and item for item in upstream_ids):
                errors.append(_error("invalid_upstream_ids", f"{path}.upstream_ids", "string array required"))

    # Build a correlation graph. Same source_group, identical content or a shared
    # upstream identifier are not independent observations.
    union = _UnionFind(source_order)
    by_group: dict[str, list[str]] = defaultdict(list)
    by_content: dict[str, list[str]] = defaultdict(list)
    by_upstream: dict[str, list[str]] = defaultdict(list)
    for source_id in source_order:
        source = sources[source_id]
        group = source.get("source_group")
        digest = source.get("content_sha256")
        if isinstance(group, str):
            by_group[group].append(source_id)
        if isinstance(digest, str):
            by_content[digest].append(source_id)
        for upstream in source.get("upstream_ids", []) if isinstance(source.get("upstream_ids"), list) else []:
            by_upstream[str(upstream)].append(source_id)
    for bucket in (*by_group.values(), *by_content.values(), *by_upstream.values()):
        if bucket:
            first = bucket[0]
            for other in bucket[1:]:
                union.union(first, other)
    correlation_cluster = {source_id: union.find(source_id) for source_id in source_order}

    claim_results: list[dict[str, Any]] = []
    claim_ids: set[str] = set()
    raw_claims = package.get("claims")
    if not isinstance(raw_claims, list):
        errors.append(_error("invalid_type", "package.claims", "array required"))
    else:
        for index, raw in enumerate(raw_claims):
            path = f"package.claims[{index}]"
            claim = _sealed(raw, CLAIM_RECORD_CONTRACT_ID, "claim_sha256", path, errors)
            if claim is None:
                continue
            claim_id = claim.get("claim_id")
            if not isinstance(claim_id, str) or not claim_id:
                errors.append(_error("missing_required", f"{path}.claim_id", "claim_id required"))
                continue
            if claim_id in claim_ids:
                errors.append(_error("duplicate_claim_id", f"{path}.claim_id", claim_id))
                continue
            claim_ids.add(claim_id)
            subject_id = claim.get("subject_id")
            if not isinstance(subject_id, str) or not subject_id:
                errors.append(_error("missing_required", f"{path}.subject_id", "subject_id required"))
            if claim.get("claim_kind") not in CLAIM_KINDS:
                errors.append(_error("invalid_claim_kind", f"{path}.claim_kind", "unknown claim kind"))
            if type(claim.get("load_bearing")) is not bool:
                errors.append(_error("invalid_load_bearing", f"{path}.load_bearing", "boolean required"))
            required_groups = claim.get("required_independent_groups")
            if type(required_groups) is not int or required_groups < 1:
                errors.append(_error("invalid_required_groups", f"{path}.required_independent_groups", "integer >= 1 required"))
                required_groups = 1
            required_attestation = claim.get("required_attestation")
            if required_attestation not in ATTESTATION_LEVELS:
                errors.append(_error("invalid_required_attestation", f"{path}.required_attestation", "invalid attestation level"))
                required_attestation = "UNATTESTED"
            requires_authoritative = claim.get("requires_authoritative_adapter")
            if type(requires_authoritative) is not bool:
                errors.append(_error("invalid_authority_requirement", f"{path}.requires_authoritative_adapter", "boolean required"))
                requires_authoritative = False
            refs = claim.get("evidence_ids")
            if not isinstance(refs, list) or not all(isinstance(item, str) and item for item in refs):
                errors.append(_error("invalid_evidence_refs", f"{path}.evidence_ids", "string array required"))
                refs = []

            support_all: list[dict[str, Any]] = []
            contradiction_all: list[dict[str, Any]] = []
            support_fresh: list[dict[str, Any]] = []
            contradiction_fresh: list[dict[str, Any]] = []
            future_dated = False
            for ref in refs:
                source = sources.get(ref)
                if source is None:
                    errors.append(_error("unknown_evidence", f"{path}.evidence_ids", ref))
                    continue
                if source.get("subject_id") != subject_id:
                    errors.append(_error("evidence_subject_mismatch", f"{path}.evidence_ids", ref))
                    continue
                observed_at = source.get("observed_at")
                valid_until = source.get("valid_until")
                fresh = tick is not None and type(observed_at) is int and observed_at <= tick and (
                    valid_until is None or (type(valid_until) is int and tick < valid_until)
                )
                if tick is not None and type(observed_at) is int and observed_at > tick:
                    future_dated = True
                polarity = source.get("polarity")
                if polarity == "SUPPORTS":
                    support_all.append(source)
                    if fresh:
                        support_fresh.append(source)
                elif polarity == "CONTRADICTS":
                    contradiction_all.append(source)
                    if fresh:
                        contradiction_fresh.append(source)

            fresh_clusters = {
                correlation_cluster[str(source["source_id"])]
                for source in support_fresh
                if isinstance(source.get("source_id"), str)
            }
            authoritative_ok = any(
                source.get("source_type") == "AUTHORITATIVE_ADAPTER"
                and _attestation_at_least(source.get("attestation_level"), required_attestation)
                for source in support_fresh
            )
            attestation_ok = any(
                _attestation_at_least(source.get("attestation_level"), required_attestation)
                for source in support_fresh
            )

            if future_dated and not support_fresh:
                status = "FUTURE_DATED"
            elif support_fresh and contradiction_fresh:
                status = "CONTESTED"
            elif contradiction_fresh and not support_fresh:
                status = "REFUTED"
            elif not support_fresh and support_all:
                status = "STALE"
            elif not support_fresh:
                status = "UNVERIFIED"
            elif requires_authoritative and not authoritative_ok:
                status = "UNVERIFIED_AUTHORITY"
            elif not attestation_ok:
                status = "UNVERIFIED_AUTHORITY"
            elif len(fresh_clusters) < required_groups:
                status = "CORRELATED"
            else:
                status = "VERIFIED"
            claim_results.append(
                {
                    "claim_id": claim_id,
                    "subject_id": subject_id,
                    "load_bearing": claim.get("load_bearing") is True,
                    "status": status,
                    "fresh_support_count": len(support_fresh),
                    "fresh_contradiction_count": len(contradiction_fresh),
                    "independent_cluster_count": len(fresh_clusters),
                    "required_independent_groups": required_groups,
                    "authoritative_adapter_satisfied": authoritative_ok,
                }
            )

    if errors:
        unique: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in errors:
            key = (item["code"], item["path"], item["message"])
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_EVIDENCE_CONTRACT",
            "errors": unique,
            "error_count": len(unique),
            "claim_results": claim_results,
            "correlation_cluster": correlation_cluster,
        }

    load_bearing_failures = [
        row for row in claim_results if row["load_bearing"] and row["status"] != "VERIFIED"
    ]
    report = {
        "contract_id": EVIDENCE_REPORT_CONTRACT_ID,
        "package_sha256": package.get("package_sha256"),
        "evaluation_tick": tick,
        "claim_results": claim_results,
        "correlation_cluster": correlation_cluster,
        "load_bearing_failure_ids": [row["claim_id"] for row in load_bearing_failures],
        "report_sha256": "",
    }
    report = seal_mapping(report, "report_sha256")
    if load_bearing_failures:
        return {
            "status": "ESCALATE",
            "primary_reason": "EVIDENCE_INSUFFICIENT_OR_CONTESTED",
            "errors": [],
            "error_count": 0,
            "report": report,
        }
    return {
        "status": "PASS",
        "primary_reason": "EVIDENCE_REQUIREMENTS_SATISFIED",
        "errors": [],
        "error_count": 0,
        "report": report,
    }


__all__ = [
    "ATTESTATION_LEVELS",
    "CLAIM_RECORD_CONTRACT_ID",
    "EVIDENCE_PACKAGE_CONTRACT_ID",
    "EVIDENCE_REPORT_CONTRACT_ID",
    "SOURCE_RECORD_CONTRACT_ID",
    "seal_contract",
    "validate_evidence_package",
]
