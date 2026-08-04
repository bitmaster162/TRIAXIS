"""Recovered Trust Snapshot v2 fixture builder."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from triaxis.integrity import canonical_sha256, materialize_json
from triaxis.provenance_trust_state import TRUST_SNAPSHOT_CONTRACT_ID


@dataclass(frozen=True, slots=True)
class TrustFixtureV2:
    snapshot: dict[str, Any]


def build_trust_fixture_v2(
    source: Mapping[str, Any],
    *,
    evaluation_tick: int = 5,
) -> TrustFixtureV2:
    source_value = materialize_json(source)
    snapshot = {
        "contract_id": TRUST_SNAPSHOT_CONTRACT_ID,
        "evaluation_tick": evaluation_tick,
        "source_bundle_sha256": (
            source_value.get("bundle_sha256")
            if isinstance(source_value, dict) and isinstance(source_value.get("bundle_sha256"), str)
            else canonical_sha256(source_value)
        ),
        "trust_records_sha256": canonical_sha256(
            source_value.get("provenance_registry", {}) if isinstance(source_value, dict) else {}
        ),
    }
    return TrustFixtureV2(snapshot=snapshot)


__all__ = ["TrustFixtureV2", "build_trust_fixture_v2"]
