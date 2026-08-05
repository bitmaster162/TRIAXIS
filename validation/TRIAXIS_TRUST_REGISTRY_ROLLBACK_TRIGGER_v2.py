#!/usr/bin/env python3
"""Closure trigger for v3.7 monotonic trust-registry state."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from tests.test_v370_monotonic_trust_registry import RegistryFixture
from triaxis.crypto_trust import PURPOSE_ASSURANCE_ATTESTATION, verify_contract_envelope
from triaxis.trust_registry_state import TrustRegistryStateError


def run_trigger() -> dict:
    fx = RegistryFixture()
    snap1, signed1 = fx.snapshot(1, None, [fx.operational_record()], 5)
    _, signed2 = fx.snapshot(2, snap1["snapshot_sha256"], [fx.operational_record(revoked_at=7)], 7)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "registry.db"
        with fx.store(path) as store:
            head1 = store.install(signed1, 5)
            head2 = store.install(signed2, 8)
            registry = store.load_registry(8)
            verified = verify_contract_envelope(
                fx.signed_attestation(),
                registry=registry,
                evaluation_tick=8,
                expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
                expected_digest_field="attestation_sha256",
            )
            rows.append({
                "case_id": "REVOCATION_HEAD_BLOCKS_OLD_KEY",
                "expected": "BLOCK",
                "observed": verified["status"],
                "status": "PASS" if verified["status"] == "BLOCK" else "FAIL",
                "positive_control": True,
            })
            try:
                store.install(signed1, 8)
                rollback = "ACCEPTED"
            except TrustRegistryStateError as exc:
                rollback = exc.code
            rows.append({
                "case_id": "OLD_SNAPSHOT_REINSTALL",
                "expected": "registry_rollback",
                "observed": rollback,
                "status": "PASS" if rollback == "registry_rollback" else "FAIL",
            })
            rows.append({
                "case_id": "SEQUENCE_ADVANCES_EXACTLY",
                "expected": 2,
                "observed": head2["sequence"],
                "status": "PASS" if head1["sequence"] == 1 and head2["sequence"] == 2 else "FAIL",
            })
        with fx.store(path) as restarted:
            restart_head = restarted.head()
            try:
                restarted.install(signed1, 8)
                restart_rollback = "ACCEPTED"
            except TrustRegistryStateError as exc:
                restart_rollback = exc.code
            rows.append({
                "case_id": "RESTART_PRESERVES_HEAD",
                "expected": "sequence=2;rollback=blocked",
                "observed": f"sequence={restart_head['sequence']};rollback={restart_rollback}",
                "status": "PASS" if restart_head["sequence"] == 2 and restart_rollback == "registry_rollback" else "FAIL",
            })

    passed = sum(row["status"] == "PASS" for row in rows)
    return {
        "contract_id": "TRIAXIS_TRUST_REGISTRY_ROLLBACK_TRIGGER_RESULT_v2",
        "target": "TRIAXIS-v3.7-RC1-MONOTONIC-TRUST-REGISTRY",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
