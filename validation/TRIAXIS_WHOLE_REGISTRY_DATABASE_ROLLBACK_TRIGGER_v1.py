#!/usr/bin/env python3
"""Post-v3.7 trigger: restoring the whole local registry DB erases its head."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from tests.test_v370_monotonic_trust_registry import RegistryFixture
from triaxis.crypto_trust import PURPOSE_ASSURANCE_ATTESTATION, verify_contract_envelope


def verify_old_key(fx: RegistryFixture, registry, tick: int) -> str:
    return verify_contract_envelope(
        fx.signed_attestation(),
        registry=registry,
        evaluation_tick=tick,
        expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
        expected_digest_field="attestation_sha256",
    )["status"]


def run_trigger() -> dict:
    fx = RegistryFixture()
    snap1, signed1 = fx.snapshot(1, None, [fx.operational_record()], 5)
    _, signed2 = fx.snapshot(2, snap1["snapshot_sha256"], [fx.operational_record(revoked_at=7)], 7)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        db = root / "registry.db"
        old = root / "registry-seq1.db"

        with fx.store(db) as store:
            store.install(signed1, 5)
        shutil.copy2(db, old)

        with fx.store(db) as store:
            store.install(signed2, 8)
            current_status = verify_old_key(fx, store.load_registry(8), 8)
        rows.append({
            "case_id": "CURRENT_DATABASE_BLOCKS_REVOKED_KEY",
            "expected": "BLOCK",
            "observed": current_status,
            "status": "PASS" if current_status == "BLOCK" else "FAIL",
            "positive_control": True,
        })

        for suffix in ("-wal", "-shm"):
            Path(str(db) + suffix).unlink(missing_ok=True)
        shutil.copy2(old, db)

        with fx.store(db) as restored:
            restored_head = restored.head()
            restored_status = verify_old_key(fx, restored.load_registry(8), 8)
        rows.append({
            "case_id": "WHOLE_DATABASE_ROLLBACK_RESURRECTS_KEY",
            "expected": "BLOCK",
            "observed": restored_status,
            "restored_sequence": restored_head["sequence"],
            "status": "FAIL" if restored_status == "PASS" else "PASS",
        })
        rows.append({
            "case_id": "NO_EXTERNAL_HEAD_WITNESS",
            "expected": "EXTERNAL_ANCHOR_REQUIRED",
            "observed": "LOCAL_DB_IS_ITS_OWN_AUTHORITY",
            "status": "FAIL",
        })

    failures = sum(row["status"] == "FAIL" for row in rows)
    return {
        "contract_id": "TRIAXIS_WHOLE_REGISTRY_DATABASE_ROLLBACK_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.7-RC1-MONOTONIC-TRUST-REGISTRY",
        "status": "FAIL" if failures else "PASS",
        "case_count": len(rows),
        "material_failure_count": failures,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
