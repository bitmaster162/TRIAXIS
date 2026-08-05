#!/usr/bin/env python3
"""Post-v3.8 trigger: replay old valid anchor with matching rolled-back DB."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from tests.test_v380_external_registry_anchor import AnchorFixture


def run_trigger() -> dict:
    fx = AnchorFixture()
    rfx = fx.registry_fx
    snap1, signed1 = rfx.snapshot(1, None, [rfx.operational_record()], 5)
    snap2, signed2 = rfx.snapshot(2, snap1["snapshot_sha256"], [rfx.operational_record(revoked_at=7)], 7)
    anchor1 = fx.signed_anchor(1, snap1["snapshot_sha256"], issued_at=5, valid_until=20)
    anchor2 = fx.signed_anchor(2, snap2["snapshot_sha256"], issued_at=8, valid_until=20)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        db = root / "registry.db"
        old = root / "seq1.db"
        with rfx.store(db) as store:
            store.install(signed1, 5)
        shutil.copy2(db, old)
        with rfx.store(db) as store:
            store.install(signed2, 8)
            current = fx.load(store, anchor2, tick=8)
            rows.append({
                "case_id": "CURRENT_DATABASE_WITH_CURRENT_WITNESS",
                "expected": "PASS",
                "observed": "PASS" if current.get("key:assurance:1") else "MISSING",
                "status": "PASS" if current.get("key:assurance:1") else "FAIL",
                "positive_control": True,
            })
        for suffix in ("-wal", "-shm"):
            Path(str(db) + suffix).unlink(missing_ok=True)
        shutil.copy2(old, db)
        with rfx.store(db) as restored:
            replayed = fx.load(restored, anchor1, tick=8)
            observed = "PASS" if replayed.get("key:assurance:1") else "MISSING"
        rows.append({
            "case_id": "ROLLED_BACK_DATABASE_PLUS_REPLAYED_OLD_WITNESS",
            "expected": "BLOCK",
            "observed": observed,
            "status": "FAIL" if observed == "PASS" else "PASS",
        })
        rows.append({
            "case_id": "WITNESS_NOT_BOUND_TO_FRESH_VERIFIER_CHALLENGE",
            "expected": "CHALLENGE_BINDING_REQUIRED",
            "observed": "TIMESTAMP_ONLY",
            "status": "FAIL",
        })
    failures = sum(row["status"] == "FAIL" for row in rows)
    return {
        "contract_id": "TRIAXIS_EXTERNAL_ANCHOR_REPLAY_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.8-RC1-EXTERNAL-REGISTRY-ANCHOR",
        "status": "FAIL" if failures else "PASS",
        "case_count": len(rows),
        "material_failure_count": failures,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
