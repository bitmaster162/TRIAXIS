#!/usr/bin/env python3
"""Closure trigger for v3.8 external registry head witness."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from tests.test_v380_external_registry_anchor import AnchorFixture
from triaxis.trust_registry_anchor import TrustRegistryAnchorError


def run_trigger() -> dict:
    fx = AnchorFixture()
    rfx = fx.registry_fx
    snap1, signed1 = rfx.snapshot(1, None, [rfx.operational_record()], 5)
    snap2, signed2 = rfx.snapshot(2, snap1["snapshot_sha256"], [rfx.operational_record(revoked_at=7)], 7)
    signed_anchor = fx.signed_anchor(2, snap2["snapshot_sha256"])
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
            current = fx.load(store, signed_anchor)
            rows.append({
                "case_id": "CURRENT_HEAD_MATCHES_EXTERNAL_WITNESS",
                "expected": "PASS",
                "observed": "PASS" if current.get("key:assurance:1") is not None else "MISSING",
                "status": "PASS" if current.get("key:assurance:1") is not None else "FAIL",
                "positive_control": True,
            })
        for suffix in ("-wal", "-shm"):
            Path(str(db) + suffix).unlink(missing_ok=True)
        shutil.copy2(old, db)
        with rfx.store(db) as restored:
            try:
                fx.load(restored, signed_anchor)
                observed = "ACCEPTED"
            except TrustRegistryAnchorError as exc:
                observed = exc.code
        rows.append({
            "case_id": "RESTORED_OLD_DATABASE_VS_CURRENT_EXTERNAL_WITNESS",
            "expected": "local_registry_rollback",
            "observed": observed,
            "status": "PASS" if observed == "local_registry_rollback" else "FAIL",
        })
    passed = sum(row["status"] == "PASS" for row in rows)
    return {
        "contract_id": "TRIAXIS_WHOLE_REGISTRY_DATABASE_ROLLBACK_TRIGGER_RESULT_v2",
        "target": "TRIAXIS-v3.8-RC1-EXTERNAL-REGISTRY-ANCHOR",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
