from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

CASES = [
    "valid_external_attestation",
    "forged_signature_blocked",
    "cross_receipt_reuse_blocked",
    "revoked_key_blocked",
    "trust_domain_blocked",
    "required_features_and_exact_binding",
]


def main() -> int:
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_v3_23_external_sandbox_attestation.py", "-v"]
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={**dict(__import__('os').environ), "PYTHONPATH": "src"})
    result = {
        "contract_id": "TRIAXIS_v3.23_EXTERNAL_SANDBOX_ATTESTATION_CLOSURE_v1",
        "status": "PASS" if proc.returncode == 0 else "BLOCK",
        "case_count": len(CASES),
        "cases": CASES,
        "test_output": proc.stdout,
    }
    out = Path("evidence/TRIAXIS_v3.23_EXTERNAL_SANDBOX_ATTESTATION_CLOSURE.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("status", "case_count")}, sort_keys=True))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
