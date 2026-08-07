import os
import sys
import json
import time
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
PROTOTYPE_DIR = BASE_DIR / "prototype"

def main():
    print("=== EXECUTING E001 SPIFFE/SPIRE REPRODUCTION SUITE ===")
    t0 = time.time()
    res = subprocess.run([sys.executable, "-m", "pytest", str(PROTOTYPE_DIR / "test_spiffe_workload_issuance.py")], capture_output=True, text=True)
    t1 = time.time()

    receipt_data = {
        "slice_id": "E001",
        "timestamp": time.time(),
        "pytest_exit_code": res.returncode,
        "execution_time_seconds": round(t1 - t0, 4),
        "stdout": res.stdout,
        "stderr": res.stderr,
        "verdict": "PASS" if res.returncode == 0 else "FAIL"
    }

    receipt_file = BASE_DIR / "receipts" / "e001_execution_receipt.json"
    with open(receipt_file, "w", encoding="utf-8") as f:
        json.dump(receipt_data, f, indent=2)

    print(f"Pytest Exit Code: {res.returncode}")
    print(f"Execution Time: {round(t1 - t0, 4)}s")
    print(f"Receipt written to: {receipt_file}")
    sys.exit(res.returncode)

if __name__ == '__main__':
    main()
