from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

from triaxis.integrity import canonical_sha256

PROTOCOL_ID = "TRIAXIS_EXTERNAL_EXECUTION_LEDGER_CLOSURE_v3.27"
MODULES = [
    "tests.test_v3_27_external_execution_ledger",
    "tests.test_v3_27_external_execution_ledger_schemas",
]


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rows = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.rows.append({"case_id": test.id(), "status": "PASS", "error": None})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.rows.append({"case_id": test.id(), "status": "FAIL", "error": self._exc_info_to_string(err, test)})

    def addError(self, test, err):
        super().addError(test, err)
        self.rows.append({"case_id": test.id(), "status": "ERROR", "error": self._exc_info_to_string(err, test)})


def run():
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in MODULES)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=0, resultclass=RecordingResult).run(suite)
    rows = sorted(result.rows, key=lambda row: row["case_id"])
    return {
        "protocol_id": PROTOCOL_ID,
        "case_count": len(rows),
        "pass_count": sum(row["status"] == "PASS" for row in rows),
        "fail_count": sum(row["status"] != "PASS" for row in rows),
        "status": "PASS" if result.wasSuccessful() else "FAIL",
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main():
    result = run()
    path = Path("evidence/TRIAXIS_v3.27_EXTERNAL_EXECUTION_LEDGER_CLOSURE.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
