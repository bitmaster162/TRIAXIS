#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from validation.input_contract.fault_bank import templates  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--count", type=int, default=28)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    raw = f"{args.binding}|{args.candidate_commit}|{args.batch_id}|TRIAXIS-INPUT-v1".encode()
    rng = random.Random(int.from_bytes(hashlib.sha256(raw).digest()[:8], "big"))
    bank = templates()
    if args.count > len(bank):
        raise SystemExit("count exceeds bank")
    selected = rng.sample(bank, args.count)
    rows = []
    for i, template in enumerate(selected, 1):
        row = deepcopy(template)
        row["case_id"] = f"I-{i:03d}"
        row["nonce"] = rng.randrange(1, 2**31)
        rows.append(row)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    manifest = {
        "protocol": "TRIAXIS_INPUT_CONTRACT_v1",
        "binding": args.binding,
        "candidate_commit": args.candidate_commit,
        "batch_id": args.batch_id,
        "count": len(rows),
        "payload_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
    }
    Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
