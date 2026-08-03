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
from validation.composition_state.case_bank import templates  # noqa: E402

PROTOCOL_ID = "TRIAXIS_COMPOSITION_STATE_v1"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    bank = templates()
    if args.count > len(bank):
        raise SystemExit(f"count {args.count} > bank {len(bank)}")
    seed_material = f"{PROTOCOL_ID}|{args.protocol_commit}|{args.candidate_commit}|{args.version}|{args.batch_id}".encode()
    rng = random.Random(int.from_bytes(hashlib.sha256(seed_material).digest()[:8], "big"))
    selected = rng.sample(bank, args.count)
    rng.shuffle(selected)
    rows = []
    for index, template in enumerate(selected, 1):
        row = deepcopy(template)
        row["case_id"] = f"C-{index:03d}"
        row["nonce"] = rng.randrange(1, 2**31)
        rows.append(row)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    manifest = {
        "protocol": PROTOCOL_ID,
        "protocol_commit": args.protocol_commit,
        "candidate_commit": args.candidate_commit,
        "candidate_version": args.version,
        "batch_id": args.batch_id,
        "count": len(rows),
        "payload_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }
    Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
