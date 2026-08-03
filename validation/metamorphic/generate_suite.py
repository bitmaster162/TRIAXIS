#!/usr/bin/env python3
"""Emit exact commit-bound metamorphic instances for a frozen candidate."""

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

from validation.metamorphic.template_bank import templates  # noqa: E402


def seed_for(binding: str, candidate_commit: str, batch_id: str) -> int:
    raw = f"{binding}|{candidate_commit}|{batch_id}|TRIAXIS-METAMORPHIC-v1".encode()
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--count", type=int, default=32)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    bank = templates()
    if args.count > len(bank):
        raise SystemExit(f"count {args.count} > bank {len(bank)}")
    rng = random.Random(seed_for(args.binding, args.candidate_commit, args.batch_id))
    selected = rng.sample(bank, args.count)

    rows = []
    for index, template in enumerate(selected, 1):
        row = deepcopy(template)
        row["case_id"] = f"M-{index:03d}"
        row["nonce"] = rng.randrange(1, 2**31)
        rows.append(row)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    payload_hash = hashlib.sha256(out.read_bytes()).hexdigest()
    manifest = {
        "protocol": "TRIAXIS_METAMORPHIC_v1",
        "batch_id": args.batch_id,
        "binding": args.binding,
        "candidate_commit": args.candidate_commit,
        "count": len(rows),
        "payload_sha256": payload_hash,
    }
    Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
