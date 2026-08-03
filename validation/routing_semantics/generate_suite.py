#!/usr/bin/env python3
"""Generate a commit-bound routing-semantics batch."""

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

from validation.routing_semantics.template_bank import templates  # noqa: E402

PROTOCOL_ID = "TRIAXIS_ROUTING_SEMANTICS_v1"


def seed_for(framework_commit: str, candidate_commit: str, version: str, batch_id: str) -> int:
    raw = f"{PROTOCOL_ID}|{framework_commit}|{candidate_commit}|{version}|{batch_id}".encode()
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    bank = templates()
    if args.count > len(bank):
        raise SystemExit(f"count {args.count} > bank {len(bank)}")

    rng = random.Random(seed_for(args.framework_commit, args.candidate_commit, args.version, args.batch_id))

    # Stratify so every material family is represented before filling randomly.
    by_family: dict[str, list[dict]] = {}
    for row in bank:
        by_family.setdefault(row["family"], []).append(row)
    selected: list[dict] = []
    for family in sorted(by_family):
        selected.append(rng.choice(by_family[family]))
    remaining = [row for row in bank if row not in selected]
    needed = args.count - len(selected)
    if needed < 0:
        raise SystemExit(f"count {args.count} is smaller than family count {len(selected)}")
    selected.extend(rng.sample(remaining, needed))
    rng.shuffle(selected)

    rows = []
    for index, template in enumerate(selected, 1):
        row = deepcopy(template)
        row["case_id"] = f"R-{index:03d}"
        row["scenario"]["nonce"] = rng.randrange(1, 2**31)
        rows.append(row)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    payload_hash = hashlib.sha256(output.read_bytes()).hexdigest()
    manifest = {
        "protocol": PROTOCOL_ID,
        "framework_commit": args.framework_commit,
        "candidate_commit": args.candidate_commit,
        "candidate_version": args.version,
        "batch_id": args.batch_id,
        "count": len(rows),
        "payload_sha256": payload_hash,
    }
    Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
