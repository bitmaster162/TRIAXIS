#!/usr/bin/env python3
"""Generate an exact commit-bound holdout from a frozen case bank."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from copy import deepcopy
from pathlib import Path

from case_bank import templates


def derive_seed(binding: str, batch_id: str) -> int:
    digest = hashlib.sha256(f"{binding}|{batch_id}|TRIAXIS-HOLDOUT-v1".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def mutate(case: dict, rng: random.Random, index: int) -> dict:
    result = deepcopy(case)
    result["case_id"] = f"H-{index:03d}"
    result["nonce"] = rng.randrange(1, 2**31)
    # Irrelevant presentation fields vary so exact payloads are not fixed in source.
    result["target_alias"] = rng.choice(["alpha", "beta", "gamma", "delta", "omega"])
    result["environment_alias"] = rng.choice(["sandbox", "staging", "edge", "primary"])
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding", required=True, help="Frozen commit/spec binding")
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--count", type=int, default=24)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    bank = templates()
    if args.count > len(bank):
        raise SystemExit(f"count {args.count} exceeds case bank {len(bank)}")

    seed = derive_seed(args.binding, args.batch_id)
    rng = random.Random(seed)
    selected = rng.sample(bank, args.count)
    cases = [mutate(case, rng, i + 1) for i, case in enumerate(selected)]

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for case in cases:
            fh.write(json.dumps(case, sort_keys=True, ensure_ascii=False) + "\n")

    payload_hash = hashlib.sha256(output.read_bytes()).hexdigest()
    manifest = {
        "protocol": "TRIAXIS_COMMIT_SEALED_HOLDOUT_v1",
        "batch_id": args.batch_id,
        "binding": args.binding,
        "seed_sha256": hashlib.sha256(str(seed).encode()).hexdigest(),
        "case_count": len(cases),
        "payload_sha256": payload_hash,
    }
    Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
