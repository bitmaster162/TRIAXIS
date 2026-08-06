#!/usr/bin/env python3
"""Confirm the exact v3.18 single-host compromise boundary without exposing secrets."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any


def _load_harness(subject_repo: Path) -> Any:
    sys.path.insert(0, str(subject_repo / "src"))
    sys.path.insert(0, str(subject_repo))
    script = subject_repo / "validation" / "deployment_conformance" / "run_v318_single_host_conformance.py"
    spec = importlib.util.spec_from_file_location("triaxis_v318_exact_harness", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load exact v3.18 harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _uid_for(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    raise RuntimeError(f"Uid not found for pid {pid}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject-repo", required=True)
    parser.add_argument("--subject-commit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    subject_repo = Path(args.subject_repo).resolve()
    module = _load_harness(subject_repo)
    from triaxis.integrity import seal_mapping

    with tempfile.TemporaryDirectory(prefix="triaxis-v318-boundary-") as tmp:
        harness = module.Harness(Path(tmp), subject_repo)
        try:
            health = [authority.start() for authority in harness.authorities]
            pids = [int(item["process_id"]) for item in health]
            uids = [_uid_for(pid) for pid in pids]
            parent_uid = os.geteuid()
            environment_access = []
            writable_state = []
            signal_access = []
            for authority, pid in zip(harness.authorities, pids):
                environ = Path(f"/proc/{pid}/environ").read_bytes()
                environment_access.append({
                    "authority_id": authority.identity["authority_id"],
                    "private_key_variable_name_visible": authority.private_env.encode() + b"=" in environ,
                    "admin_token_variable_name_visible": authority.admin_env.encode() + b"=" in environ,
                    "secret_values_recorded": False,
                })
                writable_state.append(os.access(authority.db_path.parent, os.W_OK))
                try:
                    os.kill(pid, 0)
                    signal_access.append(True)
                except OSError:
                    signal_access.append(False)

            machine_id_path = Path("/etc/machine-id")
            machine_material = machine_id_path.read_bytes() if machine_id_path.exists() else os.uname().nodename.encode()
            host_fingerprint = hashlib.sha256(machine_material).hexdigest()
            boundary_confirmed = (
                len(set(uids)) == 1
                and uids[0] == parent_uid
                and all(item["private_key_variable_name_visible"] for item in environment_access)
                and all(item["admin_token_variable_name_visible"] for item in environment_access)
                and all(writable_state)
                and all(signal_access)
            )
            result = seal_mapping({
                "contract_id": "TRIAXIS_v3.18_POSTCOMMIT_SINGLE_HOST_COMPROMISE_BOUNDARY_v1",
                "subject_commit": args.subject_commit,
                "status": "BOUNDARY_CONFIRMED" if boundary_confirmed else "INCONCLUSIVE",
                "host_fingerprint_sha256": host_fingerprint,
                "parent_uid": parent_uid,
                "authority_pids": pids,
                "authority_uids": uids,
                "all_authorities_share_one_uid": len(set(uids)) == 1,
                "parent_can_read_process_environment_names": all(
                    item["private_key_variable_name_visible"] and item["admin_token_variable_name_visible"]
                    for item in environment_access
                ),
                "parent_can_write_all_state_directories": all(writable_state),
                "parent_can_signal_all_authority_processes": all(signal_access),
                "environment_observations": environment_access,
                "raw_secret_values_recorded": False,
                "security_conclusion": (
                    "one compromise of the shared OS user/host can reach all three laboratory authority "
                    "processes; single-host process separation is not physical or administrative independence"
                ),
                "required_next_evidence": [
                    "three separately administered hosts or providers",
                    "separate KMS/HSM-backed authority keys",
                    "authenticated transport between verifier and authorities",
                    "independent state and backup domains",
                    "physical failure and compromise drills",
                ],
                "can_trade": False,
                "capital_permission": "DENY",
                "deploy_permission": "DENY",
                "evidence_sha256": "",
            }, "evidence_sha256")
        finally:
            harness.close()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": result["status"], "evidence_sha256": result["evidence_sha256"], "output": str(output)}, sort_keys=True))
    return 0 if result["status"] == "BOUNDARY_CONFIRMED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
