#!/usr/bin/env python3
"""TRIAXIS v3.18 single-host multi-process deployment conformance.

This harness starts three separate Gossip Head Authority processes on loopback,
with separate Ed25519 keys, SQLite databases, ports, identities, and environment
secrets. It validates HTTP installation, challenge responses, quorum behavior,
process loss, stale state, split views, and restart persistence.

PASS proves only single-host process/network conformance. It does not prove
physical, cloud, KMS, administrator, or legal independence.
"""
from __future__ import annotations

from contextlib import ExitStack
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from triaxis.crypto_trust import (
    PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT,
    PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.integrity import seal_mapping
from triaxis.policy_head_authority import PolicyHeadAuthorityError
from triaxis.policy_transparency_floor import (
    SQLitePolicyTransparencyGossipStore,
    make_policy_transparency_floor_response,
)
from triaxis.policy_transparency_gossip_head import SQLiteGossipCheckpointIssuer
from triaxis.policy_transparency_gossip_head_quorum import (
    enforce_external_gossip_head_quorum,
    make_gossip_head_quorum_config,
)
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

CONTRACT_ID = "TRIAXIS_SINGLE_HOST_MULTIPROCESS_CONFORMANCE_v1"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http_json(method: str, url: str, body: Any = None, headers: dict[str, str] | None = None, timeout: float = 3.0) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urlopen(request, timeout=timeout) as response:
            return int(response.status), json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        payload = json.loads(exc.read().decode("utf-8"))
        return int(exc.code), payload


def _wait_health(base_url: str, timeout: float = 8.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status, payload = _http_json("GET", base_url + "/healthz", timeout=0.5)
            if status == 200:
                return payload
        except (URLError, TimeoutError, ConnectionError, OSError) as exc:
            last = exc
        time.sleep(0.05)
    raise RuntimeError(f"authority did not become healthy: {base_url}: {last}")


def _populate_gossip(path: Path, *, version: int, now: int) -> SQLitePolicyTransparencyGossipStore:
    store = SQLitePolicyTransparencyGossipStore(path)
    policy_sha = hashlib.sha256(f"policy:main:{version}".encode()).hexdigest()
    for index in range(2):
        response = make_policy_transparency_floor_response(
            witness_id=f"witness:{index}",
            log_id=f"log:{index}",
            policy_head_quorum_config_sha256="a" * 64,
            policy_id="policy:main",
            minimum_policy_version=version,
            minimum_policy_sha256=policy_sha,
            verifier_id="verifier:seed",
            verifier_epoch_sha256="b" * 64,
            challenge_sha256="c" * 64,
            requested_at=now - 2,
            issued_at=now - 1,
            valid_until=now + 3600,
        )
        store.observe(
            signer_id=f"witness-signer:{index}",
            key_id=f"witness-key:{index}",
            trust_domain=f"witness-domain:{index}",
            response=response,
            evaluation_tick=now,
        )
    return store


class AuthorityProcess:
    def __init__(self, *, root: Path, index: int, checkpoint_registry_path: Path, checkpoint_signer_id: str, checkpoint_domain: str, repo_root: Path) -> None:
        suffix = "abc"[index]
        self.index = index
        self.port = _free_port()
        self.admin_token = f"admin-token-{suffix}-with-sufficient-entropy"
        self.private_env = f"TRIAXIS_GOSSIP_HEAD_PRIVATE_KEY_{suffix.upper()}"
        self.admin_env = f"TRIAXIS_GOSSIP_HEAD_ADMIN_TOKEN_{suffix.upper()}"
        self.keypair = generate_ed25519_keypair()
        self.identity = {
            "authority_id": f"gossip-head-authority:{suffix}",
            "service_id": f"gossip-head-service:{suffix}",
            "key_id": f"key:gossip-head:{suffix}:1",
            "signer_id": f"gossip-head-signer:{suffix}",
            "trust_domain": f"single-host-simulated-domain:{suffix}",
        }
        self.root = root / f"authority-{suffix}"
        self.root.mkdir(parents=True, exist_ok=True)
        self.config_path = self.root / "config.json"
        self.db_path = self.root / "authority.db"
        self.stdout_path = self.root / "stdout.log"
        self.stderr_path = self.root / "stderr.log"
        self.repo_root = repo_root
        config = {
            **self.identity,
            "host": "127.0.0.1",
            "port": self.port,
            "db_path": str(self.db_path),
            "checkpoint_registry_path": str(checkpoint_registry_path),
            "expected_checkpoint_signer_id": checkpoint_signer_id,
            "expected_checkpoint_trust_domain": checkpoint_domain,
            "private_key_env": self.private_env,
            "admin_token_env": self.admin_env,
            "response_ttl": 30,
        }
        self.config_path.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
        self.process: subprocess.Popen[str] | None = None
        self._stdout = None
        self._stderr = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def trust_record(self, now: int) -> dict[str, Any]:
        return make_trust_key_record(
            key_id=self.identity["key_id"],
            signer_id=self.identity["signer_id"],
            trust_domain=self.identity["trust_domain"],
            public_key_b64=self.keypair["public_key_b64"],
            purposes=[PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY],
            valid_from=now - 3600,
            valid_until=now + 3600,
        )

    def start(self) -> dict[str, Any]:
        if self.process is not None and self.process.poll() is None:
            return _wait_health(self.base_url)
        env = os.environ.copy()
        env[self.private_env] = self.keypair["private_key_b64"]
        env[self.admin_env] = self.admin_token
        env["PYTHONPATH"] = str(self.repo_root / "src") + os.pathsep + str(self.repo_root)
        self._stdout = self.stdout_path.open("a", encoding="utf-8")
        self._stderr = self.stderr_path.open("a", encoding="utf-8")
        self.process = subprocess.Popen(
            [sys.executable, str(self.repo_root / "tools" / "run_gossip_head_authority.py"), "--config", str(self.config_path)],
            cwd=self.repo_root,
            env=env,
            stdout=self._stdout,
            stderr=self._stderr,
            text=True,
        )
        return _wait_health(self.base_url)

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.process = None
        if self._stdout is not None:
            self._stdout.close(); self._stdout = None
        if self._stderr is not None:
            self._stderr.close(); self._stderr = None

    def reset_database(self) -> None:
        self.stop()
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.db_path) + suffix)
            if path.exists():
                path.unlink()

    def install(self, checkpoint: dict[str, Any], *, token: str | None = None) -> tuple[int, dict[str, Any]]:
        return _http_json(
            "POST",
            self.base_url + "/v1/checkpoints/install",
            {"signed_checkpoint": checkpoint},
            {"Authorization": f"Bearer {token or self.admin_token}"},
        )

    def head(self, *, store_id: str, session: VerifierFreshnessSession, challenge: str, requested_at: int) -> dict[str, Any]:
        status, result = _http_json(
            "POST",
            self.base_url + "/v1/head/challenge",
            {
                "store_id": store_id,
                "challenge": challenge,
                "verifier_id": session.verifier_id,
                "verifier_epoch_sha256": session.epoch_sha256,
                "requested_at": requested_at,
            },
        )
        if status != 200:
            raise RuntimeError(f"head request failed: {self.identity['authority_id']}: {status}: {result}")
        return result["signed_gossip_head"]


class Harness:
    def __init__(self, root: Path, repo_root: Path) -> None:
        self.root = root
        self.repo_root = repo_root
        self.now = int(time.time())
        self.store_id = "gossip-store:deployment-conformance"
        self.checkpoint_pair = generate_ed25519_keypair()
        self.checkpoint_identity = {
            "key_id": "key:gossip-checkpoint:deployment:1",
            "signer_id": "verifier:gossip-checkpoint:deployment",
            "trust_domain": "domain:deployment-verifier",
        }
        self.checkpoint_record = make_trust_key_record(
            **self.checkpoint_identity,
            public_key_b64=self.checkpoint_pair["public_key_b64"],
            purposes=[PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT],
            valid_from=self.now - 3600,
            valid_until=self.now + 3600,
        )
        self.checkpoint_registry_path = root / "checkpoint_registry.json"
        self.checkpoint_registry_path.write_text(json.dumps([self.checkpoint_record], indent=2, sort_keys=True), encoding="utf-8")
        self.checkpoint_registry = TrustKeyRegistry([self.checkpoint_record])
        self.authorities = [
            AuthorityProcess(
                root=root,
                index=index,
                checkpoint_registry_path=self.checkpoint_registry_path,
                checkpoint_signer_id=self.checkpoint_identity["signer_id"],
                checkpoint_domain=self.checkpoint_identity["trust_domain"],
                repo_root=repo_root,
            )
            for index in range(3)
        ]
        authority_records = [authority.trust_record(self.now) for authority in self.authorities]
        self.authority_registry = TrustKeyRegistry(authority_records)
        self.quorum_config = make_gossip_head_quorum_config(
            config_id="gossip-head-quorum:deployment-conformance",
            authority_set_id="gossip-head-set:single-host-simulation",
            store_id=self.store_id,
            threshold=2,
            authorities=[authority.identity for authority in self.authorities],
            valid_from=self.now - 60,
            valid_until=self.now + 3600,
        )
        self.stack = ExitStack()
        self.low = _populate_gossip(root / "low-gossip.db", version=2, now=self.now)
        self.high = _populate_gossip(root / "high-gossip.db", version=3, now=self.now)
        self.stack.callback(self.low.close)
        self.stack.callback(self.high.close)
        issuer_path = root / "checkpoint-issuer.db"
        issuer1 = SQLiteGossipCheckpointIssuer(
            issuer_path,
            gossip_store=self.low,
            store_id=self.store_id,
            verifier_id="verifier:deployment-conformance",
            private_key_b64=self.checkpoint_pair["private_key_b64"],
            **self.checkpoint_identity,
        )
        self.checkpoint1 = issuer1.issue(issued_at=self.now - 5, valid_until=self.now + 3600)
        issuer1.close()
        issuer2 = SQLiteGossipCheckpointIssuer(
            issuer_path,
            gossip_store=self.high,
            store_id=self.store_id,
            verifier_id="verifier:deployment-conformance",
            private_key_b64=self.checkpoint_pair["private_key_b64"],
            **self.checkpoint_identity,
        )
        self.checkpoint2 = issuer2.issue(issued_at=self.now - 4, valid_until=self.now + 3600)
        issuer2.close()
        self.case_index = 0
        self.cases: list[dict[str, Any]] = []

    def close(self) -> None:
        for authority in self.authorities:
            authority.stop()
        self.stack.close()

    def record(self, case_id: str, status: str, observed: Any, expected: str) -> None:
        self.cases.append({"case_id": case_id, "status": status, "expected": expected, "observed": observed})

    def challenge(self, active: list[AuthorityProcess], *, expected_pass: bool) -> tuple[str, Any]:
        self.case_index += 1
        now = int(time.time())
        session = VerifierFreshnessSession.create(f"verifier:deployment:{self.case_index}", now)
        ledger = SQLiteEpochChallengeLedger(self.root / f"challenge-{self.case_index}.db", session)
        challenge = ledger.issue(now, now + 30)
        responses = []
        for authority in active:
            try:
                responses.append(authority.head(store_id=self.store_id, session=session, challenge=challenge, requested_at=now))
            except Exception:
                continue
        try:
            result = enforce_external_gossip_head_quorum(
                gossip_store=self.high,
                store_id=self.store_id,
                signed_checkpoint=self.checkpoint2,
                signed_head_responses=responses,
                checkpoint_registry=self.checkpoint_registry,
                authority_registry=self.authority_registry,
                expected_checkpoint_signer_id=self.checkpoint_identity["signer_id"],
                expected_checkpoint_trust_domain=self.checkpoint_identity["trust_domain"],
                quorum_config=self.quorum_config,
                expected_quorum_config_sha256=self.quorum_config["config_sha256"],
                challenge_ledger=ledger,
                expected_challenge=challenge,
                evaluation_tick=int(time.time()),
                max_response_age=10,
            )
            if not expected_pass:
                raise AssertionError("quorum unexpectedly passed")
            return "PASS", result
        except PolicyHeadAuthorityError as exc:
            if expected_pass:
                raise
            return "BLOCK", {"code": exc.code, "detail": exc.detail, "response_count": len(responses)}
        finally:
            ledger.close()

    def run(self) -> dict[str, Any]:
        health = [authority.start() for authority in self.authorities]
        distinct = {
            "process_ids": len({item["process_id"] for item in health}),
            "authority_ids": len({item["authority_id"] for item in health}),
            "key_ids": len({item["key_id"] for item in health}),
            "trust_domains": len({item["trust_domain"] for item in health}),
            "ports": len({authority.port for authority in self.authorities}),
            "db_paths": len({str(authority.db_path) for authority in self.authorities}),
        }
        if any(value != 3 for value in distinct.values()):
            raise AssertionError(f"process separation failed: {distinct}")
        self.record("MP01_DISTINCT_PROCESS_BOUNDARIES", "PASS", distinct, "3 distinct values for each local boundary")

        denied, denied_result = self.authorities[0].install(self.checkpoint1, token="wrong-token")
        if denied != 403:
            raise AssertionError((denied, denied_result))
        self.record("MP02_ADMIN_INSTALL_AUTH", "PASS", denied_result, "wrong bearer token is denied")

        for authority in self.authorities:
            for checkpoint in (self.checkpoint1, self.checkpoint2):
                status, result = authority.install(checkpoint)
                if status != 200:
                    raise AssertionError((authority.identity, status, result))
        outcome, result = self.challenge(self.authorities, expected_pass=True)
        self.record("MP03_HEALTHY_2_OF_3_QUORUM", "PASS", {"outcome": outcome, "members": len(result["quorum"]["members"])}, "current checkpoint accepted")

        self.authorities[2].stop()
        outcome, result = self.challenge(self.authorities[:2], expected_pass=True)
        self.record("MP04_ONE_PROCESS_UNAVAILABLE", "PASS", {"outcome": outcome, "members": len(result["quorum"]["members"])}, "2-of-3 remains available")

        self.authorities[1].stop()
        outcome, result = self.challenge([self.authorities[0]], expected_pass=False)
        self.record("MP05_TWO_PROCESSES_UNAVAILABLE", "PASS", {"outcome": outcome, **result}, "one response cannot meet threshold")

        self.authorities[1].start()
        self.authorities[2].reset_database()
        self.authorities[2].start()
        status, stale_install = self.authorities[2].install(self.checkpoint1)
        if status != 200:
            raise AssertionError(stale_install)
        outcome, result = self.challenge(self.authorities, expected_pass=True)
        self.record("MP06_ONE_STALE_AUTHORITY", "PASS", {"outcome": outcome, "members": len(result["quorum"]["members"])}, "two current authorities override one stale authority")

        self.authorities[1].stop()
        outcome, result = self.challenge([self.authorities[0], self.authorities[2]], expected_pass=False)
        self.record("MP07_SPLIT_VIEW_WITHOUT_THRESHOLD", "PASS", {"outcome": outcome, **result}, "one current plus one stale is blocked")

        self.authorities[1].start()
        before = _wait_health(self.authorities[0].base_url)
        self.authorities[0].stop()
        after = self.authorities[0].start()
        if before["process_id"] == after["process_id"]:
            raise AssertionError("process id did not change after restart")
        if after["current"]["checkpoint_sequence"] != 2:
            raise AssertionError(after)
        outcome, result = self.challenge(self.authorities[:2], expected_pass=True)
        self.record("MP08_RESTART_PERSISTS_HEAD", "PASS", {"old_pid": before["process_id"], "new_pid": after["process_id"], "outcome": outcome}, "same DB preserves current checkpoint across process restart")

        if any("private" in json.dumps(item).lower() for item in health):
            raise AssertionError("health response leaked private-key marker")
        self.record("MP09_HEALTH_SECRET_MINIMIZATION", "PASS", "no private-key fields", "health response excludes private key material")

        return seal_mapping({
            "contract_id": CONTRACT_ID,
            "status": "PASS",
            "claim_scope": "single-host multi-process loopback conformance only",
            "conformance_level": "SINGLE_HOST_MULTIPROCESS",
            "physical_independence": False,
            "administrative_independence": False,
            "transport_authentication": "NONE_LOOPBACK_ONLY",
            "key_custody": "PROCESS_ENVIRONMENT_LAB_ONLY",
            "host": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "parent_process_id": os.getpid(),
            },
            "authority_count": 3,
            "threshold": 2,
            "cases": self.cases,
            "limitations": [
                "all authority processes executed under one OS host and one user",
                "trust_domain labels are simulated and do not prove physical independence",
                "private keys were process environment secrets, not KMS/HSM-backed",
                "transport was loopback HTTP without mTLS",
                "no cloud/provider/network/administrator independence is claimed",
                "deploy_permission remained DENY; no user server was modified",
            ],
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "receipt_sha256": "",
        }, "receipt_sha256")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--workdir")
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    owned_tmp = None
    if args.workdir:
        root = Path(args.workdir).resolve()
        root.mkdir(parents=True, exist_ok=True)
    else:
        owned_tmp = tempfile.TemporaryDirectory(prefix="triaxis-v318-")
        root = Path(owned_tmp.name)
    harness = Harness(root, repo_root)
    try:
        receipt = harness.run()
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps({"status": receipt["status"], "cases": len(receipt["cases"]), "receipt_sha256": receipt["receipt_sha256"], "output": str(output)}, sort_keys=True))
    finally:
        harness.close()
        if owned_tmp is not None:
            owned_tmp.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
