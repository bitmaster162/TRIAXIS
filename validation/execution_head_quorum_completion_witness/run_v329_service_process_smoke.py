from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from triaxis.crypto_trust import (
    PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
    PURPOSE_EXECUTION_RECEIPT,
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.execution_ledger_head_quorum import (
    make_execution_ledger_head_quorum_config,
    verify_execution_ledger_head_quorum,
)
from triaxis.external_execution_ledger import SQLiteExternalExecutionLedger
from triaxis.integrity import canonical_sha256
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

LEDGER_ID = "ledger:v329:service-smoke"
LEDGER_AUTHORITY_ID = "authority:ledger:v329:service-smoke"
LEDGER_SIGNER_ID = "signer:ledger:v329:service-smoke"
LEDGER_DOMAIN = "domain:ledger:v329:service-smoke"


def http_json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def start_process(command: list[str], env: dict[str, str]) -> tuple[subprocess.Popen[str], dict[str, Any]]:
    process = subprocess.Popen(
        command,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if process.stdout is None:
        raise RuntimeError("stdout pipe unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    events = selector.select(timeout=10)
    selector.close()
    if not events:
        process.terminate()
        _, stderr = process.communicate(timeout=5)
        raise RuntimeError(f"service startup timeout: {stderr}")
    line = process.stdout.readline().strip()
    if not line:
        process.terminate()
        _, stderr = process.communicate(timeout=5)
        raise RuntimeError(f"service produced no startup receipt: {stderr}")
    payload = json.loads(line)
    if payload.get("status") != "listening":
        process.terminate()
        _, stderr = process.communicate(timeout=5)
        raise RuntimeError(f"service startup failed: {payload} {stderr}")
    return process, payload


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run() -> dict[str, Any]:
    root = Path.cwd().resolve()
    rows: list[dict[str, Any]] = []
    processes: list[subprocess.Popen[str]] = []
    with tempfile.TemporaryDirectory(prefix="triaxis-v329-service-smoke-") as td:
        work = Path(td)
        now = int(time.time())
        ledger_pair = generate_ed25519_keypair()
        ledger_record = make_trust_key_record(
            key_id="key:ledger:v329:service-smoke",
            signer_id=LEDGER_SIGNER_ID,
            trust_domain=LEDGER_DOMAIN,
            public_key_b64=ledger_pair["public_key_b64"],
            purposes=[PURPOSE_EXECUTION_RECEIPT],
            valid_from=0,
            valid_until=4_102_444_800,
        )
        ledger_keys_path = work / "ledger-public-keys.json"
        ledger_keys_path.write_text(json.dumps([ledger_record], indent=2) + "\n", encoding="utf-8")
        head_records: list[dict[str, Any]] = []
        authority_rows: list[dict[str, str]] = []
        head_services: list[dict[str, Any]] = []
        common_env = os.environ.copy()
        common_env["PYTHONPATH"] = f"{root / 'src'}:{root}"

        try:
            for index, suffix in enumerate(("a", "b", "c")):
                pair = generate_ed25519_keypair()
                row = {
                    "authority_id": f"authority:execution-head:v329:service-smoke:{suffix}",
                    "service_id": f"service:execution-head:v329:service-smoke:{suffix}",
                    "key_id": f"key:execution-head:v329:service-smoke:{suffix}",
                    "signer_id": f"signer:execution-head:v329:service-smoke:{suffix}",
                    "trust_domain": f"domain:execution-head:v329:service-smoke:{suffix}",
                }
                authority_rows.append(row)
                head_records.append(
                    make_trust_key_record(
                        key_id=row["key_id"],
                        signer_id=row["signer_id"],
                        trust_domain=row["trust_domain"],
                        public_key_b64=pair["public_key_b64"],
                        purposes=[PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY],
                        valid_from=0,
                        valid_until=4_102_444_800,
                    )
                )
                token = f"head-admin-token-{suffix}"
                env = common_env | {
                    "TRIAXIS_ELH_DB": str(work / f"head-{suffix}.sqlite"),
                    "TRIAXIS_ELH_LEDGER_KEYS_JSON": str(ledger_keys_path),
                    "TRIAXIS_ELH_EXPECTED_LEDGER_SIGNER_ID": LEDGER_SIGNER_ID,
                    "TRIAXIS_ELH_EXPECTED_LEDGER_TRUST_DOMAIN": LEDGER_DOMAIN,
                    "TRIAXIS_ELH_AUTHORITY_ID": row["authority_id"],
                    "TRIAXIS_ELH_SERVICE_ID": row["service_id"],
                    "TRIAXIS_ELH_KEY_ID": row["key_id"],
                    "TRIAXIS_ELH_SIGNER_ID": row["signer_id"],
                    "TRIAXIS_ELH_TRUST_DOMAIN": row["trust_domain"],
                    "TRIAXIS_ELH_PRIVATE_KEY_B64": pair["private_key_b64"],
                    "TRIAXIS_ELH_ADMIN_TOKEN": token,
                    "TRIAXIS_ELH_HOST": "127.0.0.1",
                    "TRIAXIS_ELH_PORT": "0",
                    "TRIAXIS_ELH_RESPONSE_TTL": "30",
                }
                process, startup = start_process(
                    ["python", "tools/run_execution_ledger_head_authority.py"], env
                )
                processes.append(process)
                head_services.append({"startup": startup, "token": token})

            provider_pair = generate_ed25519_keypair()
            provider_record = make_trust_key_record(
                key_id="key:provider:v329:service-smoke",
                signer_id="signer:provider:v329:service-smoke",
                trust_domain="domain:provider:v329:service-smoke",
                public_key_b64=provider_pair["public_key_b64"],
                purposes=[PURPOSE_PROVIDER_EFFECT_RECEIPT],
                valid_from=0,
                valid_until=4_102_444_800,
            )
            provider_keys_path = work / "provider-public-keys.json"
            provider_keys_path.write_text(
                json.dumps([provider_record], indent=2) + "\n", encoding="utf-8"
            )
            witness_pair = generate_ed25519_keypair()
            witness_token = "completion-witness-client-token"
            witness_env = common_env | {
                "TRIAXIS_ECW_DB": str(work / "completion-witness.sqlite"),
                "TRIAXIS_ECW_PROVIDER_KEYS_JSON": str(provider_keys_path),
                "TRIAXIS_ECW_EXPECTED_PROVIDER_SIGNER_ID": provider_record["signer_id"],
                "TRIAXIS_ECW_EXPECTED_PROVIDER_TRUST_DOMAIN": provider_record["trust_domain"],
                "TRIAXIS_ECW_WITNESS_ID": "completion-witness:v329:service-smoke",
                "TRIAXIS_ECW_AUTHORITY_ID": "authority:completion-witness:v329:service-smoke",
                "TRIAXIS_ECW_SERVICE_ID": "service:completion-witness:v329:service-smoke",
                "TRIAXIS_ECW_KEY_ID": "key:completion-witness:v329:service-smoke",
                "TRIAXIS_ECW_SIGNER_ID": "signer:completion-witness:v329:service-smoke",
                "TRIAXIS_ECW_TRUST_DOMAIN": "domain:completion-witness:v329:service-smoke",
                "TRIAXIS_ECW_PRIVATE_KEY_B64": witness_pair["private_key_b64"],
                "TRIAXIS_ECW_CLIENT_TOKEN": witness_token,
                "TRIAXIS_ECW_HOST": "127.0.0.1",
                "TRIAXIS_ECW_PORT": "0",
                "TRIAXIS_ECW_RESPONSE_TTL": "30",
            }
            witness_process, witness_startup = start_process(
                ["python", "tools/run_external_completion_witness.py"], witness_env
            )
            processes.append(witness_process)

            ledger_registry = TrustKeyRegistry([ledger_record])
            head_registry = TrustKeyRegistry(head_records)
            with SQLiteExternalExecutionLedger(
                work / "ledger.sqlite",
                ledger_id=LEDGER_ID,
                authority_id=LEDGER_AUTHORITY_ID,
                key_id=ledger_record["key_id"],
                signer_id=LEDGER_SIGNER_ID,
                trust_domain=LEDGER_DOMAIN,
                private_key_b64=ledger_pair["private_key_b64"],
                receipt_ttl=300,
            ) as ledger:
                signed_head = ledger.head(now_tick=now)
                for service in head_services:
                    port = service["startup"]["port"]
                    status, payload = http_json(
                        "POST",
                        f"http://127.0.0.1:{port}/v1/heads/install",
                        {"signed_head": signed_head, "signed_events": []},
                        service["token"],
                    )
                    if status != 200:
                        raise RuntimeError(f"head install failed: {status} {payload}")

                session = VerifierFreshnessSession.create("verifier:v329:service-smoke", now - 1)
                with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                    challenge = challenges.issue(now, now + 30)
                    responses = []
                    for service in head_services:
                        port = service["startup"]["port"]
                        status, payload = http_json(
                            "POST",
                            f"http://127.0.0.1:{port}/v1/head/challenge",
                            {
                                "ledger_id": LEDGER_ID,
                                "challenge": challenge,
                                "verifier_id": session.verifier_id,
                                "verifier_epoch_sha256": session.epoch_sha256,
                                "requested_at": now,
                            },
                        )
                        if status != 200:
                            raise RuntimeError(f"head challenge failed: {status} {payload}")
                        responses.append(payload["signed_execution_ledger_head"])
                    config = make_execution_ledger_head_quorum_config(
                        config_id="execution-head-quorum:v329:service-smoke",
                        authority_set_id="execution-head-authorities:v329:service-smoke",
                        ledger_id=LEDGER_ID,
                        threshold=2,
                        authorities=authority_rows,
                        valid_from=0,
                        valid_until=4_102_444_800,
                    )
                    verify_tick = int(time.time())
                    quorum = verify_execution_ledger_head_quorum(
                        ledger.head(now_tick=verify_tick),
                        responses,
                        ledger_registry=ledger_registry,
                        authority_registry=head_registry,
                        expected_ledger_id=LEDGER_ID,
                        expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                        expected_ledger_signer_id=LEDGER_SIGNER_ID,
                        expected_ledger_trust_domain=LEDGER_DOMAIN,
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        challenge_ledger=challenges,
                        expected_challenge=challenge,
                        evaluation_tick=verify_tick,
                        max_response_age=10,
                    )
                    rows.append(
                        {
                            "case_id": "V329SP01_THREE_HEAD_PROCESSES_FORM_2_OF_3_QUORUM",
                            "process_count": len(head_services),
                            "quorum_status": quorum["status"],
                            "member_count": quorum["quorum_witness"]["member_count"],
                            "status": "PASS"
                            if quorum["status"] == "PASS"
                            and quorum["quorum_witness"]["member_count"] == 3
                            else "FAIL",
                        }
                    )

            witness_port = witness_startup["port"]
            health_status, health = http_json(
                "GET", f"http://127.0.0.1:{witness_port}/healthz"
            )
            health_text = json.dumps(health, sort_keys=True).lower()
            rows.append(
                {
                    "case_id": "V329SP02_COMPLETION_WITNESS_PROCESS_HEALTH_MINIMIZES_SECRETS",
                    "http_status": health_status,
                    "contains_private": "private" in health_text,
                    "contains_token": "token" in health_text,
                    "status": "PASS"
                    if health_status == 200
                    and "private" not in health_text
                    and "token" not in health_text
                    else "FAIL",
                }
            )
            effect_id = canonical_sha256({"effect": "v329-service-smoke"})
            payload_sha256 = canonical_sha256({"payload": "v329-service-smoke"})
            reserve_body = {
                "effect_id": effect_id,
                "payload_sha256": payload_sha256,
                "provider_id": "provider:v329:service-smoke",
                "provider_service_id": "service:provider:v329:service-smoke",
                "provider_request_id": "provider-request:v329:service-smoke",
            }
            denied_status, _ = http_json(
                "POST",
                f"http://127.0.0.1:{witness_port}/v1/effects/reserve",
                reserve_body,
            )
            accepted_status, accepted = http_json(
                "POST",
                f"http://127.0.0.1:{witness_port}/v1/effects/reserve",
                reserve_body,
                witness_token,
            )
            rows.append(
                {
                    "case_id": "V329SP03_COMPLETION_WITNESS_PROCESS_ENFORCES_MUTATION_AUTH",
                    "denied_status": denied_status,
                    "accepted_status": accepted_status,
                    "external_effect_permitted": accepted.get("external_effect_permitted"),
                    "status": "PASS"
                    if denied_status == 403
                    and accepted_status == 200
                    and accepted.get("external_effect_permitted") is True
                    else "FAIL",
                }
            )
        finally:
            for process in reversed(processes):
                terminate(process)

    result = {
        "protocol_id": "TRIAXIS_v3.29_SERVICE_PROCESS_SMOKE",
        "case_count": len(rows),
        "pass_count": sum(row["status"] == "PASS" for row in rows),
        "fail_count": sum(row["status"] != "PASS" for row in rows),
        "status": "PASS" if rows and all(row["status"] == "PASS" for row in rows) else "FAIL",
        "authority_granted": False,
        "production_qualified": False,
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }
    return result


def main() -> int:
    result = run()
    path = Path("evidence/TRIAXIS_v3.29_SERVICE_PROCESS_SMOKE.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
