from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from triaxis.completion_witness_quorum import (
    CompletionWitnessQuorumError,
    make_completion_witness_quorum_config,
    verify_completion_witness_quorum,
)
from triaxis.completion_worm_anchor import (
    CompletionWORMAnchorError,
    verify_completion_worm_anchor_status,
)
from triaxis.crypto_trust import (
    PURPOSE_COMPLETION_WORM_ANCHOR,
    PURPOSE_EXTERNAL_COMPLETION_WITNESS,
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.idempotent_effect_provider import SQLiteIdempotentEffectProvider
from triaxis.integrity import canonical_sha256
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession

PROVIDER_ID = "provider:v330:service-smoke"
PROVIDER_SERVICE_ID = "service:provider:v330:service-smoke"
PROVIDER_SIGNER_ID = "signer:provider:v330:service-smoke"
PROVIDER_DOMAIN = "domain:provider:v330:service-smoke"
ANCHOR_ID = "completion-worm-anchor:v330:service-smoke"
ANCHOR_AUTHORITY_ID = "authority:completion-worm-anchor:v330:service-smoke"
ANCHOR_SERVICE_ID = "service:completion-worm-anchor:v330:service-smoke"
ANCHOR_SIGNER_ID = "signer:completion-worm-anchor:v330:service-smoke"
ANCHOR_DOMAIN = "domain:completion-worm-anchor:v330:service-smoke"


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
    with tempfile.TemporaryDirectory(prefix="triaxis-v330-service-smoke-") as td:
        work = Path(td)
        now = int(time.time())
        common_env = os.environ.copy()
        common_env["PYTHONPATH"] = f"{root / 'src'}:{root}"
        common_env.setdefault("TERM", "xterm")

        provider_pair = generate_ed25519_keypair()
        provider_record = make_trust_key_record(
            key_id="key:provider:v330:service-smoke",
            signer_id=PROVIDER_SIGNER_ID,
            trust_domain=PROVIDER_DOMAIN,
            public_key_b64=provider_pair["public_key_b64"],
            purposes=[PURPOSE_PROVIDER_EFFECT_RECEIPT],
            valid_from=0,
            valid_until=4_102_444_800,
        )
        provider_keys_path = work / "provider-public-keys.json"
        provider_keys_path.write_text(
            json.dumps([provider_record], indent=2) + "\n", encoding="utf-8"
        )
        provider_registry = TrustKeyRegistry([provider_record])

        witness_rows: list[dict[str, str]] = []
        witness_records: list[dict[str, Any]] = []
        witness_services: list[dict[str, Any]] = []
        try:
            for suffix in ("a", "b", "c"):
                pair = generate_ed25519_keypair()
                row = {
                    "witness_id": f"completion-witness:v330:service-smoke:{suffix}",
                    "authority_id": f"authority:completion-witness:v330:service-smoke:{suffix}",
                    "service_id": f"service:completion-witness:v330:service-smoke:{suffix}",
                    "key_id": f"key:completion-witness:v330:service-smoke:{suffix}",
                    "signer_id": f"signer:completion-witness:v330:service-smoke:{suffix}",
                    "trust_domain": f"domain:completion-witness:v330:service-smoke:{suffix}",
                }
                witness_rows.append(row)
                witness_records.append(
                    make_trust_key_record(
                        key_id=row["key_id"],
                        signer_id=row["signer_id"],
                        trust_domain=row["trust_domain"],
                        public_key_b64=pair["public_key_b64"],
                        purposes=[PURPOSE_EXTERNAL_COMPLETION_WITNESS],
                        valid_from=0,
                        valid_until=4_102_444_800,
                    )
                )
                token = f"completion-witness-token-{suffix}"
                env = common_env | {
                    "TRIAXIS_ECW_DB": str(work / f"completion-witness-{suffix}.sqlite"),
                    "TRIAXIS_ECW_PROVIDER_KEYS_JSON": str(provider_keys_path),
                    "TRIAXIS_ECW_EXPECTED_PROVIDER_SIGNER_ID": PROVIDER_SIGNER_ID,
                    "TRIAXIS_ECW_EXPECTED_PROVIDER_TRUST_DOMAIN": PROVIDER_DOMAIN,
                    "TRIAXIS_ECW_WITNESS_ID": row["witness_id"],
                    "TRIAXIS_ECW_AUTHORITY_ID": row["authority_id"],
                    "TRIAXIS_ECW_SERVICE_ID": row["service_id"],
                    "TRIAXIS_ECW_KEY_ID": row["key_id"],
                    "TRIAXIS_ECW_SIGNER_ID": row["signer_id"],
                    "TRIAXIS_ECW_TRUST_DOMAIN": row["trust_domain"],
                    "TRIAXIS_ECW_PRIVATE_KEY_B64": pair["private_key_b64"],
                    "TRIAXIS_ECW_CLIENT_TOKEN": token,
                    "TRIAXIS_ECW_HOST": "127.0.0.1",
                    "TRIAXIS_ECW_PORT": "0",
                    "TRIAXIS_ECW_RESPONSE_TTL": "30",
                    "TRIAXIS_ECW_MAX_PROVIDER_RECEIPT_AGE": "30",
                }
                process, startup = start_process(
                    [sys.executable, "tools/run_external_completion_witness.py"], env
                )
                processes.append(process)
                witness_services.append({"startup": startup, "token": token, "row": row})

            anchor_pair = generate_ed25519_keypair()
            anchor_record = make_trust_key_record(
                key_id="key:completion-worm-anchor:v330:service-smoke",
                signer_id=ANCHOR_SIGNER_ID,
                trust_domain=ANCHOR_DOMAIN,
                public_key_b64=anchor_pair["public_key_b64"],
                purposes=[PURPOSE_COMPLETION_WORM_ANCHOR],
                valid_from=0,
                valid_until=4_102_444_800,
            )
            anchor_token = "completion-worm-anchor-token"
            anchor_env = common_env | {
                "TRIAXIS_CWA_DB": str(work / "completion-worm-anchor.sqlite"),
                "TRIAXIS_CWA_PROVIDER_KEYS_JSON": str(provider_keys_path),
                "TRIAXIS_CWA_EXPECTED_PROVIDER_SIGNER_ID": PROVIDER_SIGNER_ID,
                "TRIAXIS_CWA_EXPECTED_PROVIDER_TRUST_DOMAIN": PROVIDER_DOMAIN,
                "TRIAXIS_CWA_ANCHOR_ID": ANCHOR_ID,
                "TRIAXIS_CWA_AUTHORITY_ID": ANCHOR_AUTHORITY_ID,
                "TRIAXIS_CWA_SERVICE_ID": ANCHOR_SERVICE_ID,
                "TRIAXIS_CWA_PROVIDER_ID": PROVIDER_ID,
                "TRIAXIS_CWA_PROVIDER_SERVICE_ID": PROVIDER_SERVICE_ID,
                "TRIAXIS_CWA_KEY_ID": anchor_record["key_id"],
                "TRIAXIS_CWA_SIGNER_ID": ANCHOR_SIGNER_ID,
                "TRIAXIS_CWA_TRUST_DOMAIN": ANCHOR_DOMAIN,
                "TRIAXIS_CWA_PRIVATE_KEY_B64": anchor_pair["private_key_b64"],
                "TRIAXIS_CWA_CLIENT_TOKEN": anchor_token,
                "TRIAXIS_CWA_HOST": "127.0.0.1",
                "TRIAXIS_CWA_PORT": "0",
                "TRIAXIS_CWA_RESPONSE_TTL": "30",
                "TRIAXIS_CWA_MAX_PROVIDER_RECEIPT_AGE": "30",
            }
            anchor_process, anchor_startup = start_process(
                [sys.executable, "tools/run_completion_worm_anchor.py"], anchor_env
            )
            processes.append(anchor_process)

            health_rows = []
            for service in witness_services + [{"startup": anchor_startup}]:
                status, payload = http_json(
                    "GET", f"http://127.0.0.1:{service['startup']['port']}/healthz"
                )
                text = json.dumps(payload, sort_keys=True).lower()
                health_rows.append(
                    status == 200 and "private_key" not in text and "client_token" not in text
                )
            rows.append(
                {
                    "case_id": "V330SP01_FOUR_EVIDENCE_PROCESSES_START_AND_MINIMIZE_SECRETS",
                    "process_count": 4,
                    "all_health_pass": all(health_rows),
                    "status": "PASS" if len(health_rows) == 4 and all(health_rows) else "FAIL",
                }
            )

            effect_id = canonical_sha256({"effect": "v330-service-smoke"})
            payload_sha256 = canonical_sha256({"payload": "v330-service-smoke"})
            session = VerifierFreshnessSession.create("verifier:v330:service-smoke:quorum", now - 1)
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                challenge = challenges.issue(now, now + 30)
                statuses = []
                for service in witness_services:
                    code, payload = http_json(
                        "POST",
                        f"http://127.0.0.1:{service['startup']['port']}/v1/effects/status/challenge",
                        {
                            "effect_id": effect_id,
                            "payload_sha256": payload_sha256,
                            "provider_id": PROVIDER_ID,
                            "provider_service_id": PROVIDER_SERVICE_ID,
                            "challenge": challenge,
                            "verifier_id": session.verifier_id,
                            "verifier_epoch_sha256": session.epoch_sha256,
                            "requested_at": now,
                        },
                    )
                    if code != 200:
                        raise RuntimeError(f"completion status failed: {code} {payload}")
                    statuses.append(payload["signed_completion_witness_status"])
                config = make_completion_witness_quorum_config(
                    config_id="completion-witness-quorum:v330:service-smoke",
                    witness_set_id="completion-witness-set:v330:service-smoke",
                    provider_id=PROVIDER_ID,
                    provider_service_id=PROVIDER_SERVICE_ID,
                    threshold=2,
                    witnesses=witness_rows,
                    valid_from=0,
                    valid_until=4_102_444_800,
                )
                evaluated_at = int(time.time())
                quorum = verify_completion_witness_quorum(
                    statuses,
                    registry=TrustKeyRegistry(witness_records),
                    quorum_config=config,
                    expected_quorum_config_sha256=config["config_sha256"],
                    expected_effect_id=effect_id,
                    expected_payload_sha256=payload_sha256,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges,
                    expected_challenge=challenge,
                    evaluation_tick=evaluated_at,
                    max_response_age=10,
                )
                rows.append(
                    {
                        "case_id": "V330SP02_THREE_COMPLETION_WITNESSES_FORM_2_OF_3_QUORUM",
                        "quorum_state": quorum["state"],
                        "member_count": quorum["member_count"],
                        "status": "PASS"
                        if quorum["status"] == "PASS"
                        and quorum["state"] == "ABSENT"
                        and quorum["member_count"] == 3
                        else "FAIL",
                    }
                )

            with SQLiteIdempotentEffectProvider(
                ":memory:",
                provider_id=PROVIDER_ID,
                service_id=PROVIDER_SERVICE_ID,
                key_id=provider_record["key_id"],
                signer_id=PROVIDER_SIGNER_ID,
                trust_domain=PROVIDER_DOMAIN,
                private_key_b64=provider_pair["private_key_b64"],
                response_ttl=60,
            ) as provider:
                provider.begin(
                    effect_id=effect_id,
                    payload_sha256=payload_sha256,
                    provider_request_id="provider-request:v330:service-smoke",
                    now_tick=now,
                )
                provider.record_outcome(
                    effect_id=effect_id,
                    provider_request_id="provider-request:v330:service-smoke",
                    outcome="COMPLETED",
                    provider_response_sha256=canonical_sha256({"response": "ok"}),
                    evidence_sha256=canonical_sha256({"evidence": "provider"}),
                    now_tick=now + 1,
                )
                receipt = provider.issue_outcome_receipt(
                    effect_id=effect_id,
                    issued_at=now + 1,
                    valid_until=now + 60,
                )

            anchor_port = anchor_startup["port"]
            denied_code, _ = http_json(
                "POST",
                f"http://127.0.0.1:{anchor_port}/v1/outcomes/ingest",
                {"signed_provider_receipt": receipt},
            )
            accepted_code, accepted = http_json(
                "POST",
                f"http://127.0.0.1:{anchor_port}/v1/outcomes/ingest",
                {"signed_provider_receipt": receipt},
                anchor_token,
            )
            rows.append(
                {
                    "case_id": "V330SP03_WORM_ANCHOR_PROCESS_ENFORCES_MUTATION_AUTH",
                    "denied_status": denied_code,
                    "accepted_status": accepted_code,
                    "anchored_state": accepted.get("effect", {}).get("state"),
                    "status": "PASS"
                    if denied_code == 403
                    and accepted_code == 200
                    and accepted.get("effect", {}).get("state") == "COMPLETED"
                    else "FAIL",
                }
            )

            anchor_session = VerifierFreshnessSession.create(
                "verifier:v330:service-smoke:anchor", now - 1
            )
            with SQLiteEpochChallengeLedger(":memory:", anchor_session) as anchor_challenges:
                anchor_request_tick = int(time.time())
                anchor_challenge = anchor_challenges.issue(anchor_request_tick, anchor_request_tick + 30)
                code, payload = http_json(
                    "POST",
                    f"http://127.0.0.1:{anchor_port}/v1/effects/status/challenge",
                    {
                        "effect_id": effect_id,
                        "payload_sha256": payload_sha256,
                        "challenge": anchor_challenge,
                        "verifier_id": anchor_session.verifier_id,
                        "verifier_epoch_sha256": anchor_session.epoch_sha256,
                        "requested_at": anchor_request_tick,
                    },
                )
                block_code = None
                if code == 200:
                    try:
                        verify_completion_worm_anchor_status(
                            payload["signed_completion_worm_anchor_status"],
                            registry=TrustKeyRegistry([anchor_record]),
                            expected_anchor_id=ANCHOR_ID,
                            expected_authority_id=ANCHOR_AUTHORITY_ID,
                            expected_service_id=ANCHOR_SERVICE_ID,
                            expected_signer_id=ANCHOR_SIGNER_ID,
                            expected_trust_domain=ANCHOR_DOMAIN,
                            expected_effect_id=effect_id,
                            expected_payload_sha256=payload_sha256,
                            expected_provider_id=PROVIDER_ID,
                            expected_provider_service_id=PROVIDER_SERVICE_ID,
                            challenge_ledger=anchor_challenges,
                            expected_challenge=anchor_challenge,
                            evaluation_tick=int(time.time()),
                            max_response_age=10,
                        )
                    except CompletionWORMAnchorError as exc:
                        block_code = exc.code
                rows.append(
                    {
                        "case_id": "V330SP04_CURRENT_WORM_ANCHOR_BLOCKS_COMPLETED_EFFECT",
                        "http_status": code,
                        "block_code": block_code,
                        "status": "PASS"
                        if code == 200 and block_code == "worm_anchor_state_blocks_retry"
                        else "FAIL",
                    }
                )

            # Put the completed receipt into one configured witness. The valid
            # blocking minority must veto the two remaining ABSENT statements.
            target = witness_services[2]
            code, _ = http_json(
                "POST",
                f"http://127.0.0.1:{target['startup']['port']}/v1/effects/reserve",
                {
                    "effect_id": effect_id,
                    "payload_sha256": payload_sha256,
                    "provider_id": PROVIDER_ID,
                    "provider_service_id": PROVIDER_SERVICE_ID,
                    "provider_request_id": "provider-request:v330:service-smoke",
                },
                target["token"],
            )
            if code not in (200, 409):
                raise RuntimeError(f"witness reserve failed: {code}")
            code, _ = http_json(
                "POST",
                f"http://127.0.0.1:{target['startup']['port']}/v1/effects/provider-outcome",
                {"signed_provider_receipt": receipt},
                target["token"],
            )
            if code != 200:
                raise RuntimeError(f"witness outcome ingest failed: {code}")
            veto_session = VerifierFreshnessSession.create(
                "verifier:v330:service-smoke:veto", now - 1
            )
            with SQLiteEpochChallengeLedger(":memory:", veto_session) as veto_challenges:
                veto_request_tick = int(time.time())
                veto_challenge = veto_challenges.issue(veto_request_tick, veto_request_tick + 30)
                veto_statuses = []
                for service in witness_services:
                    code, payload = http_json(
                        "POST",
                        f"http://127.0.0.1:{service['startup']['port']}/v1/effects/status/challenge",
                        {
                            "effect_id": effect_id,
                            "payload_sha256": payload_sha256,
                            "provider_id": PROVIDER_ID,
                            "provider_service_id": PROVIDER_SERVICE_ID,
                            "challenge": veto_challenge,
                            "verifier_id": veto_session.verifier_id,
                            "verifier_epoch_sha256": veto_session.epoch_sha256,
                            "requested_at": veto_request_tick,
                        },
                    )
                    if code != 200:
                        raise RuntimeError(f"veto status failed: {code} {payload}")
                    veto_statuses.append(payload["signed_completion_witness_status"])
                veto_code = None
                try:
                    verify_completion_witness_quorum(
                        veto_statuses,
                        registry=TrustKeyRegistry(witness_records),
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=payload_sha256,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=veto_challenges,
                        expected_challenge=veto_challenge,
                        evaluation_tick=int(time.time()),
                        max_response_age=10,
                    )
                except CompletionWitnessQuorumError as exc:
                    veto_code = exc.code
                rows.append(
                    {
                        "case_id": "V330SP05_CONFIGURED_BLOCKING_MINORITY_VETOES_PROCESS_QUORUM",
                        "veto_code": veto_code,
                        "status": "PASS"
                        if veto_code == "blocking_completion_witness_minority"
                        else "FAIL",
                    }
                )
        finally:
            for process in reversed(processes):
                terminate(process)

    return {
        "protocol_id": "TRIAXIS_v3.30_SERVICE_PROCESS_SMOKE",
        "case_count": len(rows),
        "pass_count": sum(row["status"] == "PASS" for row in rows),
        "fail_count": sum(row["status"] != "PASS" for row in rows),
        "status": "PASS" if rows and all(row["status"] == "PASS" for row in rows) else "FAIL",
        "authority_granted": False,
        "production_qualified": False,
        "physical_worm_established": False,
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    result = run()
    path = Path("evidence/TRIAXIS_v3.30_SERVICE_PROCESS_SMOKE.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
