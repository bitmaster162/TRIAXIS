from __future__ import annotations

from contextlib import ExitStack
import hashlib
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

from triaxis.completion_availability_control import (
    CompletionAvailabilityError,
    make_completion_availability_policy,
    verify_availability_closed_completion_quorum,
)
from triaxis.completion_immutable_anchor import (
    CompletionImmutableAnchorError,
    SQLiteImmutableAnchorCheckpointLedger,
    verify_completion_immutable_anchor_head,
    verify_completion_immutable_anchor_status,
)
from triaxis.completion_witness_quorum import make_completion_witness_quorum_config
from triaxis.crypto_trust import (
    PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
    PURPOSE_EXTERNAL_COMPLETION_WITNESS,
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.idempotent_effect_provider import SQLiteIdempotentEffectProvider
from triaxis.integrity import canonical_sha256
from triaxis.trust_registry_quorum import (
    SQLiteEpochChallengeLedger,
    VerifierFreshnessSession,
)

PROVIDER_ID = "provider:v331:service-smoke"
PROVIDER_SERVICE_ID = "service:provider:v331:service-smoke"
PROVIDER_SIGNER_ID = "signer:provider:v331:service-smoke"
PROVIDER_DOMAIN = "domain:provider:v331:service-smoke"
ANCHOR_ID = "completion-immutable-anchor:v331:service-smoke"
ANCHOR_AUTHORITY_ID = "authority:completion-immutable-anchor:v331:service-smoke"
ANCHOR_SERVICE_ID = "service:completion-immutable-anchor:v331:service-smoke"
ANCHOR_SIGNER_ID = "signer:completion-immutable-anchor:v331:service-smoke"
ANCHOR_DOMAIN = "domain:completion-immutable-anchor:v331:service-smoke"
RETENTION_POLICY_ID = "retention:completion:v331:service-smoke"


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


def start_process(
    command: list[str], env: dict[str, str]
) -> tuple[subprocess.Popen[str], dict[str, Any]]:
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
    with tempfile.TemporaryDirectory(prefix="triaxis-v331-service-smoke-") as td:
        work = Path(td)
        now = int(time.time())
        common_env = os.environ.copy()
        common_env["PYTHONPATH"] = f"{root / 'src'}:{root}"
        common_env.setdefault("TERM", "xterm")

        provider_pair = generate_ed25519_keypair()
        provider_record = make_trust_key_record(
            key_id="key:provider:v331:service-smoke",
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
                    "witness_id": f"completion-witness:v331:service-smoke:{suffix}",
                    "authority_id": f"authority:completion-witness:v331:service-smoke:{suffix}",
                    "service_id": f"service:completion-witness:v331:service-smoke:{suffix}",
                    "key_id": f"key:completion-witness:v331:service-smoke:{suffix}",
                    "signer_id": f"signer:completion-witness:v331:service-smoke:{suffix}",
                    "trust_domain": f"domain:completion-witness:v331:service-smoke:{suffix}",
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
                token = f"completion-witness-v331-token-{suffix}"
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
                witness_services.append(
                    {"startup": startup, "token": token, "row": row}
                )

            anchor_pair = generate_ed25519_keypair()
            anchor_record = make_trust_key_record(
                key_id="key:completion-immutable-anchor:v331:service-smoke",
                signer_id=ANCHOR_SIGNER_ID,
                trust_domain=ANCHOR_DOMAIN,
                public_key_b64=anchor_pair["public_key_b64"],
                purposes=[PURPOSE_COMPLETION_IMMUTABLE_ANCHOR],
                valid_from=0,
                valid_until=4_102_444_800,
            )
            anchor_registry = TrustKeyRegistry([anchor_record])
            anchor_token = "completion-immutable-anchor-v331-token"
            anchor_root = work / "completion-immutable-anchor"
            anchor_env = common_env | {
                "TRIAXIS_CIA_ROOT": str(anchor_root),
                "TRIAXIS_CIA_PROVIDER_KEYS_JSON": str(provider_keys_path),
                "TRIAXIS_CIA_EXPECTED_PROVIDER_SIGNER_ID": PROVIDER_SIGNER_ID,
                "TRIAXIS_CIA_EXPECTED_PROVIDER_TRUST_DOMAIN": PROVIDER_DOMAIN,
                "TRIAXIS_CIA_ANCHOR_ID": ANCHOR_ID,
                "TRIAXIS_CIA_AUTHORITY_ID": ANCHOR_AUTHORITY_ID,
                "TRIAXIS_CIA_SERVICE_ID": ANCHOR_SERVICE_ID,
                "TRIAXIS_CIA_PROVIDER_ID": PROVIDER_ID,
                "TRIAXIS_CIA_PROVIDER_SERVICE_ID": PROVIDER_SERVICE_ID,
                "TRIAXIS_CIA_RETENTION_POLICY_ID": RETENTION_POLICY_ID,
                "TRIAXIS_CIA_KEY_ID": anchor_record["key_id"],
                "TRIAXIS_CIA_SIGNER_ID": ANCHOR_SIGNER_ID,
                "TRIAXIS_CIA_TRUST_DOMAIN": ANCHOR_DOMAIN,
                "TRIAXIS_CIA_PRIVATE_KEY_B64": anchor_pair["private_key_b64"],
                "TRIAXIS_CIA_CLIENT_TOKEN": anchor_token,
                "TRIAXIS_CIA_HOST": "127.0.0.1",
                "TRIAXIS_CIA_PORT": "0",
                "TRIAXIS_CIA_RESPONSE_TTL": "30",
                "TRIAXIS_CIA_MAX_PROVIDER_RECEIPT_AGE": "30",
                "TRIAXIS_CIA_MINIMUM_RETENTION_TICKS": "100",
            }
            anchor_process, anchor_startup = start_process(
                [sys.executable, "tools/run_completion_immutable_anchor.py"],
                anchor_env,
            )
            processes.append(anchor_process)

            health_rows = []
            for service in witness_services + [{"startup": anchor_startup}]:
                status, payload = http_json(
                    "GET", f"http://127.0.0.1:{service['startup']['port']}/healthz"
                )
                text = json.dumps(payload, sort_keys=True).lower()
                health_rows.append(
                    status == 200
                    and "private_key" not in text
                    and "client_token" not in text
                )
            rows.append(
                {
                    "case_id": "V331SP01_FOUR_EVIDENCE_PROCESSES_START_AND_MINIMIZE_SECRETS",
                    "process_count": 4,
                    "all_health_pass": all(health_rows),
                    "status": "PASS"
                    if len(health_rows) == 4 and all(health_rows)
                    else "FAIL",
                }
            )

            effect_id = canonical_sha256({"effect": "v331-service-smoke"})
            payload_sha256 = canonical_sha256({"payload": "v331-service-smoke"})
            config = make_completion_witness_quorum_config(
                config_id="completion-witness-quorum:v331:service-smoke",
                witness_set_id="completion-witness-set:v331:service-smoke",
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                threshold=2,
                witnesses=witness_rows,
                valid_from=0,
                valid_until=4_102_444_800,
            )
            policy = make_completion_availability_policy(
                policy_id="completion-availability:v331:service-smoke",
                completion_quorum_config_sha256=config["config_sha256"],
                risk_class="HIGH",
                required_witness_count=3,
                valid_from=0,
                valid_until=4_102_444_800,
            )
            witness_registry = TrustKeyRegistry(witness_records)

            def collect_statuses(
                session: VerifierFreshnessSession,
                challenge: str,
                request_tick: int,
                count: int,
            ) -> list[dict[str, Any]]:
                statuses: list[dict[str, Any]] = []
                for service in witness_services[:count]:
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
                            "requested_at": request_tick,
                        },
                    )
                    if code != 200:
                        raise RuntimeError(f"completion status failed: {code} {payload}")
                    statuses.append(payload["signed_completion_witness_status"])
                return statuses

            session = VerifierFreshnessSession.create(
                "verifier:v331:service-smoke:all", now - 1
            )
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                request_tick = int(time.time())
                challenge = challenges.issue(request_tick, request_tick + 30)
                statuses = collect_statuses(session, challenge, request_tick, 3)
                result = verify_availability_closed_completion_quorum(
                    statuses,
                    registry=witness_registry,
                    quorum_config=config,
                    expected_quorum_config_sha256=config["config_sha256"],
                    availability_policy=policy,
                    expected_availability_policy_sha256=policy["policy_sha256"],
                    expected_effect_id=effect_id,
                    expected_payload_sha256=payload_sha256,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge_ledger=challenges,
                    expected_challenge=challenge,
                    evaluation_tick=int(time.time()),
                    max_response_age=10,
                )
                rows.append(
                    {
                        "case_id": "V331SP02_ALL_CONFIGURED_COMPLETION_WITNESSES_REQUIRED_AND_PRESENT",
                        "responding_witness_count": result["responding_witness_count"],
                        "state": result["availability_witness"]["state"],
                        "status": "PASS"
                        if result["status"] == "PASS"
                        and result["responding_witness_count"] == 3
                        and result["availability_witness"]["state"] == "ABSENT"
                        else "FAIL",
                    }
                )

            missing_session = VerifierFreshnessSession.create(
                "verifier:v331:service-smoke:missing", now - 1
            )
            with SQLiteEpochChallengeLedger(
                ":memory:", missing_session
            ) as missing_challenges:
                request_tick = int(time.time())
                missing_challenge = missing_challenges.issue(
                    request_tick, request_tick + 30
                )
                statuses = collect_statuses(
                    missing_session, missing_challenge, request_tick, 2
                )
                block_code = None
                try:
                    verify_availability_closed_completion_quorum(
                        statuses,
                        registry=witness_registry,
                        quorum_config=config,
                        expected_quorum_config_sha256=config["config_sha256"],
                        availability_policy=policy,
                        expected_availability_policy_sha256=policy["policy_sha256"],
                        expected_effect_id=effect_id,
                        expected_payload_sha256=payload_sha256,
                        expected_provider_id=PROVIDER_ID,
                        expected_provider_service_id=PROVIDER_SERVICE_ID,
                        challenge_ledger=missing_challenges,
                        expected_challenge=missing_challenge,
                        evaluation_tick=int(time.time()),
                        max_response_age=10,
                    )
                except CompletionAvailabilityError as exc:
                    block_code = exc.code
                rows.append(
                    {
                        "case_id": "V331SP03_MISSING_CONFIGURED_WITNESS_FAILS_CLOSED",
                        "block_code": block_code,
                        "status": "PASS"
                        if block_code
                        == "completion_availability_witness_set_incomplete"
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
                    provider_request_id="provider-request:v331:service-smoke",
                    now_tick=now,
                )
                provider.record_outcome(
                    effect_id=effect_id,
                    provider_request_id="provider-request:v331:service-smoke",
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
            request_body = {
                "signed_provider_receipt": receipt,
                "retention_until_tick": now + 1_000,
                "legal_hold": True,
            }
            denied_code, _ = http_json(
                "POST",
                f"http://127.0.0.1:{anchor_port}/v1/outcomes/store",
                request_body,
            )
            accepted_code, accepted = http_json(
                "POST",
                f"http://127.0.0.1:{anchor_port}/v1/outcomes/store",
                request_body,
                anchor_token,
            )
            object_receipt = accepted.get("signed_object_receipt", {}).get(
                "inner_contract", {}
            )
            object_key = object_receipt.get("object_key")
            object_path = anchor_root / object_key if isinstance(object_key, str) else None
            object_digest_ok = (
                object_path is not None
                and object_path.is_file()
                and hashlib.sha256(object_path.read_bytes()).hexdigest()
                == object_receipt.get("content_sha256")
            )
            rows.append(
                {
                    "case_id": "V331SP04_IMMUTABLE_ANCHOR_AUTH_AND_CONTENT_ADDRESS_BINDING",
                    "denied_status": denied_code,
                    "accepted_status": accepted_code,
                    "anchored_state": accepted.get("effect", {}).get("state"),
                    "object_digest_ok": object_digest_ok,
                    "status": "PASS"
                    if denied_code == 403
                    and accepted_code == 200
                    and accepted.get("effect", {}).get("state") == "COMPLETED"
                    and object_digest_ok
                    else "FAIL",
                }
            )

            head_code, head_payload = http_json(
                "GET", f"http://127.0.0.1:{anchor_port}/v1/head"
            )
            head_verified = False
            checkpoint_sequence = None
            if head_code == 200:
                head_result = verify_completion_immutable_anchor_head(
                    head_payload["signed_completion_immutable_anchor_head"],
                    registry=anchor_registry,
                    expected_anchor_id=ANCHOR_ID,
                    expected_authority_id=ANCHOR_AUTHORITY_ID,
                    expected_service_id=ANCHOR_SERVICE_ID,
                    expected_signer_id=ANCHOR_SIGNER_ID,
                    expected_trust_domain=ANCHOR_DOMAIN,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    expected_retention_policy_id=RETENTION_POLICY_ID,
                    evaluation_tick=int(time.time()),
                )
                with SQLiteImmutableAnchorCheckpointLedger(
                    ":memory:", anchor_id=ANCHOR_ID
                ) as checkpoint:
                    checkpoint_sequence = checkpoint.observe_head(
                        head_result["head"],
                        observed_at_tick=int(time.time()),
                    )["checkpoint"]["sequence"]
                head_verified = head_result["status"] == "PASS"

            anchor_session = VerifierFreshnessSession.create(
                "verifier:v331:service-smoke:anchor", now - 1
            )
            with SQLiteEpochChallengeLedger(
                ":memory:", anchor_session
            ) as anchor_challenges:
                request_tick = int(time.time())
                anchor_challenge = anchor_challenges.issue(
                    request_tick, request_tick + 30
                )
                code, payload = http_json(
                    "POST",
                    f"http://127.0.0.1:{anchor_port}/v1/effects/status/challenge",
                    {
                        "effect_id": effect_id,
                        "payload_sha256": payload_sha256,
                        "challenge": anchor_challenge,
                        "verifier_id": anchor_session.verifier_id,
                        "verifier_epoch_sha256": anchor_session.epoch_sha256,
                        "requested_at": request_tick,
                    },
                )
                block_code = None
                if code == 200:
                    try:
                        verify_completion_immutable_anchor_status(
                            payload["signed_completion_immutable_anchor_status"],
                            registry=anchor_registry,
                            expected_anchor_id=ANCHOR_ID,
                            expected_authority_id=ANCHOR_AUTHORITY_ID,
                            expected_service_id=ANCHOR_SERVICE_ID,
                            expected_signer_id=ANCHOR_SIGNER_ID,
                            expected_trust_domain=ANCHOR_DOMAIN,
                            expected_provider_id=PROVIDER_ID,
                            expected_provider_service_id=PROVIDER_SERVICE_ID,
                            expected_retention_policy_id=RETENTION_POLICY_ID,
                            expected_effect_id=effect_id,
                            expected_payload_sha256=payload_sha256,
                            challenge_ledger=anchor_challenges,
                            expected_challenge=anchor_challenge,
                            evaluation_tick=int(time.time()),
                            max_response_age=10,
                        )
                    except CompletionImmutableAnchorError as exc:
                        block_code = exc.code
                rows.append(
                    {
                        "case_id": "V331SP05_SIGNED_HEAD_CHECKPOINT_AND_COMPLETED_STATUS_BLOCK",
                        "head_verified": head_verified,
                        "checkpoint_sequence": checkpoint_sequence,
                        "status_http": code,
                        "block_code": block_code,
                        "status": "PASS"
                        if head_verified
                        and checkpoint_sequence == 1
                        and code == 200
                        and block_code == "immutable_anchor_state_blocks_retry"
                        else "FAIL",
                    }
                )
        finally:
            for process in reversed(processes):
                terminate(process)

    return {
        "protocol_id": "TRIAXIS_v3.31_SERVICE_PROCESS_SMOKE",
        "case_count": len(rows),
        "pass_count": sum(row["status"] == "PASS" for row in rows),
        "fail_count": sum(row["status"] != "PASS" for row in rows),
        "status": "PASS"
        if rows and all(row["status"] == "PASS" for row in rows)
        else "FAIL",
        "authority_granted": False,
        "production_qualified": False,
        "physical_worm_established": False,
        "hardware_monotonicity": False,
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    result = run()
    path = Path("evidence/TRIAXIS_v3.31_SERVICE_PROCESS_SMOKE.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
