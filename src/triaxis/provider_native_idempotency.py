"""TRIAXIS v3.32 provider-native durable idempotency protocol reference.

The filesystem implementation is intentionally only a local executable reference.
It models the contract a real external provider must satisfy, but does not claim
that any vendor actually provides this durability or administrative independence.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .crypto_trust import (
    PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY,
    TrustKeyRegistry,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import canonical_json_bytes, canonical_sha256, materialize_json, seal_mapping, verify_sealed_mapping

PROVIDER_NATIVE_POLICY_CONTRACT_ID = "TRIAXIS_PROVIDER_NATIVE_IDEMPOTENCY_POLICY_v1"
PROVIDER_NATIVE_EVENT_CONTRACT_ID = "TRIAXIS_PROVIDER_NATIVE_IDEMPOTENCY_EVENT_v1"
PROVIDER_NATIVE_HEAD_CONTRACT_ID = "TRIAXIS_PROVIDER_NATIVE_IDEMPOTENCY_HEAD_v1"
PROVIDER_NATIVE_STATUS_CONTRACT_ID = "TRIAXIS_PROVIDER_NATIVE_IDEMPOTENCY_STATUS_v1"
PROVIDER_NATIVE_STATES = frozenset({"ABSENT", "IN_FLIGHT", "UNKNOWN", "COMPLETED", "NO_EFFECT"})
PROVIDER_NATIVE_PERMISSIVE_STATES = frozenset({"ABSENT", "NO_EFFECT"})
PROVIDER_NATIVE_BLOCKING_STATES = frozenset({"IN_FLIGHT", "UNKNOWN", "COMPLETED"})
ZERO_SHA256 = "0" * 64


class ProviderNativeIdempotencyError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 16:
        raise ProviderNativeIdempotencyError("invalid_challenge", "minimum 16 characters required")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


def make_provider_native_policy(*, policy_id: str, provider_id: str, service_id: str, namespace_id: str, valid_from: int, valid_until: int) -> dict[str, Any]:
    return seal_mapping({
        "contract_id": PROVIDER_NATIVE_POLICY_CONTRACT_ID,
        "policy_id": policy_id,
        "provider_id": provider_id,
        "service_id": service_id,
        "namespace_id": namespace_id,
        "stable_effect_id_required": True,
        "payload_binding_required": True,
        "permissive_states": ["ABSENT", "NO_EFFECT"],
        "valid_from": valid_from,
        "valid_until": valid_until,
        "policy_sha256": "",
    }, "policy_sha256")


def validate_provider_native_policy(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [{"code": "invalid_type", "path": "policy", "message": "mapping required"}]}
    try:
        policy = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [{"code": "materialization_failed", "path": "policy", "message": type(exc).__name__}]}
    if not isinstance(policy, dict):
        return {"status": "BLOCK", "errors": [{"code": "invalid_type", "path": "policy", "message": "object required"}]}
    if policy.get("contract_id") != PROVIDER_NATIVE_POLICY_CONTRACT_ID:
        errors.append({"code": "invalid_contract_id", "path": "policy.contract_id", "message": PROVIDER_NATIVE_POLICY_CONTRACT_ID})
    if not verify_sealed_mapping(policy, "policy_sha256"):
        errors.append({"code": "digest_mismatch", "path": "policy.policy_sha256", "message": "canonical digest mismatch"})
    for field in ("policy_id", "provider_id", "service_id", "namespace_id"):
        if not isinstance(policy.get(field), str) or not policy[field]:
            errors.append({"code": f"invalid_{field}", "path": f"policy.{field}", "message": "non-empty string required"})
    if policy.get("stable_effect_id_required") is not True:
        errors.append({"code": "stable_effect_id_not_required", "path": "policy.stable_effect_id_required", "message": "must be true"})
    if policy.get("payload_binding_required") is not True:
        errors.append({"code": "payload_binding_not_required", "path": "policy.payload_binding_required", "message": "must be true"})
    if policy.get("permissive_states") != ["ABSENT", "NO_EFFECT"]:
        errors.append({"code": "invalid_permissive_states", "path": "policy.permissive_states", "message": "must be exactly ABSENT,NO_EFFECT"})
    vf, vu = policy.get("valid_from"), policy.get("valid_until")
    if type(vf) is not int or type(vu) is not int or vf < 0 or vu <= vf:
        errors.append({"code": "invalid_validity_window", "path": "policy", "message": "valid_from < valid_until required"})
    if evaluation_tick is not None and type(vf) is int and type(vu) is int and not (vf <= evaluation_tick < vu):
        errors.append({"code": "policy_not_current", "path": "policy", "message": str(evaluation_tick)})
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "policy": policy}


class FilesystemProviderNativeIdempotencyReference:
    """Write-once local protocol reference keyed by stable ``effect_id``."""

    def __init__(self, root: str | Path, *, provider_id: str, service_id: str, namespace_id: str, key_id: str, signer_id: str, trust_domain: str, private_key_b64: str, response_ttl: int = 30) -> None:
        for name, value in (("provider_id", provider_id), ("service_id", service_id), ("namespace_id", namespace_id), ("key_id", key_id), ("signer_id", signer_id), ("trust_domain", trust_domain), ("private_key_b64", private_key_b64)):
            if not isinstance(value, str) or not value:
                raise ProviderNativeIdempotencyError("invalid_configuration", name)
        if type(response_ttl) is not int or response_ttl < 1:
            raise ProviderNativeIdempotencyError("invalid_configuration", "response_ttl")
        self.root = Path(root).resolve()
        self.events_dir = self.root / "events"
        self.events_dir.mkdir(parents=True, exist_ok=True)
        self.provider_id = provider_id
        self.service_id = service_id
        self.namespace_id = namespace_id
        self.key_id = key_id
        self.signer_id = signer_id
        self.trust_domain = trust_domain
        self.private_key_b64 = private_key_b64
        self.response_ttl = response_ttl
        self._lock = threading.RLock()
        self._registry = self._own_registry()
        self._write_identity()
        self._events: list[dict[str, Any]] = []
        self._state: dict[str, dict[str, Any]] = {}
        self._rebuild()

    def _own_registry(self) -> TrustKeyRegistry:
        raw = base64.b64decode(self.private_key_b64.encode("ascii"), validate=True)
        private = Ed25519PrivateKey.from_private_bytes(raw)
        public_b64 = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
        return TrustKeyRegistry([make_trust_key_record(key_id=self.key_id, signer_id=self.signer_id, trust_domain=self.trust_domain, public_key_b64=public_b64, purposes=[PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY], valid_from=0, valid_until=2**62)])

    @staticmethod
    def _write_once(path: Path, payload: bytes) -> bool:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise ProviderNativeIdempotencyError("provider_native_write_once_conflict", str(path))
            return False
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return True

    def _write_identity(self) -> None:
        identity = seal_mapping({
            "contract_id": "TRIAXIS_PROVIDER_NATIVE_IDENTITY_v1",
            "provider_id": self.provider_id,
            "service_id": self.service_id,
            "namespace_id": self.namespace_id,
            "key_id": self.key_id,
            "signer_id": self.signer_id,
            "trust_domain": self.trust_domain,
            "delete_api": False,
            "overwrite_api": False,
            "authority_granted": False,
            "identity_sha256": "",
        }, "identity_sha256")
        self._write_once(self.root / "identity.json", canonical_json_bytes(identity) + b"\n")

    def _verify_signed_event(self, signed: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
        result = verify_contract_envelope(signed, registry=self._registry, evaluation_tick=evaluation_tick, expected_purpose=PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY, expected_digest_field="event_sha256", expected_inner_contract_id=PROVIDER_NATIVE_EVENT_CONTRACT_ID, expected_signer_id=self.signer_id, expected_trust_domain=self.trust_domain)
        if result["status"] != "PASS":
            raise ProviderNativeIdempotencyError("invalid_provider_native_event_signature", str(result["errors"]))
        event = result["inner_contract"]
        if event.get("issued_at") != signed.get("issued_at") or event.get("valid_until") != signed.get("valid_until"):
            raise ProviderNativeIdempotencyError("provider_native_event_envelope_window_mismatch", str(event.get("sequence")))
        return event

    def _rebuild(self) -> None:
        self._events = []
        self._state = {}
        expected_seq = 1
        parent = ZERO_SHA256
        for path in sorted(self.events_dir.glob("*.json")):
            signed = json.loads(path.read_text(encoding="utf-8"))
            event = self._verify_signed_event(signed, evaluation_tick=int(signed.get("issued_at", 0)))
            if event.get("sequence") != expected_seq:
                raise ProviderNativeIdempotencyError("provider_native_sequence_gap", path.name)
            if event.get("previous_event_sha256") != parent:
                raise ProviderNativeIdempotencyError("provider_native_parent_mismatch", path.name)
            if path.name != f"{expected_seq:020d}-{event['event_sha256']}.json":
                raise ProviderNativeIdempotencyError("provider_native_event_filename_mismatch", path.name)
            self._apply_event(event, rebuilding=True)
            self._events.append(event)
            parent = event["event_sha256"]
            expected_seq += 1

    def _apply_event(self, event: Mapping[str, Any], *, rebuilding: bool = False) -> None:
        eid = event["effect_id"]
        current = self._state.get(eid)
        if current is None:
            if event["from_state"] is not None or event["to_state"] != "IN_FLIGHT" or event["generation"] != 1:
                raise ProviderNativeIdempotencyError("provider_native_invalid_genesis", eid)
        else:
            if current["payload_sha256"] != event["payload_sha256"]:
                raise ProviderNativeIdempotencyError("provider_native_payload_conflict", eid)
            if current["state"] != event["from_state"]:
                raise ProviderNativeIdempotencyError("provider_native_state_discontinuity", eid)
            if event["generation"] == current["generation"] + 1:
                if current["state"] != "NO_EFFECT" or event["to_state"] != "IN_FLIGHT":
                    raise ProviderNativeIdempotencyError("provider_native_generation_without_no_effect", eid)
            elif event["generation"] != current["generation"]:
                raise ProviderNativeIdempotencyError("provider_native_generation_gap", eid)
        self._state[eid] = {
            "effect_id": eid,
            "payload_sha256": event["payload_sha256"],
            "state": event["to_state"],
            "generation": event["generation"],
            "provider_request_id": event["provider_request_id"],
            "provider_response_sha256": event.get("provider_response_sha256"),
            "evidence_sha256": event.get("evidence_sha256"),
            "event_sha256": event["event_sha256"],
            "updated_at": event["issued_at"],
        }

    def _append(self, *, effect_id: str, payload_sha256: str, provider_request_id: str, from_state: str | None, to_state: str, generation: int, now_tick: int, provider_response_sha256: str | None = None, evidence_sha256: str | None = None) -> dict[str, Any]:
        sequence = len(self._events) + 1
        previous = self._events[-1]["event_sha256"] if self._events else ZERO_SHA256
        event = seal_mapping({
            "contract_id": PROVIDER_NATIVE_EVENT_CONTRACT_ID,
            "provider_id": self.provider_id,
            "service_id": self.service_id,
            "namespace_id": self.namespace_id,
            "sequence": sequence,
            "previous_event_sha256": previous,
            "effect_id": effect_id,
            "payload_sha256": payload_sha256,
            "provider_request_id": provider_request_id,
            "generation": generation,
            "from_state": from_state,
            "to_state": to_state,
            "provider_response_sha256": provider_response_sha256,
            "evidence_sha256": evidence_sha256,
            "issued_at": now_tick,
            "valid_until": now_tick + self.response_ttl,
            "authority_granted": False,
            "event_sha256": "",
        }, "event_sha256")
        signed = sign_contract_envelope(event, digest_field="event_sha256", purpose=PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY, key_id=self.key_id, signer_id=self.signer_id, trust_domain=self.trust_domain, private_key_b64=self.private_key_b64, issued_at=now_tick, valid_until=now_tick+self.response_ttl)
        path = self.events_dir / f"{sequence:020d}-{event['event_sha256']}.json"
        self._write_once(path, canonical_json_bytes(signed) + b"\n")
        self._apply_event(event)
        self._events.append(event)
        return signed

    def begin(self, *, effect_id: str, payload_sha256: str, provider_request_id: str, now_tick: int) -> dict[str, Any]:
        if not _is_sha256(effect_id) or not _is_sha256(payload_sha256):
            raise ProviderNativeIdempotencyError("invalid_effect_identity", effect_id)
        if not isinstance(provider_request_id, str) or not provider_request_id:
            raise ProviderNativeIdempotencyError("invalid_provider_request_id", str(provider_request_id))
        if type(now_tick) is not int or now_tick < 0:
            raise ProviderNativeIdempotencyError("invalid_now_tick", str(now_tick))
        with self._lock:
            current = self._state.get(effect_id)
            if current is not None:
                if current["payload_sha256"] != payload_sha256:
                    raise ProviderNativeIdempotencyError("provider_native_payload_conflict", effect_id)
                if current["state"] != "NO_EFFECT":
                    return {"status": "PASS", "external_effect_permitted": False, "idempotent_replay": True, "effect": dict(current)}
                generation = current["generation"] + 1
                from_state = "NO_EFFECT"
            else:
                generation = 1
                from_state = None
            signed = self._append(effect_id=effect_id, payload_sha256=payload_sha256, provider_request_id=provider_request_id, from_state=from_state, to_state="IN_FLIGHT", generation=generation, now_tick=now_tick)
            return {"status": "PASS", "external_effect_permitted": True, "idempotent_replay": False, "signed_event": signed, "effect": dict(self._state[effect_id])}

    def record_outcome(self, *, effect_id: str, state: str, provider_response_sha256: str, evidence_sha256: str, now_tick: int) -> dict[str, Any]:
        if state not in {"UNKNOWN", "COMPLETED", "NO_EFFECT"}:
            raise ProviderNativeIdempotencyError("invalid_outcome_state", state)
        if not _is_sha256(provider_response_sha256) or not _is_sha256(evidence_sha256):
            raise ProviderNativeIdempotencyError("invalid_outcome_digest", effect_id)
        with self._lock:
            current = self._state.get(effect_id)
            if current is None:
                raise ProviderNativeIdempotencyError("unknown_effect_id", effect_id)
            if current["state"] not in {"IN_FLIGHT", "UNKNOWN"}:
                if current["state"] == state and current.get("provider_response_sha256") == provider_response_sha256 and current.get("evidence_sha256") == evidence_sha256:
                    return {"status": "PASS", "idempotent_replay": True, "effect": dict(current)}
                raise ProviderNativeIdempotencyError("provider_native_terminal_state_conflict", current["state"])
            signed = self._append(effect_id=effect_id, payload_sha256=current["payload_sha256"], provider_request_id=current["provider_request_id"], from_state=current["state"], to_state=state, generation=current["generation"], now_tick=now_tick, provider_response_sha256=provider_response_sha256, evidence_sha256=evidence_sha256)
            return {"status": "PASS", "idempotent_replay": False, "signed_event": signed, "effect": dict(self._state[effect_id])}

    def signed_head(self, *, now_tick: int) -> dict[str, Any]:
        head_event = self._events[-1]["event_sha256"] if self._events else ZERO_SHA256
        state_root = canonical_sha256([self._state[k] for k in sorted(self._state)])
        head = seal_mapping({
            "contract_id": PROVIDER_NATIVE_HEAD_CONTRACT_ID,
            "provider_id": self.provider_id,
            "service_id": self.service_id,
            "namespace_id": self.namespace_id,
            "sequence": len(self._events),
            "head_event_sha256": head_event,
            "state_root_sha256": state_root,
            "issued_at": now_tick,
            "valid_until": now_tick + self.response_ttl,
            "authority_granted": False,
            "head_sha256": "",
        }, "head_sha256")
        return sign_contract_envelope(head, digest_field="head_sha256", purpose=PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY, key_id=self.key_id, signer_id=self.signer_id, trust_domain=self.trust_domain, private_key_b64=self.private_key_b64, issued_at=now_tick, valid_until=now_tick+self.response_ttl)

    def signed_status(self, *, effect_id: str, payload_sha256: str, challenge: str, verifier_id: str, verifier_epoch_sha256: str, policy: Mapping[str, Any], now_tick: int) -> dict[str, Any]:
        policy_result = validate_provider_native_policy(policy, now_tick)
        if policy_result["status"] != "PASS":
            raise ProviderNativeIdempotencyError("invalid_provider_native_policy", str(policy_result["errors"]))
        p = policy_result["policy"]
        if (p["provider_id"], p["service_id"], p["namespace_id"]) != (self.provider_id, self.service_id, self.namespace_id):
            raise ProviderNativeIdempotencyError("provider_native_policy_identity_mismatch", p["policy_id"])
        current = self._state.get(effect_id)
        if current is not None and current["payload_sha256"] != payload_sha256:
            raise ProviderNativeIdempotencyError("provider_native_payload_conflict", effect_id)
        state = "ABSENT" if current is None else current["state"]
        status = seal_mapping({
            "contract_id": PROVIDER_NATIVE_STATUS_CONTRACT_ID,
            "provider_id": self.provider_id,
            "service_id": self.service_id,
            "namespace_id": self.namespace_id,
            "effect_id": effect_id,
            "payload_sha256": payload_sha256,
            "state": state,
            "generation": 0 if current is None else current["generation"],
            "provider_request_id": None if current is None else current["provider_request_id"],
            "provider_response_sha256": None if current is None else current.get("provider_response_sha256"),
            "evidence_sha256": None if current is None else current.get("evidence_sha256"),
            "policy_id": p["policy_id"],
            "policy_sha256": p["policy_sha256"],
            "verifier_id": verifier_id,
            "verifier_epoch_sha256": verifier_epoch_sha256,
            "challenge_sha256": _challenge_sha256(challenge),
            "issued_at": now_tick,
            "valid_until": now_tick + self.response_ttl,
            "authority_granted": False,
            "status_sha256": "",
        }, "status_sha256")
        return sign_contract_envelope(status, digest_field="status_sha256", purpose=PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY, key_id=self.key_id, signer_id=self.signer_id, trust_domain=self.trust_domain, private_key_b64=self.private_key_b64, issued_at=now_tick, valid_until=now_tick+self.response_ttl)


def verify_provider_native_status(value: Mapping[str, Any], *, registry: TrustKeyRegistry, current_policy: Mapping[str, Any], expected_policy_sha256: str, expected_provider_id: str, expected_service_id: str, expected_namespace_id: str, expected_signer_id: str, expected_trust_domain: str, expected_effect_id: str, expected_payload_sha256: str, expected_verifier_id: str, expected_verifier_epoch_sha256: str, expected_challenge: str, evaluation_tick: int, max_age: int = 5, allowed_states: Sequence[str] = ("ABSENT", "NO_EFFECT")) -> dict[str, Any]:
    if tuple(allowed_states) != ("ABSENT", "NO_EFFECT"):
        raise ProviderNativeIdempotencyError("invalid_allowed_provider_native_states", str(tuple(allowed_states)))
    policy_result = validate_provider_native_policy(current_policy, evaluation_tick)
    if policy_result["status"] != "PASS":
        raise ProviderNativeIdempotencyError("provider_native_policy_not_current", str(policy_result["errors"]))
    policy = policy_result["policy"]
    if policy["policy_sha256"] != expected_policy_sha256:
        raise ProviderNativeIdempotencyError("provider_native_policy_substitution", policy["policy_sha256"])
    if (policy["provider_id"], policy["service_id"], policy["namespace_id"]) != (expected_provider_id, expected_service_id, expected_namespace_id):
        raise ProviderNativeIdempotencyError("provider_native_policy_identity_mismatch", policy["policy_id"])
    result = verify_contract_envelope(value, registry=registry, evaluation_tick=evaluation_tick, expected_purpose=PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY, expected_digest_field="status_sha256", expected_inner_contract_id=PROVIDER_NATIVE_STATUS_CONTRACT_ID, expected_signer_id=expected_signer_id, expected_trust_domain=expected_trust_domain)
    if result["status"] != "PASS":
        raise ProviderNativeIdempotencyError("invalid_provider_native_status_signature", str(result["errors"]))
    status = result["inner_contract"]
    if status.get("issued_at") != value.get("issued_at") or status.get("valid_until") != value.get("valid_until"):
        raise ProviderNativeIdempotencyError("provider_native_status_envelope_window_mismatch", expected_effect_id)
    for field, expected in (("provider_id", expected_provider_id), ("service_id", expected_service_id), ("namespace_id", expected_namespace_id), ("effect_id", expected_effect_id), ("payload_sha256", expected_payload_sha256), ("verifier_id", expected_verifier_id), ("verifier_epoch_sha256", expected_verifier_epoch_sha256), ("challenge_sha256", _challenge_sha256(expected_challenge)), ("policy_sha256", expected_policy_sha256), ("policy_id", policy["policy_id"])):
        if status.get(field) != expected:
            raise ProviderNativeIdempotencyError(f"provider_native_{field}_mismatch", str(status.get(field)))
    issued_at = status.get("issued_at")
    if type(issued_at) is not int or issued_at > evaluation_tick or evaluation_tick - issued_at > max_age:
        raise ProviderNativeIdempotencyError("provider_native_status_not_fresh", str(issued_at))
    if status.get("state") not in PROVIDER_NATIVE_PERMISSIVE_STATES:
        raise ProviderNativeIdempotencyError("provider_native_state_blocks_retry", str(status.get("state")))
    if status.get("authority_granted") is not False:
        raise ProviderNativeIdempotencyError("provider_native_authority_expansion", str(status.get("authority_granted")))
    return {"status": "PASS", "provider_status": status, "external_effect_permitted": False, "authority_granted": False}


def verify_provider_native_head(value: Mapping[str, Any], *, registry: TrustKeyRegistry, expected_provider_id: str, expected_service_id: str, expected_namespace_id: str, expected_signer_id: str, expected_trust_domain: str, evaluation_tick: int, max_age: int = 5) -> dict[str, Any]:
    result = verify_contract_envelope(value, registry=registry, evaluation_tick=evaluation_tick, expected_purpose=PURPOSE_PROVIDER_NATIVE_IDEMPOTENCY, expected_digest_field="head_sha256", expected_inner_contract_id=PROVIDER_NATIVE_HEAD_CONTRACT_ID, expected_signer_id=expected_signer_id, expected_trust_domain=expected_trust_domain)
    if result["status"] != "PASS":
        raise ProviderNativeIdempotencyError("invalid_provider_native_head_signature", str(result["errors"]))
    head = result["inner_contract"]
    if head.get("issued_at") != value.get("issued_at") or head.get("valid_until") != value.get("valid_until"):
        raise ProviderNativeIdempotencyError("provider_native_head_envelope_window_mismatch", expected_provider_id)
    for field, expected in (("provider_id", expected_provider_id), ("service_id", expected_service_id), ("namespace_id", expected_namespace_id)):
        if head.get(field) != expected:
            raise ProviderNativeIdempotencyError(f"provider_native_{field}_mismatch", str(head.get(field)))
    issued_at = head.get("issued_at")
    if type(issued_at) is not int or issued_at > evaluation_tick or evaluation_tick - issued_at > max_age:
        raise ProviderNativeIdempotencyError("provider_native_head_not_fresh", str(issued_at))
    if head.get("authority_granted") is not False:
        raise ProviderNativeIdempotencyError("provider_native_authority_expansion", str(head.get("authority_granted")))
    return {"status": "PASS", "head": head, "authority_granted": False}


__all__ = [
    "PROVIDER_NATIVE_POLICY_CONTRACT_ID", "PROVIDER_NATIVE_EVENT_CONTRACT_ID", "PROVIDER_NATIVE_HEAD_CONTRACT_ID", "PROVIDER_NATIVE_STATUS_CONTRACT_ID",
    "PROVIDER_NATIVE_STATES", "PROVIDER_NATIVE_PERMISSIVE_STATES", "PROVIDER_NATIVE_BLOCKING_STATES",
    "ProviderNativeIdempotencyError", "FilesystemProviderNativeIdempotencyReference", "make_provider_native_policy", "validate_provider_native_policy", "verify_provider_native_status", "verify_provider_native_head",
]
