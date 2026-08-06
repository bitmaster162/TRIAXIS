"""TRIAXIS v3.31 external immutable-completion anchor reference.

The reference writes canonical provider outcome envelopes to content-addressed
files using ``O_EXCL`` and records a separate signed, hash-linked event per
accepted outcome.  The public API has no overwrite or delete operation.  A
separate verifier checkpoint ledger remembers the highest observed signed head
and therefore detects rollback while that verifier state remains current.

This is a logical immutable-anchor contract and executable reference.  A local
filesystem can still be deleted, restored or administered by the same operator;
physical WORM media, independent administration, KMS/HSM custody and production
exactly-once execution are explicitly outside the claim.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .crypto_trust import (
    PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
    TrustKeyRegistry,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .idempotent_effect_provider import (
    ProviderEffectError,
    verify_provider_outcome_receipt,
)
from .integrity import (
    canonical_json_bytes,
    canonical_sha256,
    materialize_json,
    seal_mapping,
    verify_sealed_mapping,
)
from .trust_registry_quorum import SQLiteEpochChallengeLedger

COMPLETION_IMMUTABLE_OBJECT_RECEIPT_CONTRACT_ID = (
    "TRIAXIS_COMPLETION_IMMUTABLE_OBJECT_RECEIPT_v1"
)
COMPLETION_IMMUTABLE_ANCHOR_EVENT_CONTRACT_ID = (
    "TRIAXIS_COMPLETION_IMMUTABLE_ANCHOR_EVENT_v1"
)
COMPLETION_IMMUTABLE_ANCHOR_HEAD_CONTRACT_ID = (
    "TRIAXIS_COMPLETION_IMMUTABLE_ANCHOR_HEAD_v1"
)
COMPLETION_IMMUTABLE_ANCHOR_STATUS_CONTRACT_ID = (
    "TRIAXIS_COMPLETION_IMMUTABLE_ANCHOR_STATUS_v1"
)
COMPLETION_IMMUTABLE_ANCHOR_STATES = frozenset(
    {"ABSENT", "UNKNOWN", "COMPLETED", "NO_EFFECT"}
)
COMPLETION_IMMUTABLE_ANCHOR_BLOCKING_STATES = frozenset({"UNKNOWN", "COMPLETED"})
ZERO_SHA256 = "0" * 64


class CompletionImmutableAnchorError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or not challenge:
        raise CompletionImmutableAnchorError("invalid_challenge", str(challenge))
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


def _safe_component(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise CompletionImmutableAnchorError("invalid_path_component", field)
    return value


class FilesystemImmutableCompletionAnchor:
    """Content-addressed, append-only completion anchor reference."""

    def __init__(
        self,
        root: str | Path,
        *,
        anchor_id: str,
        authority_id: str,
        service_id: str,
        provider_id: str,
        provider_service_id: str,
        retention_policy_id: str,
        key_id: str,
        signer_id: str,
        trust_domain: str,
        private_key_b64: str,
        minimum_retention_ticks: int = 100,
        receipt_ttl: int = 30,
    ) -> None:
        for name, value in (
            ("anchor_id", anchor_id),
            ("authority_id", authority_id),
            ("service_id", service_id),
            ("provider_id", provider_id),
            ("provider_service_id", provider_service_id),
            ("retention_policy_id", retention_policy_id),
            ("key_id", key_id),
            ("signer_id", signer_id),
            ("trust_domain", trust_domain),
            ("private_key_b64", private_key_b64),
        ):
            if not isinstance(value, str) or not value:
                raise CompletionImmutableAnchorError("invalid_configuration", name)
        if type(minimum_retention_ticks) is not int or minimum_retention_ticks < 1:
            raise CompletionImmutableAnchorError(
                "invalid_configuration", "minimum_retention_ticks"
            )
        if type(receipt_ttl) is not int or receipt_ttl < 1:
            raise CompletionImmutableAnchorError("invalid_configuration", "receipt_ttl")
        self.root = Path(root).resolve()
        self.objects_dir = self.root / "objects"
        self.receipts_dir = self.root / "receipts"
        self.events_dir = self.root / "events"
        self.anchor_id = anchor_id
        self.authority_id = authority_id
        self.service_id = service_id
        self.provider_id = provider_id
        self.provider_service_id = provider_service_id
        self.retention_policy_id = retention_policy_id
        self.key_id = key_id
        self.signer_id = signer_id
        self.trust_domain = trust_domain
        self._private_key_b64 = private_key_b64
        self.minimum_retention_ticks = minimum_retention_ticks
        self.receipt_ttl = receipt_ttl
        self._lock = threading.RLock()
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        self.events_dir.mkdir(parents=True, exist_ok=True)
        self._registry = self._make_own_registry(private_key_b64)
        self._initialize_identity()
        self._rebuild_state()

    def _make_own_registry(self, private_key_b64: str) -> TrustKeyRegistry:
        try:
            raw = base64.b64decode(private_key_b64.encode("ascii"), validate=True)
            private = Ed25519PrivateKey.from_private_bytes(raw)
            public_b64 = base64.b64encode(
                private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode("ascii")
        except Exception as exc:
            raise CompletionImmutableAnchorError(
                "invalid_configuration", "private_key_b64"
            ) from exc
        return TrustKeyRegistry(
            [
                make_trust_key_record(
                    key_id=self.key_id,
                    signer_id=self.signer_id,
                    trust_domain=self.trust_domain,
                    public_key_b64=public_b64,
                    purposes=[PURPOSE_COMPLETION_IMMUTABLE_ANCHOR],
                    valid_from=0,
                    valid_until=2**62,
                )
            ]
        )

    def _identity_document(self) -> dict[str, Any]:
        return seal_mapping(
            {
                "contract_id": "TRIAXIS_COMPLETION_IMMUTABLE_ANCHOR_IDENTITY_v1",
                "anchor_id": self.anchor_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "provider_id": self.provider_id,
                "provider_service_id": self.provider_service_id,
                "retention_policy_id": self.retention_policy_id,
                "key_id": self.key_id,
                "signer_id": self.signer_id,
                "trust_domain": self.trust_domain,
                "minimum_retention_ticks": self.minimum_retention_ticks,
                "overwrite_api": False,
                "delete_api": False,
                "identity_sha256": "",
            },
            "identity_sha256",
        )

    def _initialize_identity(self) -> None:
        path = self.root / "identity.json"
        payload = canonical_json_bytes(self._identity_document()) + b"\n"
        self._write_once(path, payload)

    @staticmethod
    def _write_once(path: Path, payload: bytes) -> bool:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        except FileExistsError:
            observed = path.read_bytes()
            if observed != payload:
                raise CompletionImmutableAnchorError(
                    "immutable_object_conflict", str(path)
                )
            return False
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                path.unlink(missing_ok=True)
            finally:
                raise
        try:
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(path.parent, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Some filesystems/platforms do not support directory fsync. The
            # reference remains fail-closed on content conflicts, while the
            # deployment claim explicitly excludes physical durability.
            pass
        return True

    def _verify_materialized_artifacts(self, event: Mapping[str, Any]) -> None:
        content_sha256 = event.get("content_sha256")
        object_id = event.get("object_id")
        if not _is_sha256(content_sha256) or object_id != content_sha256:
            raise CompletionImmutableAnchorError(
                "immutable_anchor_object_identity_mismatch", str(object_id)
            )
        expected_key = f"objects/{content_sha256[:2]}/{content_sha256}.json"
        if event.get("object_key") != expected_key:
            raise CompletionImmutableAnchorError(
                "immutable_anchor_object_key_mismatch", str(event.get("object_key"))
            )
        object_path = self.root / expected_key
        if not object_path.is_file():
            raise CompletionImmutableAnchorError(
                "immutable_anchor_object_missing", str(event.get("effect_id"))
            )
        observed_content_sha256 = hashlib.sha256(object_path.read_bytes()).hexdigest()
        if observed_content_sha256 != content_sha256:
            raise CompletionImmutableAnchorError(
                "immutable_anchor_object_content_mismatch", str(event.get("effect_id"))
            )

        receipt_path = self.receipts_dir / f"{content_sha256}.json"
        if not receipt_path.is_file():
            raise CompletionImmutableAnchorError(
                "immutable_anchor_object_receipt_missing", str(event.get("effect_id"))
            )
        try:
            signed_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise CompletionImmutableAnchorError(
                "immutable_anchor_object_receipt_read_failed", receipt_path.name
            ) from exc
        if not isinstance(signed_receipt, dict) or type(
            signed_receipt.get("issued_at")
        ) is not int:
            raise CompletionImmutableAnchorError(
                "invalid_immutable_object_receipt_envelope", receipt_path.name
            )
        verified = verify_contract_envelope(
            signed_receipt,
            registry=self._registry,
            evaluation_tick=signed_receipt["issued_at"],
            expected_purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
            expected_digest_field="receipt_sha256",
            expected_inner_contract_id=COMPLETION_IMMUTABLE_OBJECT_RECEIPT_CONTRACT_ID,
            expected_signer_id=self.signer_id,
            expected_trust_domain=self.trust_domain,
        )
        if verified["status"] != "PASS":
            raise CompletionImmutableAnchorError(
                "invalid_immutable_object_receipt_signature",
                str(verified["errors"]),
            )
        receipt = verified["inner_contract"]
        if not isinstance(receipt, dict):
            raise CompletionImmutableAnchorError(
                "invalid_immutable_object_receipt", receipt_path.name
            )
        for field, expected in (
            ("anchor_id", self.anchor_id),
            ("authority_id", self.authority_id),
            ("service_id", self.service_id),
            ("provider_id", self.provider_id),
            ("provider_service_id", self.provider_service_id),
            ("retention_policy_id", self.retention_policy_id),
            ("effect_id", event.get("effect_id")),
            ("payload_sha256", event.get("payload_sha256")),
            ("state", event.get("state")),
            ("generation", event.get("generation")),
            ("provider_request_id", event.get("provider_request_id")),
            ("provider_receipt_sha256", event.get("provider_receipt_sha256")),
            ("provider_response_sha256", event.get("provider_response_sha256")),
            ("evidence_sha256", event.get("evidence_sha256")),
            ("outcome_at_tick", event.get("outcome_at_tick")),
            ("content_sha256", content_sha256),
            ("object_id", content_sha256),
            ("object_version_id", content_sha256),
            ("object_key", expected_key),
            ("retention_until_tick", event.get("retention_until_tick")),
            ("legal_hold", True),
            ("write_once", True),
            ("overwrite_prohibited", True),
            ("deletion_prohibited", True),
            ("authority_granted", False),
            ("receipt_sha256", event.get("object_receipt_sha256")),
        ):
            if receipt.get(field) != expected:
                raise CompletionImmutableAnchorError(
                    f"immutable_anchor_object_receipt_{field}_mismatch",
                    str(receipt.get(field)),
                )

    def close(self) -> None:
        return None

    def __enter__(self) -> "FilesystemImmutableCompletionAnchor":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _event_paths(self) -> list[Path]:
        paths = sorted(self.events_dir.glob("*.json"))
        return paths

    def _load_signed_events(self) -> list[dict[str, Any]]:
        signed_events: list[dict[str, Any]] = []
        for path in self._event_paths():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise CompletionImmutableAnchorError(
                    "immutable_anchor_event_read_failed", path.name
                ) from exc
            if not isinstance(value, dict):
                raise CompletionImmutableAnchorError(
                    "invalid_immutable_anchor_event", path.name
                )
            signed_events.append(value)
        return signed_events

    def _verify_own_event(self, signed_event: Mapping[str, Any]) -> dict[str, Any]:
        envelope = materialize_json(signed_event)
        if not isinstance(envelope, dict) or type(envelope.get("issued_at")) is not int:
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_event_envelope", "issued_at"
            )
        verified = verify_contract_envelope(
            envelope,
            registry=self._registry,
            evaluation_tick=envelope["issued_at"],
            expected_purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
            expected_digest_field="event_sha256",
            expected_inner_contract_id=COMPLETION_IMMUTABLE_ANCHOR_EVENT_CONTRACT_ID,
            expected_signer_id=self.signer_id,
            expected_trust_domain=self.trust_domain,
        )
        if verified["status"] != "PASS":
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_event_signature", str(verified["errors"])
            )
        event = verified["inner_contract"]
        if not isinstance(event, dict):
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_event", "object required"
            )
        return event

    def _rebuild_state(self) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        previous = ZERO_SHA256
        expected_sequence = 1
        events: list[dict[str, Any]] = []
        effects: dict[str, dict[str, Any]] = {}
        for path, signed in zip(self._event_paths(), self._load_signed_events()):
            event = self._verify_own_event(signed)
            if event.get("sequence") != expected_sequence:
                raise CompletionImmutableAnchorError(
                    "immutable_anchor_sequence_gap",
                    f"expected={expected_sequence} observed={event.get('sequence')}",
                )
            if event.get("previous_event_sha256") != previous:
                raise CompletionImmutableAnchorError(
                    "immutable_anchor_parent_mismatch", str(expected_sequence)
                )
            if path.name != f"{expected_sequence:020d}-{event['event_sha256']}.json":
                raise CompletionImmutableAnchorError(
                    "immutable_anchor_event_filename_mismatch", path.name
                )
            self._verify_materialized_artifacts(event)
            effect_id = event.get("effect_id")
            if not _is_sha256(effect_id):
                raise CompletionImmutableAnchorError(
                    "invalid_effect_id", str(effect_id)
                )
            current = effects.get(effect_id)
            if current is None:
                if event.get("from_state") is not None:
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_invalid_genesis", effect_id
                    )
            else:
                if event.get("payload_sha256") != current["payload_sha256"]:
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_payload_conflict", effect_id
                    )
                observed_generation = event.get("generation")
                if observed_generation == current["generation"]:
                    if not (
                        current["state"] == "UNKNOWN"
                        and event.get("state") in {"COMPLETED", "NO_EFFECT"}
                        and event.get("provider_request_id")
                        == current["provider_request_id"]
                        and event.get("from_state") == "UNKNOWN"
                    ):
                        raise CompletionImmutableAnchorError(
                            "immutable_anchor_state_discontinuity", effect_id
                        )
                elif observed_generation == current["generation"] + 1:
                    if current["state"] != "NO_EFFECT" or event.get("from_state") != "NO_EFFECT":
                        raise CompletionImmutableAnchorError(
                            "immutable_anchor_generation_without_no_effect", effect_id
                        )
                else:
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_generation_gap", effect_id
                    )
            effects[effect_id] = {
                "effect_id": effect_id,
                "payload_sha256": event["payload_sha256"],
                "state": event["state"],
                "generation": event["generation"],
                "provider_request_id": event["provider_request_id"],
                "provider_receipt_sha256": event["provider_receipt_sha256"],
                "provider_response_sha256": event["provider_response_sha256"],
                "evidence_sha256": event["evidence_sha256"],
                "outcome_at_tick": event["outcome_at_tick"],
                "object_id": event["object_id"],
                "object_key": event["object_key"],
                "content_sha256": event["content_sha256"],
                "object_receipt_sha256": event["object_receipt_sha256"],
                "retention_until_tick": event["retention_until_tick"],
                "legal_hold": event["legal_hold"],
                "last_event_sha256": event["event_sha256"],
                "anchored_at_tick": event["anchored_at_tick"],
            }
            previous = event["event_sha256"]
            expected_sequence += 1
            events.append(event)
        return events, effects

    def _head_tuple(self) -> tuple[int, str]:
        events, _ = self._rebuild_state()
        if not events:
            return 0, ZERO_SHA256
        return len(events), events[-1]["event_sha256"]

    def _state_root(self) -> str:
        _, effects = self._rebuild_state()
        rows = [effects[key] for key in sorted(effects)]
        return canonical_sha256(rows)

    def get(self, effect_id: str) -> dict[str, Any] | None:
        if not _is_sha256(effect_id):
            raise CompletionImmutableAnchorError("invalid_effect_id", str(effect_id))
        _, effects = self._rebuild_state()
        value = effects.get(effect_id)
        return materialize_json(value) if value is not None else None

    def effect_count(self) -> int:
        _, effects = self._rebuild_state()
        return len(effects)

    def event_count(self) -> int:
        events, _ = self._rebuild_state()
        return len(events)

    def health_snapshot(self) -> dict[str, Any]:
        sequence, head_event = self._head_tuple()
        return {
            "anchor_id": self.anchor_id,
            "provider_id": self.provider_id,
            "provider_service_id": self.provider_service_id,
            "retention_policy_id": self.retention_policy_id,
            "sequence": sequence,
            "head_event_sha256": head_event,
            "state_root_sha256": self._state_root(),
            "effect_count": self.effect_count(),
            "content_addressed": True,
            "overwrite_api": False,
            "delete_api": False,
            "physical_worm_established": False,
        }

    def store_provider_outcome(
        self,
        signed_provider_receipt: Mapping[str, Any],
        *,
        provider_registry: TrustKeyRegistry,
        expected_provider_signer_id: str,
        expected_provider_trust_domain: str,
        evaluation_tick: int,
        retention_until_tick: int,
        legal_hold: bool = True,
        max_provider_receipt_age: int = 30,
    ) -> dict[str, Any]:
        if type(evaluation_tick) is not int or evaluation_tick < 0:
            raise CompletionImmutableAnchorError(
                "invalid_evaluation_tick", str(evaluation_tick)
            )
        if (
            type(retention_until_tick) is not int
            or retention_until_tick
            < evaluation_tick + self.minimum_retention_ticks
        ):
            raise CompletionImmutableAnchorError(
                "immutable_retention_window_too_short", str(retention_until_tick)
            )
        if legal_hold is not True:
            raise CompletionImmutableAnchorError(
                "immutable_legal_hold_required", str(legal_hold)
            )
        envelope = materialize_json(signed_provider_receipt)
        if not isinstance(envelope, dict):
            raise CompletionImmutableAnchorError(
                "invalid_provider_outcome_receipt", "object required"
            )
        inner = envelope.get("inner_contract")
        effect_id = inner.get("effect_id") if isinstance(inner, dict) else None
        payload_sha256 = inner.get("payload_sha256") if isinstance(inner, dict) else None
        if not _is_sha256(effect_id) or not _is_sha256(payload_sha256):
            raise CompletionImmutableAnchorError(
                "invalid_provider_outcome_identity", f"{effect_id}:{payload_sha256}"
            )
        try:
            verified = verify_provider_outcome_receipt(
                envelope,
                registry=provider_registry,
                expected_provider_id=self.provider_id,
                expected_service_id=self.provider_service_id,
                expected_signer_id=expected_provider_signer_id,
                expected_trust_domain=expected_provider_trust_domain,
                expected_effect_id=effect_id,
                expected_payload_sha256=payload_sha256,
                evaluation_tick=evaluation_tick,
                max_receipt_age=max_provider_receipt_age,
            )
        except ProviderEffectError as exc:
            raise CompletionImmutableAnchorError(exc.code, exc.detail) from exc
        receipt = verified["provider_receipt"]
        object_payload = canonical_json_bytes(envelope) + b"\n"
        content_sha256 = hashlib.sha256(object_payload).hexdigest()
        object_id = content_sha256
        object_key = f"objects/{content_sha256[:2]}/{content_sha256}.json"
        object_path = self.root / object_key
        receipt_path = self.receipts_dir / f"{content_sha256}.json"

        with self._lock:
            events, effects = self._rebuild_state()
            current = effects.get(effect_id)
            from_state: str | None = None
            if current is not None:
                exact_statement = (
                    current["state"] == receipt["state"]
                    and current["generation"] == receipt["generation"]
                    and current["provider_request_id"] == receipt["provider_request_id"]
                    and current["provider_response_sha256"]
                    == receipt["provider_response_sha256"]
                    and current["evidence_sha256"] == receipt["evidence_sha256"]
                    and current["outcome_at_tick"] == receipt["outcome_at_tick"]
                    and current["content_sha256"] == content_sha256
                )
                if exact_statement:
                    if not object_path.exists() or not receipt_path.exists():
                        raise CompletionImmutableAnchorError(
                            "immutable_anchor_object_missing", effect_id
                        )
                    signed_object_receipt = json.loads(
                        receipt_path.read_text(encoding="utf-8")
                    )
                    return {
                        "status": "PASS",
                        "idempotent_replay": True,
                        "effect": self.get(effect_id),
                        "provider_receipt": receipt,
                        "signed_object_receipt": signed_object_receipt,
                    }
                if receipt["generation"] < current["generation"]:
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_generation_rollback",
                        f"current={current['generation']} observed={receipt['generation']}",
                    )
                if receipt["generation"] == current["generation"]:
                    if (
                        current["state"] == "UNKNOWN"
                        and receipt["state"] in {"COMPLETED", "NO_EFFECT"}
                        and receipt["provider_request_id"]
                        == current["provider_request_id"]
                    ):
                        from_state = "UNKNOWN"
                    else:
                        raise CompletionImmutableAnchorError(
                            "immutable_anchor_outcome_conflict",
                            f"current={current['state']} observed={receipt['state']}",
                        )
                elif receipt["generation"] == current["generation"] + 1:
                    if current["state"] != "NO_EFFECT":
                        raise CompletionImmutableAnchorError(
                            "immutable_anchor_generation_without_no_effect",
                            current["state"],
                        )
                    from_state = "NO_EFFECT"
                else:
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_generation_gap",
                        f"current={current['generation']} observed={receipt['generation']}",
                    )

            self._write_once(object_path, object_payload)
            sequence = len(events) + 1
            previous = events[-1]["event_sha256"] if events else ZERO_SHA256
            object_receipt = seal_mapping(
                {
                    "contract_id": COMPLETION_IMMUTABLE_OBJECT_RECEIPT_CONTRACT_ID,
                    "anchor_id": self.anchor_id,
                    "authority_id": self.authority_id,
                    "service_id": self.service_id,
                    "provider_id": self.provider_id,
                    "provider_service_id": self.provider_service_id,
                    "effect_id": effect_id,
                    "payload_sha256": payload_sha256,
                    "state": receipt["state"],
                    "generation": receipt["generation"],
                    "provider_request_id": receipt["provider_request_id"],
                    "provider_receipt_sha256": receipt["receipt_sha256"],
                    "provider_response_sha256": receipt["provider_response_sha256"],
                    "evidence_sha256": receipt["evidence_sha256"],
                    "outcome_at_tick": receipt["outcome_at_tick"],
                    "object_id": object_id,
                    "object_key": object_key,
                    "object_version_id": content_sha256,
                    "content_sha256": content_sha256,
                    "retention_policy_id": self.retention_policy_id,
                    "retention_until_tick": retention_until_tick,
                    "legal_hold": True,
                    "write_once": True,
                    "overwrite_prohibited": True,
                    "deletion_prohibited": True,
                    "stored_at_tick": evaluation_tick,
                    "authority_granted": False,
                    "receipt_sha256": "",
                },
                "receipt_sha256",
            )
            signed_object_receipt = sign_contract_envelope(
                object_receipt,
                digest_field="receipt_sha256",
                purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
                key_id=self.key_id,
                signer_id=self.signer_id,
                trust_domain=self.trust_domain,
                private_key_b64=self._private_key_b64,
                issued_at=evaluation_tick,
                valid_until=retention_until_tick,
            )
            self._write_once(
                receipt_path,
                canonical_json_bytes(signed_object_receipt) + b"\n",
            )
            event = seal_mapping(
                {
                    "contract_id": COMPLETION_IMMUTABLE_ANCHOR_EVENT_CONTRACT_ID,
                    "anchor_id": self.anchor_id,
                    "authority_id": self.authority_id,
                    "service_id": self.service_id,
                    "provider_id": self.provider_id,
                    "provider_service_id": self.provider_service_id,
                    "sequence": sequence,
                    "previous_event_sha256": previous,
                    "effect_id": effect_id,
                    "payload_sha256": payload_sha256,
                    "from_state": from_state,
                    "state": receipt["state"],
                    "generation": receipt["generation"],
                    "provider_request_id": receipt["provider_request_id"],
                    "provider_receipt_sha256": receipt["receipt_sha256"],
                    "provider_response_sha256": receipt["provider_response_sha256"],
                    "evidence_sha256": receipt["evidence_sha256"],
                    "outcome_at_tick": receipt["outcome_at_tick"],
                    "object_id": object_id,
                    "object_key": object_key,
                    "content_sha256": content_sha256,
                    "object_receipt_sha256": object_receipt["receipt_sha256"],
                    "retention_until_tick": retention_until_tick,
                    "legal_hold": True,
                    "anchored_at_tick": evaluation_tick,
                    "authority_granted": False,
                    "event_sha256": "",
                },
                "event_sha256",
            )
            signed_event = sign_contract_envelope(
                event,
                digest_field="event_sha256",
                purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
                key_id=self.key_id,
                signer_id=self.signer_id,
                trust_domain=self.trust_domain,
                private_key_b64=self._private_key_b64,
                issued_at=evaluation_tick,
                valid_until=retention_until_tick,
            )
            event_path = self.events_dir / f"{sequence:020d}-{event['event_sha256']}.json"
            self._write_once(event_path, canonical_json_bytes(signed_event) + b"\n")
            return {
                "status": "PASS",
                "idempotent_replay": False,
                "effect": self.get(effect_id),
                "provider_receipt": receipt,
                "signed_object_receipt": signed_object_receipt,
                "signed_anchor_event": signed_event,
            }

    def events_since(self, sequence: int) -> list[dict[str, Any]]:
        if type(sequence) is not int or sequence < 0:
            raise CompletionImmutableAnchorError("invalid_sequence", str(sequence))
        return self._load_signed_events()[sequence:]

    def head(self, *, now_tick: int) -> dict[str, Any]:
        if type(now_tick) is not int or now_tick < 0:
            raise CompletionImmutableAnchorError("invalid_now_tick", str(now_tick))
        sequence, head_event = self._head_tuple()
        head = seal_mapping(
            {
                "contract_id": COMPLETION_IMMUTABLE_ANCHOR_HEAD_CONTRACT_ID,
                "anchor_id": self.anchor_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "provider_id": self.provider_id,
                "provider_service_id": self.provider_service_id,
                "retention_policy_id": self.retention_policy_id,
                "sequence": sequence,
                "head_event_sha256": head_event,
                "state_root_sha256": self._state_root(),
                "issued_at_tick": now_tick,
                "physical_worm_established": False,
                "authority_granted": False,
                "head_sha256": "",
            },
            "head_sha256",
        )
        return sign_contract_envelope(
            head,
            digest_field="head_sha256",
            purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=now_tick,
            valid_until=now_tick + self.receipt_ttl,
        )

    def issue_status(
        self,
        *,
        effect_id: str,
        expected_payload_sha256: str,
        challenge: str,
        verifier_id: str,
        verifier_epoch_sha256: str,
        requested_at: int,
        issued_at: int,
        valid_until: int | None = None,
    ) -> dict[str, Any]:
        if not _is_sha256(effect_id):
            raise CompletionImmutableAnchorError("invalid_effect_id", str(effect_id))
        if not _is_sha256(expected_payload_sha256):
            raise CompletionImmutableAnchorError(
                "invalid_payload_sha256", str(expected_payload_sha256)
            )
        if not isinstance(verifier_id, str) or not verifier_id:
            raise CompletionImmutableAnchorError("invalid_verifier_id", str(verifier_id))
        if not _is_sha256(verifier_epoch_sha256):
            raise CompletionImmutableAnchorError(
                "invalid_verifier_epoch", str(verifier_epoch_sha256)
            )
        if (
            type(requested_at) is not int
            or type(issued_at) is not int
            or requested_at < 0
            or issued_at < requested_at
        ):
            raise CompletionImmutableAnchorError(
                "invalid_response_time", f"{requested_at}:{issued_at}"
            )
        if valid_until is None:
            valid_until = issued_at + self.receipt_ttl
        if type(valid_until) is not int or valid_until <= issued_at:
            raise CompletionImmutableAnchorError(
                "invalid_response_window", str(valid_until)
            )
        current = self.get(effect_id)
        if current is None:
            state = "ABSENT"
            payload_sha256 = expected_payload_sha256
            generation = 0
            provider_request_id = None
            provider_receipt_sha256 = None
            provider_response_sha256 = None
            evidence_sha256 = None
            outcome_at_tick = None
            object_id = None
            object_receipt_sha256 = None
            retention_until_tick = None
            legal_hold = None
        else:
            state = current["state"]
            payload_sha256 = current["payload_sha256"]
            generation = current["generation"]
            provider_request_id = current["provider_request_id"]
            provider_receipt_sha256 = current["provider_receipt_sha256"]
            provider_response_sha256 = current["provider_response_sha256"]
            evidence_sha256 = current["evidence_sha256"]
            outcome_at_tick = current["outcome_at_tick"]
            object_id = current["object_id"]
            object_receipt_sha256 = current["object_receipt_sha256"]
            retention_until_tick = current["retention_until_tick"]
            legal_hold = current["legal_hold"]
        sequence, head_event = self._head_tuple()
        status = seal_mapping(
            {
                "contract_id": COMPLETION_IMMUTABLE_ANCHOR_STATUS_CONTRACT_ID,
                "anchor_id": self.anchor_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "provider_id": self.provider_id,
                "provider_service_id": self.provider_service_id,
                "retention_policy_id": self.retention_policy_id,
                "effect_id": effect_id,
                "payload_sha256": payload_sha256,
                "state": state,
                "generation": generation,
                "provider_request_id": provider_request_id,
                "provider_receipt_sha256": provider_receipt_sha256,
                "provider_response_sha256": provider_response_sha256,
                "evidence_sha256": evidence_sha256,
                "outcome_at_tick": outcome_at_tick,
                "object_id": object_id,
                "object_receipt_sha256": object_receipt_sha256,
                "retention_until_tick": retention_until_tick,
                "legal_hold": legal_hold,
                "anchor_sequence": sequence,
                "anchor_head_event_sha256": head_event,
                "anchor_state_root_sha256": self._state_root(),
                "verifier_id": verifier_id,
                "verifier_epoch_sha256": verifier_epoch_sha256,
                "challenge_sha256": _challenge_sha256(challenge),
                "requested_at": requested_at,
                "issued_at": issued_at,
                "valid_until": valid_until,
                "physical_worm_established": False,
                "authority_granted": False,
                "status_sha256": "",
            },
            "status_sha256",
        )
        return sign_contract_envelope(
            status,
            digest_field="status_sha256",
            purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at,
            valid_until=valid_until,
        )


class SQLiteImmutableAnchorCheckpointLedger:
    """Verifier-side monotonic memory for an immutable-anchor head."""

    def __init__(self, path: str | Path, *, anchor_id: str) -> None:
        if not isinstance(anchor_id, str) or not anchor_id:
            raise CompletionImmutableAnchorError("invalid_anchor_id", str(anchor_id))
        self.path = str(path)
        self.anchor_id = anchor_id
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS immutable_anchor_checkpoints (
              anchor_id TEXT PRIMARY KEY,
              sequence INTEGER NOT NULL,
              head_event_sha256 TEXT NOT NULL,
              state_root_sha256 TEXT NOT NULL,
              observed_at_tick INTEGER NOT NULL
            )
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteImmutableAnchorCheckpointLedger":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def snapshot(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT sequence,head_event_sha256,state_root_sha256,observed_at_tick "
            "FROM immutable_anchor_checkpoints WHERE anchor_id=?",
            (self.anchor_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "anchor_id": self.anchor_id,
            "sequence": int(row[0]),
            "head_event_sha256": str(row[1]),
            "state_root_sha256": str(row[2]),
            "observed_at_tick": int(row[3]),
        }

    def observe(
        self,
        *,
        sequence: int,
        head_event_sha256: str,
        state_root_sha256: str,
        observed_at_tick: int,
    ) -> dict[str, Any]:
        if type(sequence) is not int or sequence < 0:
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_sequence", str(sequence)
            )
        if not _is_sha256(head_event_sha256) or not _is_sha256(state_root_sha256):
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_checkpoint_digest",
                f"{head_event_sha256}:{state_root_sha256}",
            )
        if type(observed_at_tick) is not int or observed_at_tick < 0:
            raise CompletionImmutableAnchorError(
                "invalid_observed_at_tick", str(observed_at_tick)
            )
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            current = self.snapshot()
            if current is None:
                self._conn.execute(
                    "INSERT INTO immutable_anchor_checkpoints("
                    "anchor_id,sequence,head_event_sha256,state_root_sha256,observed_at_tick"
                    ") VALUES(?,?,?,?,?)",
                    (
                        self.anchor_id,
                        sequence,
                        head_event_sha256,
                        state_root_sha256,
                        observed_at_tick,
                    ),
                )
            else:
                if sequence < current["sequence"]:
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_checkpoint_rollback",
                        f"pinned={current['sequence']} observed={sequence}",
                    )
                if sequence == current["sequence"] and (
                    head_event_sha256 != current["head_event_sha256"]
                    or state_root_sha256 != current["state_root_sha256"]
                ):
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_checkpoint_fork", str(sequence)
                    )
                if sequence > current["sequence"]:
                    self._conn.execute(
                        "UPDATE immutable_anchor_checkpoints SET sequence=?,head_event_sha256=?,"
                        "state_root_sha256=?,observed_at_tick=? WHERE anchor_id=?",
                        (
                            sequence,
                            head_event_sha256,
                            state_root_sha256,
                            observed_at_tick,
                            self.anchor_id,
                        ),
                    )
            self._conn.commit()
            return {"status": "PASS", "checkpoint": self.snapshot()}
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def observe_head(self, head: Mapping[str, Any], *, observed_at_tick: int) -> dict[str, Any]:
        if head.get("anchor_id") != self.anchor_id:
            raise CompletionImmutableAnchorError(
                "immutable_anchor_checkpoint_identity_mismatch",
                str(head.get("anchor_id")),
            )
        return self.observe(
            sequence=head.get("sequence"),
            head_event_sha256=head.get("head_event_sha256"),
            state_root_sha256=head.get("state_root_sha256"),
            observed_at_tick=observed_at_tick,
        )

    def observe_status(
        self, status: Mapping[str, Any], *, observed_at_tick: int
    ) -> dict[str, Any]:
        if status.get("anchor_id") != self.anchor_id:
            raise CompletionImmutableAnchorError(
                "immutable_anchor_checkpoint_identity_mismatch",
                str(status.get("anchor_id")),
            )
        return self.observe(
            sequence=status.get("anchor_sequence"),
            head_event_sha256=status.get("anchor_head_event_sha256"),
            state_root_sha256=status.get("anchor_state_root_sha256"),
            observed_at_tick=observed_at_tick,
        )


def verify_completion_immutable_object_receipt(
    signed_object_receipt: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    signed_provider_receipt: Mapping[str, Any],
    provider_registry: TrustKeyRegistry,
    expected_provider_signer_id: str,
    expected_provider_trust_domain: str,
    evaluation_tick: int,
    max_provider_receipt_age: int = 30,
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_object_receipt,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
        expected_digest_field="receipt_sha256",
        expected_inner_contract_id=COMPLETION_IMMUTABLE_OBJECT_RECEIPT_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionImmutableAnchorError(
            "invalid_immutable_object_receipt_signature", str(verified["errors"])
        )
    receipt = verified["inner_contract"]
    if not isinstance(receipt, dict):
        raise CompletionImmutableAnchorError(
            "invalid_immutable_object_receipt", "object required"
        )
    provider_inner = signed_provider_receipt.get("inner_contract")
    if not isinstance(provider_inner, Mapping):
        raise CompletionImmutableAnchorError(
            "invalid_provider_outcome_receipt", "inner contract required"
        )
    try:
        provider_verified = verify_provider_outcome_receipt(
            signed_provider_receipt,
            registry=provider_registry,
            expected_provider_id=expected_provider_id,
            expected_service_id=expected_provider_service_id,
            expected_signer_id=expected_provider_signer_id,
            expected_trust_domain=expected_provider_trust_domain,
            expected_effect_id=str(provider_inner.get("effect_id", "")),
            expected_payload_sha256=str(provider_inner.get("payload_sha256", "")),
            evaluation_tick=evaluation_tick,
            max_receipt_age=max_provider_receipt_age,
        )
    except ProviderEffectError as exc:
        raise CompletionImmutableAnchorError(exc.code, exc.detail) from exc
    provider_receipt = provider_verified["provider_receipt"]
    for field, expected in (
        ("anchor_id", expected_anchor_id),
        ("authority_id", expected_authority_id),
        ("service_id", expected_service_id),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
        ("effect_id", provider_receipt["effect_id"]),
        ("payload_sha256", provider_receipt["payload_sha256"]),
        ("state", provider_receipt["state"]),
        ("generation", provider_receipt["generation"]),
        ("provider_request_id", provider_receipt["provider_request_id"]),
        ("provider_receipt_sha256", provider_receipt["receipt_sha256"]),
        ("provider_response_sha256", provider_receipt["provider_response_sha256"]),
        ("evidence_sha256", provider_receipt["evidence_sha256"]),
        ("outcome_at_tick", provider_receipt["outcome_at_tick"]),
    ):
        if receipt.get(field) != expected:
            raise CompletionImmutableAnchorError(
                f"immutable_object_{field}_mismatch", str(receipt.get(field))
            )
    content_sha256 = hashlib.sha256(
        canonical_json_bytes(materialize_json(signed_provider_receipt)) + b"\n"
    ).hexdigest()
    if receipt.get("content_sha256") != content_sha256:
        raise CompletionImmutableAnchorError(
            "immutable_object_content_digest_mismatch",
            str(receipt.get("content_sha256")),
        )
    if receipt.get("object_id") != content_sha256 or receipt.get(
        "object_version_id"
    ) != content_sha256:
        raise CompletionImmutableAnchorError(
            "immutable_object_identity_mismatch", str(receipt.get("object_id"))
        )
    if receipt.get("object_key") != (
        f"objects/{content_sha256[:2]}/{content_sha256}.json"
    ):
        raise CompletionImmutableAnchorError(
            "immutable_object_key_mismatch", str(receipt.get("object_key"))
        )
    if any(
        receipt.get(field) is not True
        for field in (
            "legal_hold",
            "write_once",
            "overwrite_prohibited",
            "deletion_prohibited",
        )
    ):
        raise CompletionImmutableAnchorError(
            "immutable_object_retention_claim_missing", receipt["effect_id"]
        )
    retention_until = receipt.get("retention_until_tick")
    stored_at = receipt.get("stored_at_tick")
    if (
        type(stored_at) is not int
        or type(retention_until) is not int
        or stored_at < provider_receipt["outcome_at_tick"]
        or retention_until <= evaluation_tick
        or retention_until <= stored_at
    ):
        raise CompletionImmutableAnchorError(
            "immutable_object_retention_not_current", str(retention_until)
        )
    if receipt.get("authority_granted") is not False:
        raise CompletionImmutableAnchorError(
            "immutable_anchor_authority_expansion",
            str(receipt.get("authority_granted")),
        )
    return {
        "status": "PASS",
        "object_receipt": receipt,
        "provider_receipt": provider_receipt,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_completion_immutable_anchor_event(
    signed_event: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    evaluation_tick: int,
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_event,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
        expected_digest_field="event_sha256",
        expected_inner_contract_id=COMPLETION_IMMUTABLE_ANCHOR_EVENT_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_event_signature", str(verified["errors"])
        )
    event = verified["inner_contract"]
    if not isinstance(event, dict):
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_event", "object required"
        )
    for field, expected in (
        ("anchor_id", expected_anchor_id),
        ("authority_id", expected_authority_id),
        ("service_id", expected_service_id),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
    ):
        if event.get(field) != expected:
            raise CompletionImmutableAnchorError(
                f"immutable_anchor_{field}_mismatch", str(event.get(field))
            )
    if type(event.get("sequence")) is not int or event["sequence"] < 1:
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_sequence", str(event.get("sequence"))
        )
    for field in (
        "previous_event_sha256",
        "effect_id",
        "payload_sha256",
        "provider_receipt_sha256",
        "evidence_sha256",
        "object_id",
        "content_sha256",
        "object_receipt_sha256",
        "event_sha256",
    ):
        if not _is_sha256(event.get(field)):
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_digest", f"{field}={event.get(field)}"
            )
    if event.get("state") not in {"UNKNOWN", "COMPLETED", "NO_EFFECT"}:
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_state", str(event.get("state"))
        )
    if type(event.get("generation")) is not int or event["generation"] < 1:
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_generation", str(event.get("generation"))
        )
    if not isinstance(event.get("provider_request_id"), str) or not event[
        "provider_request_id"
    ]:
        raise CompletionImmutableAnchorError(
            "invalid_provider_request_id", str(event.get("provider_request_id"))
        )
    if event["state"] == "COMPLETED" and not _is_sha256(
        event.get("provider_response_sha256")
    ):
        raise CompletionImmutableAnchorError(
            "immutable_anchor_provider_response_required",
            str(event.get("provider_response_sha256")),
        )
    if event.get("object_key") != (
        f"objects/{event['content_sha256'][:2]}/{event['content_sha256']}.json"
    ):
        raise CompletionImmutableAnchorError(
            "immutable_anchor_object_key_mismatch", str(event.get("object_key"))
        )
    if event.get("object_id") != event.get("content_sha256"):
        raise CompletionImmutableAnchorError(
            "immutable_anchor_object_identity_mismatch", str(event.get("object_id"))
        )
    if event.get("legal_hold") is not True:
        raise CompletionImmutableAnchorError(
            "immutable_anchor_legal_hold_required", str(event.get("legal_hold"))
        )
    for field in ("outcome_at_tick", "anchored_at_tick", "retention_until_tick"):
        if type(event.get(field)) is not int or event[field] < 0:
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_time", f"{field}={event.get(field)}"
            )
    if not (
        event["outcome_at_tick"] <= event["anchored_at_tick"] < event["retention_until_tick"]
    ):
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_retention_window", event["effect_id"]
        )
    if event.get("authority_granted") is not False:
        raise CompletionImmutableAnchorError(
            "immutable_anchor_authority_expansion", str(event.get("authority_granted"))
        )
    return {
        "status": "PASS",
        "event": event,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_completion_immutable_anchor_event_chain(
    signed_events: Sequence[Mapping[str, Any]],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    evaluation_tick: int,
) -> dict[str, Any]:
    previous = ZERO_SHA256
    expected_sequence = 1
    effects: dict[str, dict[str, Any]] = {}
    verified_events: list[dict[str, Any]] = []
    for signed_event in signed_events:
        result = verify_completion_immutable_anchor_event(
            signed_event,
            registry=registry,
            expected_anchor_id=expected_anchor_id,
            expected_authority_id=expected_authority_id,
            expected_service_id=expected_service_id,
            expected_signer_id=expected_signer_id,
            expected_trust_domain=expected_trust_domain,
            expected_provider_id=expected_provider_id,
            expected_provider_service_id=expected_provider_service_id,
            evaluation_tick=evaluation_tick,
        )
        event = result["event"]
        if event["sequence"] != expected_sequence:
            raise CompletionImmutableAnchorError(
                "immutable_anchor_chain_sequence_gap", str(event["sequence"])
            )
        if event["previous_event_sha256"] != previous:
            raise CompletionImmutableAnchorError(
                "immutable_anchor_chain_parent_mismatch", str(event["sequence"])
            )
        current = effects.get(event["effect_id"])
        if current is None:
            if event["from_state"] is not None:
                raise CompletionImmutableAnchorError(
                    "immutable_anchor_chain_invalid_genesis", event["effect_id"]
                )
        else:
            if event["payload_sha256"] != current["payload_sha256"]:
                raise CompletionImmutableAnchorError(
                    "immutable_anchor_chain_payload_conflict", event["effect_id"]
                )
            if event["generation"] == current["generation"]:
                if not (
                    current["state"] == "UNKNOWN"
                    and event["state"] in {"COMPLETED", "NO_EFFECT"}
                    and event["provider_request_id"] == current["provider_request_id"]
                    and event["from_state"] == "UNKNOWN"
                ):
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_chain_state_discontinuity", event["effect_id"]
                    )
            elif event["generation"] == current["generation"] + 1:
                if current["state"] != "NO_EFFECT" or event["from_state"] != "NO_EFFECT":
                    raise CompletionImmutableAnchorError(
                        "immutable_anchor_chain_generation_without_no_effect",
                        event["effect_id"],
                    )
            else:
                raise CompletionImmutableAnchorError(
                    "immutable_anchor_chain_generation_gap", event["effect_id"]
                )
        effects[event["effect_id"]] = {
            "payload_sha256": event["payload_sha256"],
            "state": event["state"],
            "generation": event["generation"],
            "provider_request_id": event["provider_request_id"],
            "provider_receipt_sha256": event["provider_receipt_sha256"],
            "provider_response_sha256": event["provider_response_sha256"],
            "evidence_sha256": event["evidence_sha256"],
            "outcome_at_tick": event["outcome_at_tick"],
            "object_id": event["object_id"],
            "object_receipt_sha256": event["object_receipt_sha256"],
            "retention_until_tick": event["retention_until_tick"],
            "last_event_sha256": event["event_sha256"],
        }
        previous = event["event_sha256"]
        expected_sequence += 1
        verified_events.append(event)
    return {
        "status": "PASS",
        "event_count": len(verified_events),
        "head_sequence": len(verified_events),
        "head_event_sha256": previous,
        "effects": materialize_json(effects),
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_completion_immutable_anchor_head(
    signed_head: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    expected_retention_policy_id: str,
    evaluation_tick: int,
    checkpoint_ledger: SQLiteImmutableAnchorCheckpointLedger | None = None,
    max_head_age: int = 30,
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_head,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
        expected_digest_field="head_sha256",
        expected_inner_contract_id=COMPLETION_IMMUTABLE_ANCHOR_HEAD_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_head_signature", str(verified["errors"])
        )
    head = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(head, dict) or not isinstance(envelope, dict):
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_head", "object required"
        )
    for field, expected in (
        ("anchor_id", expected_anchor_id),
        ("authority_id", expected_authority_id),
        ("service_id", expected_service_id),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
        ("retention_policy_id", expected_retention_policy_id),
    ):
        if head.get(field) != expected:
            raise CompletionImmutableAnchorError(
                f"immutable_anchor_{field}_mismatch", str(head.get(field))
            )
    if type(head.get("sequence")) is not int or head["sequence"] < 0:
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_sequence", str(head.get("sequence"))
        )
    for field in ("head_event_sha256", "state_root_sha256", "head_sha256"):
        if not _is_sha256(head.get(field)):
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_head_digest", f"{field}={head.get(field)}"
            )
    issued_at = head.get("issued_at_tick")
    if (
        type(issued_at) is not int
        or issued_at != envelope.get("issued_at")
        or issued_at > evaluation_tick
        or evaluation_tick - issued_at > max_head_age
    ):
        raise CompletionImmutableAnchorError(
            "immutable_anchor_head_not_fresh", str(issued_at)
        )
    if head.get("physical_worm_established") is not False:
        raise CompletionImmutableAnchorError(
            "immutable_anchor_physical_claim_expansion",
            str(head.get("physical_worm_established")),
        )
    if head.get("authority_granted") is not False:
        raise CompletionImmutableAnchorError(
            "immutable_anchor_authority_expansion", str(head.get("authority_granted"))
        )
    checkpoint = None
    if checkpoint_ledger is not None:
        checkpoint = checkpoint_ledger.observe_head(
            head, observed_at_tick=evaluation_tick
        )["checkpoint"]
    return {
        "status": "PASS",
        "head": head,
        "checkpoint": checkpoint,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_completion_immutable_anchor_status(
    signed_status: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    expected_retention_policy_id: str,
    expected_effect_id: str,
    expected_payload_sha256: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    checkpoint_ledger: SQLiteImmutableAnchorCheckpointLedger | None = None,
    allowed_states: Sequence[str] = ("ABSENT", "NO_EFFECT"),
    max_response_age: int = 5,
) -> dict[str, Any]:
    allowed = set(allowed_states)
    if not allowed or not allowed.issubset(COMPLETION_IMMUTABLE_ANCHOR_STATES):
        raise CompletionImmutableAnchorError(
            "invalid_allowed_immutable_anchor_states", str(tuple(allowed_states))
        )
    challenge = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    verified = verify_contract_envelope(
        signed_status,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_IMMUTABLE_ANCHOR,
        expected_digest_field="status_sha256",
        expected_inner_contract_id=COMPLETION_IMMUTABLE_ANCHOR_STATUS_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_status_signature", str(verified["errors"])
        )
    status = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(status, dict) or not isinstance(envelope, dict):
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_status", "object required"
        )
    for field, expected in (
        ("anchor_id", expected_anchor_id),
        ("authority_id", expected_authority_id),
        ("service_id", expected_service_id),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
        ("retention_policy_id", expected_retention_policy_id),
        ("effect_id", expected_effect_id),
        ("payload_sha256", expected_payload_sha256),
    ):
        if status.get(field) != expected:
            raise CompletionImmutableAnchorError(
                f"immutable_anchor_{field}_mismatch", str(status.get(field))
            )
    if status.get("state") not in allowed:
        raise CompletionImmutableAnchorError(
            "immutable_anchor_state_blocks_retry", str(status.get("state"))
        )
    if (
        status.get("verifier_id") != challenge_ledger.session.verifier_id
        or status.get("verifier_epoch_sha256")
        != challenge_ledger.session.epoch_sha256
        or status.get("challenge_sha256") != challenge["challenge_sha256"]
        or status.get("requested_at") != challenge["issued_at"]
    ):
        raise CompletionImmutableAnchorError(
            "immutable_anchor_challenge_binding_mismatch",
            str(status.get("challenge_sha256")),
        )
    issued_at = status.get("issued_at")
    valid_until = status.get("valid_until")
    if (
        type(issued_at) is not int
        or type(valid_until) is not int
        or issued_at != envelope.get("issued_at")
        or valid_until != envelope.get("valid_until")
        or issued_at > evaluation_tick
        or evaluation_tick >= valid_until
        or evaluation_tick - issued_at > max_response_age
    ):
        raise CompletionImmutableAnchorError(
            "immutable_anchor_status_not_fresh", str(issued_at)
        )
    if type(status.get("anchor_sequence")) is not int or status[
        "anchor_sequence"
    ] < 0:
        raise CompletionImmutableAnchorError(
            "invalid_immutable_anchor_sequence", str(status.get("anchor_sequence"))
        )
    for field in ("anchor_head_event_sha256", "anchor_state_root_sha256"):
        if not _is_sha256(status.get(field)):
            raise CompletionImmutableAnchorError(
                "invalid_immutable_anchor_head", f"{field}={status.get(field)}"
            )
    state = status["state"]
    if state == "ABSENT":
        if any(
            status.get(field) is not None
            for field in (
                "provider_request_id",
                "provider_receipt_sha256",
                "provider_response_sha256",
                "evidence_sha256",
                "outcome_at_tick",
                "object_id",
                "object_receipt_sha256",
                "retention_until_tick",
                "legal_hold",
            )
        ):
            raise CompletionImmutableAnchorError(
                "immutable_anchor_absent_state_not_empty", expected_effect_id
            )
    else:
        if (
            not _is_sha256(status.get("object_id"))
            or not _is_sha256(status.get("object_receipt_sha256"))
            or type(status.get("retention_until_tick")) is not int
            or status["retention_until_tick"] <= evaluation_tick
            or status.get("legal_hold") is not True
        ):
            raise CompletionImmutableAnchorError(
                "immutable_anchor_retention_not_current", expected_effect_id
            )
    if status.get("physical_worm_established") is not False:
        raise CompletionImmutableAnchorError(
            "immutable_anchor_physical_claim_expansion",
            str(status.get("physical_worm_established")),
        )
    if status.get("authority_granted") is not False:
        raise CompletionImmutableAnchorError(
            "immutable_anchor_authority_expansion", str(status.get("authority_granted"))
        )
    checkpoint = None
    if checkpoint_ledger is not None:
        checkpoint = checkpoint_ledger.observe_status(
            status, observed_at_tick=evaluation_tick
        )["checkpoint"]
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {
        "status": "PASS",
        "immutable_anchor_status": status,
        "checkpoint": checkpoint,
        "external_effect_permitted": state in {"ABSENT", "NO_EFFECT"},
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "COMPLETION_IMMUTABLE_ANCHOR_BLOCKING_STATES",
    "COMPLETION_IMMUTABLE_ANCHOR_EVENT_CONTRACT_ID",
    "COMPLETION_IMMUTABLE_ANCHOR_HEAD_CONTRACT_ID",
    "COMPLETION_IMMUTABLE_ANCHOR_STATES",
    "COMPLETION_IMMUTABLE_ANCHOR_STATUS_CONTRACT_ID",
    "COMPLETION_IMMUTABLE_OBJECT_RECEIPT_CONTRACT_ID",
    "CompletionImmutableAnchorError",
    "FilesystemImmutableCompletionAnchor",
    "SQLiteImmutableAnchorCheckpointLedger",
    "verify_completion_immutable_anchor_event",
    "verify_completion_immutable_anchor_event_chain",
    "verify_completion_immutable_anchor_head",
    "verify_completion_immutable_anchor_status",
    "verify_completion_immutable_object_receipt",
]
