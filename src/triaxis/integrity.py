"""Canonical integrity helpers used by the recovered TRIAXIS authority layer."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from typing import Any


def materialize_json(value: Any) -> Any:
    """Return a detached JSON-compatible value or raise ``TypeError``.

    Mapping inputs are read through the mapping protocol exactly once at each
    level.  The function deliberately rejects floats that JSON cannot represent
    canonically and does not coerce keys or primitive values.
    """

    if isinstance(value, Mapping):
        keys = list(iter(value))
        result: dict[str, Any] = {}
        for key in keys:
            if not isinstance(key, str):
                raise TypeError("canonical mappings require string keys")
            result[key] = materialize_json(value[key])
        if len(result) != len(value):
            raise ValueError("mapping length changed during materialization")
        return result
    if isinstance(value, list):
        return [materialize_json(item) for item in value]
    if isinstance(value, tuple):
        return [materialize_json(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return deepcopy(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite float is not canonical JSON")
        return value
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        materialize_json(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def seal_mapping(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    result = materialize_json(value)
    if not isinstance(result, dict):  # defensive; Mapping always yields dict
        raise TypeError("seal_mapping requires a mapping")
    result[digest_field] = ""
    result[digest_field] = canonical_sha256(result)
    return result


def verify_sealed_mapping(value: Mapping[str, Any], digest_field: str) -> bool:
    try:
        result = materialize_json(value)
    except (TypeError, ValueError, RuntimeError):
        return False
    if not isinstance(result, dict):
        return False
    observed = result.get(digest_field)
    if not isinstance(observed, str) or len(observed) != 64:
        return False
    result[digest_field] = ""
    return canonical_sha256(result) == observed


__all__ = [
    "canonical_json_bytes",
    "canonical_sha256",
    "materialize_json",
    "seal_mapping",
    "verify_sealed_mapping",
]
