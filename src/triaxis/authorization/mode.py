"""TRIAXIS v4.0 Authorization Mode Specification (PI-001)."""

from __future__ import annotations

from enum import Enum


class AuthorizationMode(str, Enum):
    LEGACY = "legacy"
    CEDAR_REFERENCE = "cedar_reference"

    @classmethod
    def parse(cls, value: str | AuthorizationMode) -> AuthorizationMode:
        if isinstance(value, AuthorizationMode):
            return value
        if isinstance(value, str):
            val_norm = value.strip().lower()
            for member in cls:
                if member.value == val_norm:
                    return member
        raise ValueError(f"Invalid or unsupported AuthorizationMode: {value!r}. Allowed: 'legacy', 'cedar_reference'")
