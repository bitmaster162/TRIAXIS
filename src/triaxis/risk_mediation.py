"""Risk Authority R1 complete-mediation design boundary.

This module is deliberately side-effect free. It does not replace TRIAXIS
Cedar/PEP authorization. Instead it places a mandatory trusted risk-fact
observation in front of an injected authorization callable and verifies that
the resulting authorization token is bound to the authoritative effective
risk before returning it.

Repository-wide complete mediation is achieved only when effect-capable
runtime entry points are wired to this boundary and direct authorization
bypass is removed under a separate reviewed integration gate.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .integrity import (
    canonical_sha256,
    materialize_json,
    seal_mapping,
    verify_sealed_mapping,
)
from .risk_authority import (
    RiskAssessment,
    RiskAuthorityError,
    RiskDowngradeError,
    RiskFacts,
    assess_risk,
)

RISK_MEDIATION_RECEIPT_CONTRACT_ID = "TRIAXIS_RISK_MEDIATION_RECEIPT_v1"


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


class RiskMediationError(RuntimeError):
    """Fail-closed mediation error raised before effect authorization is usable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RiskFactObservation:
    """Risk facts returned by one exact trusted adapter generation."""

    adapter_id: str
    adapter_version: int
    risk_subject_sha256: str
    facts: RiskFacts

    def __post_init__(self) -> None:
        if not isinstance(self.adapter_id, str) or not self.adapter_id:
            raise ValueError("adapter_id must be non-empty")
        if type(self.adapter_version) is not int or self.adapter_version < 1:
            raise ValueError("adapter_version must be integer >= 1")
        if not _is_sha256(self.risk_subject_sha256):
            raise ValueError("risk_subject_sha256 must be lowercase SHA-256")
        if not isinstance(self.facts, RiskFacts):
            raise TypeError("facts must be RiskFacts")


class RiskFactsAdapter(Protocol):
    """Bounded adapter that deterministically observes consequence facts."""

    adapter_id: str
    adapter_version: int

    def observe_risk_facts(
        self,
        action_value: Mapping[str, Any],
    ) -> RiskFactObservation: ...


class TrustedRiskFactsAdapterRegistry:
    """Immutable in-process trust binding for exact adapter objects and versions."""

    def __init__(self, bindings: Mapping[str, tuple[int, object]]) -> None:
        if not isinstance(bindings, Mapping):
            raise TypeError("bindings must be a mapping")
        normalized: dict[str, tuple[int, object]] = {}
        for adapter_id, binding in bindings.items():
            if not isinstance(adapter_id, str) or not adapter_id:
                raise ValueError("adapter id must be non-empty")
            if (
                not isinstance(binding, tuple)
                or len(binding) != 2
                or type(binding[0]) is not int
                or binding[0] < 1
                or binding[1] is None
            ):
                raise ValueError("binding must be (version>=1, adapter_instance)")
            normalized[adapter_id] = binding
        self._bindings = normalized

    def is_trusted(
        self,
        adapter_id: str,
        adapter_version: int,
        adapter: object,
    ) -> bool:
        binding = self._bindings.get(adapter_id)
        return (
            binding is not None
            and binding[0] == adapter_version
            and binding[1] is adapter
        )


def risk_subject_sha256(action_value: Mapping[str, Any]) -> str:
    """Digest exact effect semantics independently of caller risk metadata.

    The subject deliberately excludes ``risk_class`` so the adapter observes
    consequence facts before caller risk claims are evaluated. It includes the
    authenticated state-witness digest because reversibility or criticality may
    depend on the state against which the action was authorized.
    """

    try:
        action = materialize_json(action_value)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise RiskMediationError(
            "RISK_ACTION_MATERIALIZATION_FAILED",
            type(exc).__name__,
        ) from exc
    if not isinstance(action, dict):
        raise RiskMediationError("RISK_ACTION_INVALID", "action mapping required")

    for field in (
        "subject_id",
        "object_id",
        "capability",
        "tool_id",
        "execution_target",
    ):
        if not isinstance(action.get(field), str) or not action.get(field):
            raise RiskMediationError(
                "RISK_ACTION_INVALID",
                f"{field} must be non-empty",
            )
    if not _is_sha256(action.get("payload_sha256")):
        raise RiskMediationError(
            "RISK_ACTION_INVALID",
            "payload_sha256 must be lowercase SHA-256",
        )

    state_witness = action.get("state_witness")
    state_witness_sha256 = (
        state_witness.get("witness_sha256")
        if isinstance(state_witness, Mapping)
        else None
    )
    if not _is_sha256(state_witness_sha256):
        raise RiskMediationError(
            "RISK_ACTION_INVALID",
            "state witness digest required",
        )

    material = {
        "subject_id": action["subject_id"],
        "object_id": action["object_id"],
        "capability": action["capability"],
        "tool_id": action["tool_id"],
        "execution_target": action["execution_target"],
        "payload_sha256": action["payload_sha256"],
        "state_witness_sha256": state_witness_sha256,
    }
    return canonical_sha256(material)


@dataclass(frozen=True, slots=True)
class RiskMediatedAuthorizationResult:
    authorization: dict[str, Any]
    risk_mediation_receipt: dict[str, Any]
    risk_assessment: RiskAssessment


class RiskMediatedAuthorizationBoundary:
    """Mandatory risk mediation in front of the existing authorization stack.

    The injected ``authorizer`` remains the only PDP/authorization implementation.
    This boundary never invokes providers or effects.
    """

    def __init__(
        self,
        *,
        authorizer: Callable[..., Mapping[str, Any]],
        risk_adapter: RiskFactsAdapter,
        trusted_registry: TrustedRiskFactsAdapterRegistry,
        adapter_id: str,
        adapter_version: int,
    ) -> None:
        if not callable(authorizer):
            raise TypeError("authorizer must be callable")
        if not isinstance(trusted_registry, TrustedRiskFactsAdapterRegistry):
            raise TypeError("trusted_registry must be TrustedRiskFactsAdapterRegistry")
        if not isinstance(adapter_id, str) or not adapter_id:
            raise ValueError("adapter_id must be non-empty")
        if type(adapter_version) is not int or adapter_version < 1:
            raise ValueError("adapter_version must be integer >= 1")
        if getattr(risk_adapter, "adapter_id", None) != adapter_id:
            raise ValueError("risk adapter id does not match configured adapter_id")
        if getattr(risk_adapter, "adapter_version", None) != adapter_version:
            raise ValueError("risk adapter version does not match configured adapter_version")

        self._authorizer = authorizer
        self._risk_adapter = risk_adapter
        self._trusted_registry = trusted_registry
        self._adapter_id = adapter_id
        self._adapter_version = adapter_version

    def authorize(
        self,
        action_value: Mapping[str, Any],
        *authorizer_args: Any,
        **authorizer_kwargs: Any,
    ) -> RiskMediatedAuthorizationResult:
        try:
            action = materialize_json(action_value)
        except (TypeError, ValueError, RuntimeError) as exc:
            raise RiskMediationError(
                "RISK_ACTION_MATERIALIZATION_FAILED",
                type(exc).__name__,
            ) from exc
        if not isinstance(action, dict):
            raise RiskMediationError("RISK_ACTION_INVALID", "action mapping required")

        if not self._trusted_registry.is_trusted(
            self._adapter_id,
            self._adapter_version,
            self._risk_adapter,
        ):
            raise RiskMediationError(
                "UNTRUSTED_RISK_FACT_ADAPTER",
                "adapter id/version/instance is not trusted",
            )

        subject_sha256 = risk_subject_sha256(action)
        adapter_input = materialize_json(action)
        try:
            observation = self._risk_adapter.observe_risk_facts(adapter_input)
        except Exception as exc:
            raise RiskMediationError(
                "RISK_FACT_ADAPTER_FAILURE",
                type(exc).__name__,
            ) from exc

        if not isinstance(observation, RiskFactObservation):
            raise RiskMediationError(
                "INVALID_RISK_FACT_OBSERVATION",
                "adapter must return RiskFactObservation",
            )
        if (
            observation.adapter_id != self._adapter_id
            or observation.adapter_version != self._adapter_version
        ):
            raise RiskMediationError(
                "RISK_FACT_PROVENANCE_MISMATCH",
                "observation adapter identity/version mismatch",
            )
        if observation.risk_subject_sha256 != subject_sha256:
            raise RiskMediationError(
                "RISK_FACT_SUBJECT_MISMATCH",
                "risk facts are not bound to the current effect subject",
            )

        claimed_risk = action.get("risk_class")
        if not isinstance(claimed_risk, str) or not claimed_risk:
            raise RiskMediationError(
                "RISK_CLASS_REQUIRED",
                "action risk_class required before authorization",
            )
        try:
            assessment = assess_risk(
                observation.facts,
                claimed_risk=claimed_risk,
            )
        except RiskDowngradeError as exc:
            raise RiskMediationError("RISK_DOWNGRADE_BLOCKED", str(exc)) from exc
        except RiskAuthorityError as exc:
            raise RiskMediationError("RISK_ASSESSMENT_FAILED", str(exc)) from exc

        authorization_action = materialize_json(action)
        authorization_raw = self._authorizer(
            authorization_action,
            *authorizer_args,
            **authorizer_kwargs,
        )
        try:
            authorization = materialize_json(authorization_raw)
        except (TypeError, ValueError, RuntimeError) as exc:
            raise RiskMediationError(
                "AUTHORIZATION_RESULT_INVALID",
                type(exc).__name__,
            ) from exc
        if not isinstance(authorization, dict):
            raise RiskMediationError(
                "AUTHORIZATION_RESULT_INVALID",
                "authorization mapping required",
            )
        token_sha256 = authorization.get("token_sha256")
        if not _is_sha256(token_sha256):
            raise RiskMediationError(
                "AUTHORIZATION_TOKEN_DIGEST_MISSING",
                "sealed authorization token digest required",
            )
        if not verify_sealed_mapping(authorization, "token_sha256"):
            raise RiskMediationError(
                "AUTHORIZATION_TOKEN_DIGEST_INVALID",
                "authorization token canonical digest mismatch",
            )

        token_subject = {
            "subject_id": authorization.get("subject_id"),
            "object_id": authorization.get("object_id"),
            "capability": authorization.get("capability"),
            "tool_id": authorization.get("tool_id"),
            "execution_target": authorization.get("execution_target"),
            "payload_sha256": authorization.get("payload_sha256"),
            "state_witness_sha256": authorization.get("state_witness_sha256"),
        }
        if canonical_sha256(token_subject) != subject_sha256:
            raise RiskMediationError(
                "AUTHORIZATION_EFFECT_BINDING_MISMATCH",
                "authorization token is not bound to the mediated effect subject",
            )
        if authorization.get("risk_class") != assessment.effective_risk:
            raise RiskMediationError(
                "AUTHORIZATION_RISK_BINDING_MISMATCH",
                "authorization token risk differs from mediated effective risk",
            )
        receipt = seal_mapping(
            {
                "contract_id": RISK_MEDIATION_RECEIPT_CONTRACT_ID,
                "adapter_id": self._adapter_id,
                "adapter_version": self._adapter_version,
                "risk_subject_sha256": subject_sha256,
                "effect_scope": observation.facts.effect_scope.value,
                "reversibility": observation.facts.reversibility.value,
                "critical_domains": list(assessment.critical_domains),
                "derived_risk": assessment.derived_risk,
                "claimed_risk": assessment.claimed_risk,
                "effective_risk": assessment.effective_risk,
                "authorization_token_sha256": token_sha256,
                "receipt_sha256": "",
            },
            "receipt_sha256",
        )
        return RiskMediatedAuthorizationResult(
            authorization=authorization,
            risk_mediation_receipt=receipt,
            risk_assessment=assessment,
        )


__all__ = [
    "RISK_MEDIATION_RECEIPT_CONTRACT_ID",
    "RiskFactObservation",
    "RiskFactsAdapter",
    "RiskMediatedAuthorizationBoundary",
    "RiskMediatedAuthorizationResult",
    "RiskMediationError",
    "TrustedRiskFactsAdapterRegistry",
    "risk_subject_sha256",
]
