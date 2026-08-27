"""Deterministic TRIAXIS risk authority.

This module classifies trusted, typed effect facts into the existing TRIAXIS
R0-R4 risk scale. It is intentionally inert: it performs no authorization,
policy evaluation, provider invocation, deployment, trading, capital action,
or external I/O.

Risk authority is a consequence classifier, not a PDP. Cedar/PEP remains the
authorization authority; callers may over-classify an action but may not
silently downgrade below the risk derived here.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RiskAuthorityError(ValueError):
    """Base class for fail-closed risk-authority errors."""


class InvalidRiskFacts(RiskAuthorityError):
    """Raised when effect facts are contradictory or incomplete."""


class RiskDowngradeError(RiskAuthorityError):
    """Raised when a caller claims a lower risk class than derived."""


class EffectScope(str, Enum):
    NONE = "NONE"
    LOCAL = "LOCAL"
    EXTERNAL = "EXTERNAL"


class Reversibility(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REVERSIBLE = "REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"


class CriticalDomain(str, Enum):
    CAPITAL = "CAPITAL"
    TRADING = "TRADING"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    IDENTITY_ADMIN = "IDENTITY_ADMIN"
    POLICY_ADMIN = "POLICY_ADMIN"


RISK_CLASSES = ("R0", "R1", "R2", "R3", "R4")
_RISK_RANK = {risk: index for index, risk in enumerate(RISK_CLASSES)}


@dataclass(frozen=True, slots=True)
class RiskFacts:
    """Trusted consequence facts supplied by a bounded action/effect adapter.

    The classifier deliberately does not infer risk from free-form action names,
    prompts, capability strings, or model output.
    """

    effect_scope: EffectScope
    reversibility: Reversibility
    critical_domains: frozenset[CriticalDomain] = frozenset()

    def __post_init__(self) -> None:
        try:
            scope = EffectScope(self.effect_scope)
            reversibility = Reversibility(self.reversibility)
            domains = frozenset(CriticalDomain(item) for item in self.critical_domains)
        except (TypeError, ValueError) as exc:
            raise InvalidRiskFacts(f"unknown risk fact: {exc}") from exc

        object.__setattr__(self, "effect_scope", scope)
        object.__setattr__(self, "reversibility", reversibility)
        object.__setattr__(self, "critical_domains", domains)

        if scope is EffectScope.NONE and reversibility is not Reversibility.NOT_APPLICABLE:
            raise InvalidRiskFacts("NONE scope requires NOT_APPLICABLE reversibility")
        if scope is not EffectScope.NONE and reversibility is Reversibility.NOT_APPLICABLE:
            raise InvalidRiskFacts("effectful scope requires REVERSIBLE or IRREVERSIBLE")
        if scope is EffectScope.NONE and domains:
            raise InvalidRiskFacts("critical domains require an effectful scope")


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    derived_risk: str
    claimed_risk: str | None
    effective_risk: str
    critical_domains: tuple[str, ...]


def derive_risk(facts: RiskFacts) -> str:
    """Derive the minimum TRIAXIS R0-R4 risk class from trusted effect facts."""

    if not isinstance(facts, RiskFacts):
        raise InvalidRiskFacts("facts must be RiskFacts")

    if facts.critical_domains:
        return "R4"
    if facts.effect_scope is EffectScope.NONE:
        return "R0"
    if facts.effect_scope is EffectScope.LOCAL:
        if facts.reversibility is Reversibility.REVERSIBLE:
            return "R1"
        return "R2"
    if facts.effect_scope is EffectScope.EXTERNAL:
        if facts.reversibility is Reversibility.REVERSIBLE:
            return "R2"
        return "R3"
    raise InvalidRiskFacts("unhandled effect facts")


def assess_risk(facts: RiskFacts, *, claimed_risk: str | None = None) -> RiskAssessment:
    """Return effective risk, rejecting any caller-requested downgrade.

    A higher caller claim is allowed and becomes the effective risk. A lower
    claim raises RiskDowngradeError, so downstream authorization can fail
    closed instead of accepting caller-controlled risk reduction.
    """

    derived = derive_risk(facts)
    if claimed_risk is None:
        effective = derived
    else:
        if claimed_risk not in _RISK_RANK:
            raise InvalidRiskFacts(f"unknown claimed risk class: {claimed_risk!r}")
        if _RISK_RANK[claimed_risk] < _RISK_RANK[derived]:
            raise RiskDowngradeError(
                f"claimed risk {claimed_risk} is below derived minimum {derived}"
            )
        effective = claimed_risk

    return RiskAssessment(
        derived_risk=derived,
        claimed_risk=claimed_risk,
        effective_risk=effective,
        critical_domains=tuple(sorted(domain.value for domain in facts.critical_domains)),
    )


__all__ = [
    "CriticalDomain",
    "EffectScope",
    "InvalidRiskFacts",
    "RISK_CLASSES",
    "Reversibility",
    "RiskAssessment",
    "RiskAuthorityError",
    "RiskDowngradeError",
    "RiskFacts",
    "assess_risk",
    "derive_risk",
]
