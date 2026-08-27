import pytest

from triaxis.risk_authority import (
    CriticalDomain,
    EffectScope,
    InvalidRiskFacts,
    Reversibility,
    RiskDowngradeError,
    RiskFacts,
    assess_risk,
    derive_risk,
)


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        (RiskFacts(EffectScope.NONE, Reversibility.NOT_APPLICABLE), "R0"),
        (RiskFacts(EffectScope.LOCAL, Reversibility.REVERSIBLE), "R1"),
        (RiskFacts(EffectScope.LOCAL, Reversibility.IRREVERSIBLE), "R2"),
        (RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE), "R2"),
        (RiskFacts(EffectScope.EXTERNAL, Reversibility.IRREVERSIBLE), "R3"),
    ],
)
def test_base_consequence_matrix_is_deterministic(facts, expected):
    assert derive_risk(facts) == expected
    assert derive_risk(facts) == expected


@pytest.mark.parametrize("domain", list(CriticalDomain))
def test_critical_domains_are_always_r4(domain):
    facts = RiskFacts(
        EffectScope.EXTERNAL,
        Reversibility.REVERSIBLE,
        frozenset({domain}),
    )
    assert derive_risk(facts) == "R4"


def test_multiple_critical_domains_are_order_independent():
    left = RiskFacts(
        EffectScope.EXTERNAL,
        Reversibility.IRREVERSIBLE,
        frozenset({CriticalDomain.TRADING, CriticalDomain.CAPITAL}),
    )
    right = RiskFacts(
        EffectScope.EXTERNAL,
        Reversibility.IRREVERSIBLE,
        frozenset({CriticalDomain.CAPITAL, CriticalDomain.TRADING}),
    )
    assert assess_risk(left) == assess_risk(right)
    assert assess_risk(left).effective_risk == "R4"


def test_caller_cannot_downgrade_derived_risk():
    facts = RiskFacts(EffectScope.EXTERNAL, Reversibility.IRREVERSIBLE)
    with pytest.raises(RiskDowngradeError):
        assess_risk(facts, claimed_risk="R0")


def test_caller_may_overclassify():
    facts = RiskFacts(EffectScope.LOCAL, Reversibility.REVERSIBLE)
    result = assess_risk(facts, claimed_risk="R3")
    assert result.derived_risk == "R1"
    assert result.effective_risk == "R3"


def test_equal_claim_is_accepted():
    facts = RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE)
    result = assess_risk(facts, claimed_risk="R2")
    assert result.effective_risk == "R2"


@pytest.mark.parametrize("claim", ["", "R5", "r3", "unknown"])
def test_unknown_claim_fails_closed(claim):
    facts = RiskFacts(EffectScope.NONE, Reversibility.NOT_APPLICABLE)
    with pytest.raises(InvalidRiskFacts):
        assess_risk(facts, claimed_risk=claim)


def test_none_scope_cannot_claim_reversibility():
    with pytest.raises(InvalidRiskFacts):
        RiskFacts(EffectScope.NONE, Reversibility.REVERSIBLE)


def test_effectful_scope_requires_reversibility():
    with pytest.raises(InvalidRiskFacts):
        RiskFacts(EffectScope.EXTERNAL, Reversibility.NOT_APPLICABLE)


def test_no_effect_cannot_carry_critical_domain():
    with pytest.raises(InvalidRiskFacts):
        RiskFacts(
            EffectScope.NONE,
            Reversibility.NOT_APPLICABLE,
            frozenset({CriticalDomain.TRADING}),
        )


def test_unknown_typed_fact_fails_closed():
    with pytest.raises(InvalidRiskFacts):
        RiskFacts("REMOTE", Reversibility.REVERSIBLE)  # type: ignore[arg-type]


def test_non_riskfacts_input_fails_closed():
    with pytest.raises(InvalidRiskFacts):
        derive_risk({"effect_scope": "NONE"})  # type: ignore[arg-type]


def test_assessment_exposes_sorted_critical_domains_only_as_evidence():
    facts = RiskFacts(
        EffectScope.EXTERNAL,
        Reversibility.REVERSIBLE,
        frozenset({CriticalDomain.TRADING, CriticalDomain.CAPITAL}),
    )
    result = assess_risk(facts)
    assert result.critical_domains == ("CAPITAL", "TRADING")
    assert result.effective_risk == "R4"
