"""Tests for the risk scoring algorithm."""

from src.models import IPIntelligence, SecurityData
from src.risk_scorer import (
    RISK_CRITICAL,
    RISK_LOW,
    RISK_MEDIUM,
)


class TestRiskScorer:

    def test_clean_ip_is_low_risk(self, clean_intel, scorer):
        result = scorer.assess(clean_intel)
        assert result.risk_level == RISK_LOW
        assert result.unified_score <= 20

    def test_high_threat_ip_is_critical(self, high_risk_intel, scorer):
        """IP with threat_score=80 + VPN + proxy + known attacker."""
        result = scorer.assess(high_risk_intel)
        assert result.risk_level == RISK_CRITICAL
        assert result.unified_score >= 81

    def test_score_capped_at_100(self, scorer):
        """Even with all flags, score should not exceed 100."""
        intel = IPIntelligence(ip="10.0.0.1")
        intel.security = SecurityData(
            threat_score=90,
            is_tor=True,
            is_vpn=True,
            is_proxy=True,
            is_known_attacker=True,
            is_spam=True,
            is_bot=True,
            is_cloud_provider=True,
            is_anonymous=True,
            is_residential_proxy=True,
            is_relay=True,
        )
        result = scorer.assess(intel)
        assert result.unified_score == 100

    def test_explanation_contains_factors(self, high_risk_intel, scorer):
        result = scorer.assess(high_risk_intel)
        assert "known attacker" in result.explanation
        assert (
            "VPN" in result.explanation.lower() or "vpn" in result.explanation.lower()
        )

    def test_contributing_factors_list(self, high_risk_intel, scorer):
        result = scorer.assess(high_risk_intel)
        assert len(result.contributing_factors) > 0
        factor_text = " ".join(result.contributing_factors).lower()
        assert "vpn" in factor_text or "known attacker" in factor_text

    def test_confidence_derived_from_api(self, high_risk_intel, scorer):
        result = scorer.assess(high_risk_intel)
        # VPN confidence=80, proxy confidence=80, threat+20=100
        # average ~ 86
        assert 70 <= result.confidence <= 100

    def test_no_threat_flags_defaults(self, scorer):
        intel = IPIntelligence(ip="192.168.1.1")
        intel.security = SecurityData(threat_score=10)
        result = scorer.assess(intel)
        assert result.risk_level == RISK_LOW
        assert result.confidence == 30  # min(10+20, 100) = 30

    def test_medium_range(self, scorer):
        intel = IPIntelligence(ip="10.0.0.2")
        intel.security = SecurityData(threat_score=30, is_vpn=True)
        result = scorer.assess(intel)
        assert result.risk_level == RISK_MEDIUM

    def test_opinion_text_mapping(self, scorer, high_risk_intel, clean_intel):
        critical = scorer.assess(high_risk_intel)
        low = scorer.assess(clean_intel)
        assert critical.opinion_text == "strongly-agree"
        assert low.opinion_text == "strongly-disagree"
