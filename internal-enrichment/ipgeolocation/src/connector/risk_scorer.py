"""
IPGeolocation.io OpenCTI Connector — Risk Scorer
==================================================

Turns the IPGeolocation.io security data into:

* **unified_score** (0-100): the IPGeolocation.io ``threat_score`` as is, used as the
  OpenCTI ``x_opencti_score``. It already accounts for the security flags, so they are
  not weighted again.
* **risk_level**: Low (0-20), Medium (21-50), High (51-80) or Critical (81-100)
* **contributing_factors**: the security flags that are set, in words
* **explanation**: a human-readable paragraph for analysts
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ipgeolocation_client.models import IPIntelligence, SecurityData

# ---------------------------------------------------------------------------
# Risk level enum (simple str)
# ---------------------------------------------------------------------------

RISK_LOW = "Low"
RISK_MEDIUM = "Medium"
RISK_HIGH = "High"
RISK_CRITICAL = "Critical"


@dataclass
class RiskAssessment:
    """Outcome of the risk scoring process."""

    unified_score: int = 0
    risk_level: str = RISK_LOW
    explanation: str = ""
    contributing_factors: list[str] = field(default_factory=list)
    opencti_score: int = 0  # identical to unified_score, for convenience
    assessment_confidence: int = 0  # our confidence in the assessment (0-100)


class RiskScorer:
    """Stateless scorer: call ``assess`` with an ``IPIntelligence``."""

    # Security flags in the order they are reported, with their description.
    _LABELS = {
        "is_tor": "TOR exit node",
        "is_known_attacker": "known attacker infrastructure",
        "is_spam": "spam source",
        "is_bot": "bot activity detected",
        "is_residential_proxy": "residential proxy",
        "is_vpn": "VPN endpoint",
        "is_proxy": "proxy server",
        "is_relay": "relay node",
        "is_anonymous": "anonymous traffic",
        "is_cloud_provider": "cloud/hosting provider",
    }

    def assess(self, intel: IPIntelligence) -> RiskAssessment:
        sec = intel.security
        factors: list[str] = []
        already_anon = False

        for flag in self._LABELS:
            if not getattr(sec, flag, False):
                continue
            # "anonymous" adds nothing when a VPN, proxy, Tor or relay flag explains it
            if flag == "is_anonymous" and already_anon:
                continue
            if flag in (
                "is_vpn",
                "is_proxy",
                "is_tor",
                "is_relay",
                "is_residential_proxy",
            ):
                already_anon = True
            label = self._LABELS[flag]
            # Add provider detail where available
            if flag == "is_vpn" and sec.vpn_provider_names:
                label += f" ({', '.join(sec.vpn_provider_names)})"
            elif flag == "is_proxy" and sec.proxy_provider_names:
                label += f" ({', '.join(sec.proxy_provider_names)})"
            elif flag == "is_cloud_provider" and sec.cloud_provider_name:
                label += f" ({sec.cloud_provider_name})"
            factors.append(label)

        score = max(0, min(int(sec.threat_score or 0), 100))

        level = self._level(score)
        confidence = self._derive_confidence(sec)
        explanation = self._build_explanation(
            intel.ip, score, level, factors, sec, confidence
        )

        return RiskAssessment(
            unified_score=score,
            risk_level=level,
            explanation=explanation,
            contributing_factors=factors,
            opencti_score=score,
            assessment_confidence=confidence,
        )

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    @staticmethod
    def _level(score: int) -> str:
        if score <= 20:
            return RISK_LOW
        if score <= 50:
            return RISK_MEDIUM
        if score <= 80:
            return RISK_HIGH
        return RISK_CRITICAL

    @staticmethod
    def _derive_confidence(sec: SecurityData) -> int:
        """Derive our confidence in the enrichment quality.

        Uses API-provided confidence scores where available, otherwise
        defaults to 70 (reasonable for a commercial TI feed).
        """
        scores: list[int] = []
        if sec.vpn_confidence_score:
            scores.append(sec.vpn_confidence_score)
        if sec.proxy_confidence_score:
            scores.append(sec.proxy_confidence_score)
        if sec.threat_score:
            scores.append(min(sec.threat_score + 20, 100))
        if scores:
            return min(int(sum(scores) / len(scores)), 100)
        return 70

    @staticmethod
    def _build_explanation(
        ip: str,
        score: int,
        level: str,
        factors: list[str],
        sec: SecurityData,
        confidence: int,
    ) -> str:
        if not factors:
            return (
                f"**{ip}** has an IPGeolocation.io threat score of {score}/100 "
                f"(**{level}** risk) with no specific threat flags raised."
            )
        parts = [
            f"**{ip}** has an IPGeolocation.io threat score of {score}/100 "
            f"(**{level}** risk), with these signals: {', '.join(factors)}.",
        ]
        parts.append(f"Assessment confidence: {confidence}/100.")
        return " ".join(parts)
