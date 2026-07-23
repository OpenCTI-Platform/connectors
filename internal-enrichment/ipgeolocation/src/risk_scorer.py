"""
IPGeolocation.io OpenCTI Connector — Risk Scorer
==================================================

Normalises the heterogeneous risk signals from IPGeolocation.io into:

* **unified_score** (0–100): single number for OpenCTI ``x_opencti_score``
* **risk_level**: Low / Medium / High / Critical
* **explanation**: human-readable analyst paragraph

Algorithm
---------
1. Start with ``threat_score`` from the Security API (0-100).
2. Apply additive modifiers for binary risk flags:
   - TOR exit:           +15
   - Known attacker:     +15
   - Spam source:        +10
   - Bot:                +10
   - VPN (non-residential): +5
   - Proxy (non-residential): +5
   - Residential proxy:  +8  (harder to detect = higher risk)
   - Relay:              +3
   - Anonymous:          +3  (only if not already captured above)
   - Cloud provider:     +2  (infrastructure, not inherently malicious)
3. Cap at 100.
4. Map to risk level:
   - 0-20:  Low
   - 21-50: Medium
   - 51-80: High
   - 81+:   Critical
5. Build an English explanation listing every contributing factor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import IPIntelligence, SecurityData

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
    confidence: int = 0  # our confidence in the assessment (0-100)

    @property
    def opinion_text(self) -> str:
        mapping = {
            RISK_LOW: "strongly-disagree",
            RISK_MEDIUM: "neutral",
            RISK_HIGH: "agree",
            RISK_CRITICAL: "strongly-agree",
        }
        return mapping.get(self.risk_level, "neutral")


class RiskScorer:
    """Stateless scorer: call ``assess`` with an ``IPIntelligence``."""

    # Additive weights
    _WEIGHTS = {
        "is_tor": 15,
        "is_known_attacker": 15,
        "is_spam": 10,
        "is_bot": 10,
        "is_residential_proxy": 8,
        "is_vpn": 5,
        "is_proxy": 5,
        "is_relay": 3,
        "is_anonymous": 3,
        "is_cloud_provider": 2,
    }

    # Human labels for each flag
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
        base = sec.threat_score
        factors: list[str] = []
        bonus = 0
        already_anon = False

        for flag, weight in self._WEIGHTS.items():
            val = getattr(sec, flag, False)
            if not val:
                continue
            # Avoid double-counting anonymous if VPN/proxy/TOR already on
            if flag == "is_anonymous":
                if already_anon:
                    continue
            if flag in (
                "is_vpn",
                "is_proxy",
                "is_tor",
                "is_relay",
                "is_residential_proxy",
            ):
                already_anon = True
            bonus += weight
            label = self._LABELS[flag]
            # Add provider detail where available
            if flag == "is_vpn" and sec.vpn_provider_names:
                label += f" ({', '.join(sec.vpn_provider_names)})"
            elif flag == "is_proxy" and sec.proxy_provider_names:
                label += f" ({', '.join(sec.proxy_provider_names)})"
            elif flag == "is_cloud_provider" and sec.cloud_provider_name:
                label += f" ({sec.cloud_provider_name})"
            factors.append(label)

        raw = base + bonus
        score = min(raw, 100)

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
            confidence=confidence,
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
                f"**{ip}** received a threat score of {sec.threat_score}/100 "
                f"from IPGeolocation.io with no specific threat flags raised. "
                f"Unified risk: **{level}** ({score}/100)."
            )
        factor_str = ", ".join(factors)
        parts = [
            f"**{ip}** is assessed as **{level} Risk** "
            f"(unified score {score}/100) based on the following signals: "
            f"{factor_str}.",
        ]
        if sec.threat_score:
            parts.append(
                f"The upstream threat score from IPGeolocation.io is "
                f"{sec.threat_score}/100."
            )
        parts.append(f"Assessment confidence: {confidence}/100.")
        return " ".join(parts)
