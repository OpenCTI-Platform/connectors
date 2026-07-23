"""
IPGeolocation.io OpenCTI Connector — Markdown Generator
=========================================================

Produces rich, analyst-readable markdown notes that appear in the
OpenCTI UI when an observable is enriched.  Includes:

1. Executive Summary (one-paragraph narrative)
2. IP Summary table
3. Security Narrative (not just booleans)
4. Infrastructure Profile
5. Network Context
6. Abuse Workflow
7. Geo Intelligence
8. Timeline (if timestamps exist)
"""

from __future__ import annotations

from .models import IPIntelligence
from .risk_scorer import RiskAssessment


class MarkdownGenerator:
    """Stateless generator: call ``generate`` with intel + risk."""

    def generate(self, intel: IPIntelligence, risk: RiskAssessment) -> str:
        sections: list[str] = []
        sections.append(self._executive_summary(intel, risk))
        sections.append(self._summary_table(intel, risk))
        sections.append(self._security_narrative(intel, risk))
        sections.append(self._infrastructure_profile(intel))
        sections.append(self._network_context(intel))
        sections.append(self._geo_intelligence(intel))
        sections.append(self._abuse_workflow(intel))
        sections.append(self._timeline(intel))
        sections.append(self._confidence_note(risk))
        sections.append(self._footer())
        return "\n\n".join(s for s in sections if s)

    # ------------------------------------------------------------------ #
    # 1. Executive Summary
    # ------------------------------------------------------------------ #

    def _executive_summary(self, intel: IPIntelligence, risk: RiskAssessment) -> str:
        loc = intel.location
        sec = intel.security
        parts: list[str] = ["## Executive Summary", ""]

        geo = (
            f"{loc.city}, {loc.state_prov}, {loc.country_name}"
            if loc.city
            else (loc.country_name or "Unknown location")
        )

        org = intel.asn.organization or intel.company.name or "an unknown organization"
        asn = intel.asn.as_number or "N/A"

        narrative = (
            f"`{intel.ip}` is geolocated in **{geo}** and belongs to "
            f"**{org}** ({asn})."
        )

        # Anonymization details
        anon: list[str] = []
        if sec.is_vpn:
            providers = (
                ", ".join(sec.vpn_provider_names)
                if sec.vpn_provider_names
                else "unknown provider"
            )
            anon.append(f"a VPN ({providers})")
        if sec.is_proxy:
            anon.append("a proxy server")
        if sec.is_residential_proxy:
            anon.append("a residential proxy")
        if sec.is_tor:
            anon.append("a TOR exit node")
        if sec.is_relay:
            anon.append("a relay node")

        if anon:
            narrative += f" The address is identified as {', '.join(anon)}."

        threat: list[str] = []
        if sec.is_known_attacker:
            threat.append("known attacker infrastructure")
        if sec.is_spam:
            threat.append("a spam source")
        if sec.is_bot:
            threat.append("bot activity")
        if threat:
            narrative += f" It has been flagged for {', '.join(threat)}."

        if sec.is_cloud_provider:
            narrative += (
                f" The IP is hosted on cloud infrastructure "
                f"({sec.cloud_provider_name or 'unknown'})."
            )

        narrative += (
            f" Overall risk assessment: **{risk.risk_level}** "
            f"({risk.unified_score}/100)."
        )

        parts.append(narrative)
        return "\n".join(parts)

    # ------------------------------------------------------------------ #
    # 2. Summary Table
    # ------------------------------------------------------------------ #

    def _summary_table(self, intel: IPIntelligence, risk: RiskAssessment) -> str:
        loc = intel.location
        sec = intel.security
        rows = [
            ("IP Address", f"`{intel.ip}`"),
            (
                "Country",
                (
                    f"{loc.country_emoji} {loc.country_name}"
                    if loc.country_name
                    else "N/A"
                ),
            ),
            ("City", loc.city or "N/A"),
            ("State/Province", loc.state_prov or "N/A"),
            ("Continent", loc.continent_name or "N/A"),
            ("ASN", intel.asn.as_number or "N/A"),
            ("Organization", intel.asn.organization or intel.company.name or "N/A"),
            ("Network Type", intel.asn.type or intel.company.type or "N/A"),
            ("ISP", intel.company.name or "N/A"),
            ("Hostname", f"`{intel.hostname}`" if intel.hostname else "N/A"),
            ("Threat Score", f"{sec.threat_score}/100"),
            ("Risk Level", f"**{risk.risk_level}** ({risk.unified_score}/100)"),
            ("VPN", _yn(sec.is_vpn)),
            ("Proxy", _yn(sec.is_proxy)),
            ("Residential Proxy", _yn(sec.is_residential_proxy)),
            ("TOR", _yn(sec.is_tor)),
            ("Known Attacker", _yn(sec.is_known_attacker)),
            ("Bot", _yn(sec.is_bot)),
            ("Spam", _yn(sec.is_spam)),
            (
                "Cloud Provider",
                sec.cloud_provider_name if sec.is_cloud_provider else "No",
            ),
            ("Timezone", intel.timezone.name or "N/A"),
        ]

        lines = ["## IP Summary", "", "| Field | Value |", "| :--- | :--- |"]
        for label, value in rows:
            lines.append(f"| {label} | {value} |")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 3. Security Narrative
    # ------------------------------------------------------------------ #

    def _security_narrative(self, intel: IPIntelligence, risk: RiskAssessment) -> str:
        sec = intel.security
        if not sec.threat_score and not any(
            [
                sec.is_vpn,
                sec.is_proxy,
                sec.is_tor,
                sec.is_known_attacker,
                sec.is_spam,
                sec.is_bot,
            ]
        ):
            return ""

        lines = ["## Security Assessment", ""]

        # Narrative instead of booleans
        if sec.is_anonymous:
            parts = []
            if sec.is_vpn:
                p = "a commercial VPN"
                if sec.vpn_provider_names:
                    p += f" ({', '.join(sec.vpn_provider_names)})"
                if sec.vpn_confidence_score:
                    p += f" [confidence: {sec.vpn_confidence_score}%]"
                parts.append(p)
            if sec.is_proxy:
                p = "a proxy"
                if sec.proxy_provider_names:
                    p += f" ({', '.join(sec.proxy_provider_names)})"
                parts.append(p)
            if sec.is_residential_proxy:
                parts.append("residential proxy network")
            if sec.is_tor:
                parts.append("a known TOR exit node")
            if sec.is_relay:
                p = "a relay service"
                if sec.relay_provider_name:
                    p += f" ({sec.relay_provider_name})"
                parts.append(p)

            lines.append(
                f"This address appears to originate from {', '.join(parts)}. "
                f"Traffic from this IP may be masking its true origin."
            )
        else:
            lines.append("No anonymization signals detected for this IP.")

        # Threat signals
        threats: list[str] = []
        if sec.is_known_attacker:
            threats.append("known attacker infrastructure")
        if sec.is_spam:
            threats.append("a spam origination point")
        if sec.is_bot:
            threats.append("automated bot traffic")
        if threats:
            lines.append("")
            lines.append(
                f"**Threat flags:** This IP has been identified as "
                f"{', '.join(threats)}."
            )

        lines.append("")
        lines.append(risk.explanation)
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 4. Infrastructure Profile
    # ------------------------------------------------------------------ #

    def _infrastructure_profile(self, intel: IPIntelligence) -> str:
        comp = intel.company
        net = intel.network
        if not comp.name and not net.connection_type:
            return ""

        lines = ["## Infrastructure Profile", ""]

        profile_type = comp.type or intel.asn.type or "Unknown"
        profile_map = {
            "hosting": "Hosting / Data Center",
            "isp": "Internet Service Provider",
            "business": "Business / Enterprise",
            "education": "Education / Research",
        }
        human = profile_map.get(profile_type.lower(), profile_type.title())
        lines.append(f"**Category:** {human}")

        if comp.name:
            lines.append(f"**Company:** {comp.name}")
        if comp.domain:
            lines.append(f"**Domain:** {comp.domain}")
        if net.connection_type:
            lines.append(f"**Connection Type:** {net.connection_type}")
        if net.route:
            lines.append(f"**Route:** `{net.route}`")
        if net.is_anycast:
            lines.append("**Anycast:** Yes — this IP is an anycast address")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 5. Network Context
    # ------------------------------------------------------------------ #

    def _network_context(self, intel: IPIntelligence) -> str:
        asn = intel.asn
        if not asn.as_number:
            return ""

        lines = ["## Network Context", ""]
        lines.append(f"**ASN:** {asn.as_number}")
        lines.append(f"**Organization:** {asn.organization or 'N/A'}")

        if asn.asn_name:
            lines.append(f"**ASN Name:** {asn.asn_name}")
        if asn.type:
            lines.append(f"**Type:** {asn.type}")
        if asn.rir:
            lines.append(f"**RIR:** {asn.rir}")
        if asn.date_allocated:
            lines.append(f"**Allocated:** {asn.date_allocated}")
        if asn.domain:
            lines.append(f"**Domain:** {asn.domain}")
        if asn.num_of_ipv4_routes:
            lines.append(f"**IPv4 Routes:** {asn.num_of_ipv4_routes}")
        if asn.num_of_ipv6_routes:
            lines.append(f"**IPv6 Routes:** {asn.num_of_ipv6_routes}")

        if asn.routes:
            routes_str = ", ".join(f"`{r}`" for r in asn.routes[:10])
            lines.append(f"**Routes:** {routes_str}")

        if asn.peers:
            peer_strs = [f"{p.as_number} ({p.description})" for p in asn.peers[:10]]
            lines.append(f"**Peers:** {', '.join(peer_strs)}")
        if asn.upstreams:
            up_strs = [f"{u.as_number} ({u.description})" for u in asn.upstreams[:10]]
            lines.append(f"**Upstreams:** {', '.join(up_strs)}")
        if asn.downstreams:
            down_strs = [
                f"{d.as_number} ({d.description})" for d in asn.downstreams[:10]
            ]
            lines.append(f"**Downstreams:** {', '.join(down_strs)}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 6. Geo Intelligence
    # ------------------------------------------------------------------ #

    def _geo_intelligence(self, intel: IPIntelligence) -> str:
        loc = intel.location
        if not loc.country_name:
            return ""

        lines = ["## Geo Intelligence", ""]
        lines.append(
            f"**Location:** {loc.city or 'N/A'}, "
            f"{loc.state_prov or 'N/A'}, {loc.country_name}"
        )
        if loc.latitude and loc.longitude:
            lines.append(f"**Coordinates:** {loc.latitude}, {loc.longitude}")
        if loc.accuracy_radius:
            conf = f" ({loc.confidence} confidence)" if loc.confidence else ""
            lines.append(f"**Accuracy Radius:** {loc.accuracy_radius} km{conf}")
        if loc.district:
            lines.append(f"**District:** {loc.district}")
        if loc.zipcode:
            lines.append(f"**Postal Code:** {loc.zipcode}")
        if loc.is_eu:
            lines.append("**EU Member:** Yes")
        if loc.continent_name:
            lines.append(f"**Continent:** {loc.continent_name}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 7. Abuse Workflow
    # ------------------------------------------------------------------ #

    def _abuse_workflow(self, intel: IPIntelligence) -> str:
        ab = intel.abuse
        if not ab.emails and not ab.name:
            return ""

        lines = ["## Abuse Contact", ""]
        lines.append(
            "Use the following contact information to report abuse "
            "originating from this IP range."
        )
        lines.append("")

        if ab.organization:
            lines.append(f"**Organization:** {ab.organization}")
        if ab.name:
            lines.append(f"**Contact Name:** {ab.name}")
        if ab.kind:
            lines.append(f"**Kind:** {ab.kind}")
        if ab.emails:
            for email in ab.emails:
                lines.append(f"**Email:** `{email}`")
        if ab.phone_numbers:
            for phone in ab.phone_numbers:
                lines.append(f"**Phone:** {phone}")
        if ab.address:
            lines.append(f"**Address:** {ab.address}")
        if ab.route:
            lines.append(f"**Network:** `{ab.route}`")
        if ab.country:
            lines.append(f"**Registered Country:** {ab.country}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 8. Timeline
    # ------------------------------------------------------------------ #

    def _timeline(self, intel: IPIntelligence) -> str:
        sec = intel.security
        events: list[tuple[str, str]] = []

        if sec.vpn_last_seen:
            events.append((sec.vpn_last_seen, "Last seen as VPN"))
        if sec.proxy_last_seen:
            events.append((sec.proxy_last_seen, "Last seen as Proxy"))
        if intel.asn.date_allocated:
            events.append((intel.asn.date_allocated, "ASN allocated"))

        if not events:
            return ""

        events.sort()
        lines = ["## Timeline", ""]
        for date, label in events:
            lines.append(f"- **{date}** — {label}")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 9. Confidence Explanation
    # ------------------------------------------------------------------ #

    def _confidence_note(self, risk: RiskAssessment) -> str:
        return (
            f"## Enrichment Confidence\n\n"
            f"Assessment confidence: **{risk.confidence}/100**. "
            f"This value is derived from the API-provided confidence "
            f"scores for VPN/proxy detection and the overall threat "
            f"score. Higher values indicate stronger signal correlation "
            f"across multiple detection methods."
        )

    # ------------------------------------------------------------------ #
    # Footer
    # ------------------------------------------------------------------ #

    @staticmethod
    def _footer() -> str:
        return "---\n*Enriched by IPGeolocation.io OpenCTI Connector*"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _yn(val: bool) -> str:
    return "**Yes** ⚠️" if val else "No"
