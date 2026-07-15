"""
IPGeolocation.io OpenCTI Connector — STIX 2.1 Mapper
======================================================

Transforms :class:`IPIntelligence` into a list of STIX 2.1 objects ready
for bundling and ingestion into OpenCTI.

STIX mapping decisions:
    Country/City  → stix2.Location
    ASN           → stix2.AutonomousSystem (custom SCO)
    Org/ISP       → stix2.Identity (class=organization)
    Hostname      → stix2.DomainName (SCO)
    Threat flags  → stix2.Indicator + labels
    Abuse contact → stix2.Identity (class=organization)
    Notes         → stix2.Note (markdown)
    Opinions      → stix2.Opinion
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Optional

import stix2

from .models import IPIntelligence
from .risk_scorer import RISK_CRITICAL, RISK_HIGH, RISK_LOW, RISK_MEDIUM, RiskAssessment

# ---------------------------------------------------------------------------
# Deterministic ID helpers (OpenCTI-style UUIDv5)
# ---------------------------------------------------------------------------
_NAMESPACE = uuid.UUID("d1f3a8c0-7e5b-4c3a-9f2d-6b8e1a0c5d4f")


def _det_id(prefix: str, value: str) -> str:
    """Deterministic STIX id: ``prefix--<uuid5>``."""
    return f"{prefix}--{uuid.uuid5(_NAMESPACE, f'{prefix}:{value}')}"


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# TLP marking definitions (re-usable singletons)
# ---------------------------------------------------------------------------
TLP_WHITE = stix2.TLP_WHITE
TLP_GREEN = stix2.TLP_GREEN
TLP_AMBER = stix2.TLP_AMBER
TLP_RED = stix2.TLP_RED

TLP_MAP = {
    "TLP:WHITE": TLP_WHITE,
    "TLP:CLEAR": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:RED": TLP_RED,
}


class STIXMapper:
    """Stateless mapper: call ``build_bundle_objects`` to get STIX objects."""

    def __init__(
        self,
        author_name: str = "IPGeolocation.io",
        default_marking: str = "TLP:WHITE",
        confidence: int = 80,
    ):
        # Author identity (created once, referenced everywhere)
        self._author = stix2.Identity(
            id=_det_id("identity", author_name),
            name=author_name,
            identity_class="organization",
            description=(
                "IPGeolocation.io — Enterprise-grade IP geolocation "
                "and threat intelligence provider."
            ),
            created_by_ref=None,
            allow_custom=True,
        )
        self._marking = TLP_MAP.get(default_marking, TLP_WHITE)
        self._confidence = confidence

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def build_bundle_objects(
        self,
        intel: IPIntelligence,
        risk: RiskAssessment,
        observable_id: str,
        observable_type: str,
        *,
        create_labels: bool = True,
        create_indicators: bool = True,
        create_relationships: bool = True,
        create_notes: bool = True,
        create_opinions: bool = False,
        create_summary: bool = True,
        indicator_threshold: int = 50,
    ) -> list[Any]:
        """Return all STIX objects for a single IP enrichment."""
        objects: list[Any] = [self._author, self._marking]
        ext_refs = self._external_references(intel)

        # --- Locations ------------------------------------------------
        country_loc = self._make_country(intel)
        if country_loc:
            objects.append(country_loc)
            if create_relationships:
                objects.append(
                    self._relationship(
                        observable_id,
                        "located-at",
                        country_loc.id,
                        f"IP is geolocated in {intel.location.country_name}",
                    )
                )

        city_loc = self._make_city(intel)
        if city_loc:
            objects.append(city_loc)
            if create_relationships and country_loc:
                objects.append(
                    self._relationship(
                        city_loc.id,
                        "located-at",
                        country_loc.id,
                        f"{intel.location.city} is in {intel.location.country_name}",
                    )
                )

        # --- Autonomous System ----------------------------------------
        asn_obj = self._make_asn(intel)
        if asn_obj:
            objects.append(asn_obj)
            if create_relationships:
                objects.append(
                    self._relationship(
                        observable_id,
                        "belongs-to",
                        asn_obj.id,
                        f"IP belongs to {intel.asn.as_number}",
                    )
                )

        # --- Organization / ISP / Company -----------------------------
        org = self._make_organization(intel)
        if org:
            objects.append(org)
            if create_relationships and asn_obj:
                objects.append(
                    self._relationship(
                        asn_obj.id,
                        "related-to",
                        org.id,
                        f"{intel.asn.as_number} operated by "
                        f"{intel.asn.organization or intel.company.name}",
                    )
                )

        # --- Cloud / Hosting Provider ---------------------------------
        cloud_org = self._make_cloud_provider(intel)
        if cloud_org:
            objects.append(cloud_org)
            if create_relationships:
                objects.append(
                    self._relationship(
                        observable_id,
                        "related-to",
                        cloud_org.id,
                        f"IP hosted on {intel.security.cloud_provider_name}",
                    )
                )

        # --- Abuse Contact --------------------------------------------
        abuse_org = self._make_abuse_contact(intel)
        if abuse_org:
            objects.append(abuse_org)
            if create_relationships:
                objects.append(
                    self._relationship(
                        observable_id,
                        "related-to",
                        abuse_org.id,
                        "Abuse contact for IP network",
                    )
                )

        # --- Hostname -------------------------------------------------
        hostname_obj = self._make_hostname(intel)
        if hostname_obj:
            objects.append(hostname_obj)
            if create_relationships:
                objects.append(
                    self._relationship(
                        observable_id,
                        "resolves-to",
                        hostname_obj.id,
                        f"IP resolves to {intel.hostname}",
                    )
                )

        # --- Labels ---------------------------------------------------
        labels: list[str] = []
        if create_labels:
            labels = self._derive_labels(intel, risk)

        # --- Indicators -----------------------------------------------
        if create_indicators and risk.unified_score >= indicator_threshold:
            indicator = self._make_indicator(intel, risk, labels, ext_refs)
            if indicator:
                objects.append(indicator)
                if create_relationships:
                    objects.append(
                        self._relationship(
                            indicator.id,
                            "based-on",
                            observable_id,
                            "Indicator derived from enrichment",
                        )
                    )

        # --- Notes ----------------------------------------------------
        if create_notes and create_summary:
            note = self._make_note(intel, risk, observable_id, labels)
            if note:
                objects.append(note)

        # --- Opinions -------------------------------------------------
        if create_opinions:
            opinion = self._make_opinion(risk, observable_id)
            if opinion:
                objects.append(opinion)

        # --- Custom properties on observable --------------------------
        # OpenCTI allows updating observable custom props via STIX
        obs_update = self._observable_update(
            intel,
            risk,
            observable_id,
            observable_type,
            labels,
            ext_refs,
        )
        if obs_update:
            objects.append(obs_update)

        return objects

    # ------------------------------------------------------------------ #
    # Object Factories
    # ------------------------------------------------------------------ #

    def _make_country(self, intel: IPIntelligence) -> Optional[stix2.Location]:
        loc = intel.location
        if not loc.country_name:
            return None
        return stix2.Location(
            id=_det_id("location", f"country:{loc.country_code2}"),
            name=loc.country_name,
            country=loc.country_code2,
            region=loc.continent_name,
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            allow_custom=True,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [loc.country_code3] if loc.country_code3 else [],
            },
        )

    def _make_city(self, intel: IPIntelligence) -> Optional[stix2.Location]:
        loc = intel.location
        if not loc.city:
            return None
        lat = _safe_float(loc.latitude)
        lon = _safe_float(loc.longitude)
        props: dict[str, Any] = {
            "x_opencti_location_type": "City",
        }
        kwargs: dict[str, Any] = dict(
            id=_det_id("location", f"city:{loc.city}:{loc.country_code2}"),
            name=f"{loc.city}, {loc.state_prov}" if loc.state_prov else loc.city,
            country=loc.country_code2,
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            allow_custom=True,
            custom_properties=props,
        )
        if lat is not None:
            kwargs["latitude"] = lat
        if lon is not None:
            kwargs["longitude"] = lon
        return stix2.Location(**kwargs)

    def _make_asn(self, intel: IPIntelligence) -> Optional[Any]:
        asn = intel.asn
        if not asn.as_number:
            return None
        # AutonomousSystem is an OpenCTI custom SCO
        asn_num = asn.as_number.replace("AS", "").strip()
        try:
            asn_int = int(asn_num)
        except ValueError:
            return None
        return stix2.AutonomousSystem(
            id=_det_id("autonomous-system", f"AS{asn_int}"),
            number=asn_int,
            name=asn.organization or asn.asn_name or f"AS{asn_int}",
            allow_custom=True,
            custom_properties={
                "x_opencti_description": (
                    f"RIR: {asn.rir or 'N/A'} | "
                    f"Allocated: {asn.date_allocated or 'N/A'} | "
                    f"Type: {asn.type or 'N/A'}"
                ),
            },
        )

    def _make_organization(self, intel: IPIntelligence) -> Optional[stix2.Identity]:
        name = (intel.asn.organization or intel.company.name or "").strip()
        if not name:
            return None
        desc_parts = []
        if intel.company.type:
            desc_parts.append(f"Type: {intel.company.type}")
        if intel.company.domain:
            desc_parts.append(f"Domain: {intel.company.domain}")
        if intel.asn.type:
            desc_parts.append(f"Network type: {intel.asn.type}")
        return stix2.Identity(
            id=_det_id("identity", f"org:{name.lower()}"),
            name=name,
            identity_class="organization",
            description=" | ".join(desc_parts) if desc_parts else None,
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            allow_custom=True,
        )

    def _make_cloud_provider(self, intel: IPIntelligence) -> Optional[stix2.Identity]:
        if not intel.security.is_cloud_provider:
            return None
        name = intel.security.cloud_provider_name or "Unknown Cloud Provider"
        return stix2.Identity(
            id=_det_id("identity", f"cloud:{name.lower()}"),
            name=name,
            identity_class="organization",
            description="Cloud / hosting infrastructure provider",
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            allow_custom=True,
        )

    def _make_abuse_contact(self, intel: IPIntelligence) -> Optional[stix2.Identity]:
        ab = intel.abuse
        if not ab.emails and not ab.name:
            return None
        name = ab.organization or ab.name or "Abuse Contact"
        desc_parts = []
        if ab.emails:
            desc_parts.append(f"Email: {', '.join(ab.emails)}")
        if ab.phone_numbers:
            desc_parts.append(f"Phone: {', '.join(ab.phone_numbers)}")
        if ab.address:
            desc_parts.append(f"Address: {ab.address}")
        if ab.route:
            desc_parts.append(f"Network: {ab.route}")
        return stix2.Identity(
            id=_det_id("identity", f"abuse:{name.lower()}:{ab.route}"),
            name=f"Abuse Contact — {name}",
            identity_class="organization",
            description=" | ".join(desc_parts),
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            allow_custom=True,
        )

    def _make_hostname(self, intel: IPIntelligence) -> Optional[Any]:
        if not intel.hostname:
            return None
        return stix2.DomainName(
            value=intel.hostname,
            allow_custom=True,
            custom_properties={
                "created_by_ref": self._author.id,
            },
        )

    # ------------------------------------------------------------------ #
    # Indicators
    # ------------------------------------------------------------------ #

    def _make_indicator(
        self,
        intel: IPIntelligence,
        risk: RiskAssessment,
        labels: list[str],
        ext_refs: list[dict],
    ) -> Optional[stix2.Indicator]:
        sec = intel.security
        # Build description based on actual flags
        reasons: list[str] = []
        if sec.is_tor:
            reasons.append("TOR exit node")
        if sec.is_known_attacker:
            reasons.append("known attacker")
        if sec.is_spam:
            reasons.append("spam source")
        if sec.is_bot:
            reasons.append("bot activity")
        if sec.is_vpn:
            reasons.append("VPN")
        if sec.is_proxy:
            reasons.append("proxy")
        if not reasons:
            reasons.append(f"threat score {sec.threat_score}")

        ip_type = "ipv6" if ":" in intel.ip else "ipv4"
        pattern = f"[{ip_type}-addr:value = '{intel.ip}']"
        name = f"Malicious IP: {intel.ip}"
        desc = (
            f"IPGeolocation.io enrichment flagged {intel.ip} as "
            f"{risk.risk_level} risk ({risk.unified_score}/100). "
            f"Signals: {', '.join(reasons)}."
        )
        valid_from = _now_iso()

        return stix2.Indicator(
            id=_det_id("indicator", f"ipgeo:{intel.ip}"),
            name=name,
            description=desc,
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            labels=labels[:10] if labels else [],
            confidence=risk.confidence,
            external_references=ext_refs,
            allow_custom=True,
            custom_properties={
                "x_opencti_score": risk.opencti_score,
                "x_opencti_main_observable_type": (
                    "IPv6-Addr" if ":" in intel.ip else "IPv4-Addr"
                ),
            },
        )

    # ------------------------------------------------------------------ #
    # Notes
    # ------------------------------------------------------------------ #

    def _make_note(
        self,
        intel: IPIntelligence,
        risk: RiskAssessment,
        observable_id: str,
        labels: list[str],
    ) -> stix2.Note:
        from .markdown_generator import MarkdownGenerator

        md = MarkdownGenerator().generate(intel, risk)
        return stix2.Note(
            id=_det_id("note", f"ipgeo:enrichment:{intel.ip}"),
            abstract=f"IPGeolocation.io Enrichment — {intel.ip}",
            content=md,
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            object_refs=[observable_id],
            labels=labels[:5] if labels else [],
            allow_custom=True,
        )

    # ------------------------------------------------------------------ #
    # Opinions
    # ------------------------------------------------------------------ #

    def _make_opinion(
        self,
        risk: RiskAssessment,
        observable_id: str,
    ) -> Optional[stix2.Opinion]:
        opinion_map = {
            RISK_LOW: "strongly-disagree",
            RISK_MEDIUM: "neutral",
            RISK_HIGH: "agree",
            RISK_CRITICAL: "strongly-agree",
        }
        return stix2.Opinion(
            id=_det_id("opinion", f"ipgeo:risk:{observable_id}"),
            opinion=opinion_map.get(risk.risk_level, "neutral"),
            explanation=risk.explanation,
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            object_refs=[observable_id],
            allow_custom=True,
        )

    # ------------------------------------------------------------------ #
    # Observable update (score + external refs)
    # ------------------------------------------------------------------ #

    def _observable_update(
        self,
        intel: IPIntelligence,
        risk: RiskAssessment,
        observable_id: str,
        observable_type: str,
        labels: list[str],
        ext_refs: list[dict],
    ) -> Optional[Any]:
        """Build a STIX SCO that OpenCTI will merge with the existing one."""
        ip_val = intel.ip
        if not ip_val:
            return None

        custom = {
            "x_opencti_score": risk.opencti_score,
            "x_opencti_description": risk.explanation,
        }
        kwargs: dict[str, Any] = {
            "id": observable_id,
            "value": ip_val,
            "allow_custom": True,
            "custom_properties": custom,
        }
        if ext_refs:
            kwargs["external_references"] = ext_refs

        if "IPv6" in observable_type:
            return stix2.IPv6Address(**kwargs)
        return stix2.IPv4Address(**kwargs)

    # ------------------------------------------------------------------ #
    # Labels
    # ------------------------------------------------------------------ #

    @staticmethod
    def _derive_labels(intel: IPIntelligence, risk: RiskAssessment) -> list[str]:
        """Derive semantically meaningful labels — no duplicates."""
        labels: set[str] = set()
        sec = intel.security

        if sec.is_vpn:
            labels.add("vpn")
        if sec.is_proxy:
            labels.add("proxy")
        if sec.is_residential_proxy:
            labels.add("residential-proxy")
        if sec.is_tor:
            labels.add("tor")
        if sec.is_relay:
            labels.add("relay")
        if sec.is_bot:
            labels.add("bot")
        if sec.is_spam:
            labels.add("spam")
        if sec.is_known_attacker:
            labels.add("known-attacker")
        if sec.is_anonymous:
            labels.add("anonymous")
        if sec.is_cloud_provider:
            labels.add("cloud-provider")

        # Company / network type labels
        comp_type = (intel.company.type or "").lower()
        if comp_type:
            labels.add(comp_type)  # e.g. hosting, isp, business, education
        net_type = (intel.asn.type or "").lower()
        if net_type and net_type != comp_type:
            labels.add(net_type)

        if intel.network.is_anycast:
            labels.add("anycast")

        # Risk tier label
        risk_label = f"risk:{risk.risk_level.lower()}"
        labels.add(risk_label)

        return sorted(labels)

    # ------------------------------------------------------------------ #
    # Relationships
    # ------------------------------------------------------------------ #

    def _relationship(
        self,
        source: str,
        rel_type: str,
        target: str,
        desc: str = "",
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=_det_id("relationship", f"{source}:{rel_type}:{target}"),
            relationship_type=rel_type,
            source_ref=source,
            target_ref=target,
            description=desc,
            created_by_ref=self._author.id,
            object_marking_refs=[self._marking.id],
            confidence=self._confidence,
            allow_custom=True,
        )

    # ------------------------------------------------------------------ #
    # External references
    # ------------------------------------------------------------------ #

    @staticmethod
    def _external_references(intel: IPIntelligence) -> list[dict]:
        refs = [
            {
                "source_name": "IPGeolocation.io",
                "url": f"https://ipgeolocation.io/what-is-my-ip/{intel.ip}",
                "description": f"IPGeolocation.io lookup for {intel.ip}",
            }
        ]
        return refs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_float(val: str) -> Optional[float]:
    try:
        return float(val) if val else None
    except (ValueError, TypeError):
        return None
