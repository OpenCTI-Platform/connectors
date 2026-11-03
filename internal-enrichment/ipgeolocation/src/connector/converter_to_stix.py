"""Convert IPGeolocation.io intelligence into STIX 2.1 objects for OpenCTI."""

import ipaddress

from connector.markdown_generator import MarkdownGenerator
from connector.risk_scorer import RiskAssessment
from connector.settings import TLPLevel
from connectors_sdk.models import (
    AutonomousSystem,
    City,
    Country,
    ExternalReference,
    Hostname,
    Indicator,
    Note,
    Organization,
    OrganizationAuthor,
    Reference,
    Relationship,
    TLPMarking,
)
from ipgeolocation_client import IPIntelligence
from pycti import STIX_EXT_OCTI_SCO, OpenCTIStix2

SOURCE_NAME = "IPGeolocation.io"

# Security flags turned into labels on the observable, in this order.
_FLAG_LABELS = (
    ("is_vpn", "vpn"),
    ("is_proxy", "proxy"),
    ("is_residential_proxy", "residential-proxy"),
    ("is_tor", "tor"),
    ("is_relay", "relay"),
    ("is_bot", "bot"),
    ("is_spam", "spam"),
    ("is_known_attacker", "known-attacker"),
    ("is_anonymous", "anonymous"),
    ("is_cloud_provider", "cloud-provider"),
)


class ConverterToStix:
    """Build the STIX objects for one enrichment.

    New entities come from `connectors_sdk.models`, which gives every object the
    deterministic ID OpenCTI expects. The enriched observable itself is updated in place
    (score, labels, external reference), so it keeps its own markings and author.
    """

    def __init__(self, tlp_level: TLPLevel):
        self.author = OrganizationAuthor(
            name=SOURCE_NAME,
            description="IP geolocation, IP intelligence and threat intelligence provider.",
            external_references=[
                ExternalReference(
                    source_name=SOURCE_NAME, url="https://ipgeolocation.io"
                )
            ],
        )
        self.marking = TLPMarking(level=tlp_level)
        self.markdown = MarkdownGenerator()

    def _relationship(self, rel_type: str, source, target, description: str):
        return Relationship(
            type=rel_type,
            source=source,
            target=target,
            description=description,
            author=self.author,
            markings=[self.marking],
        )

    def build(
        self,
        intel: IPIntelligence,
        risk: RiskAssessment | None,
        stix_entity: dict,
        *,
        create_labels: bool = True,
        create_relationships: bool = True,
        create_indicator: bool = False,
        indicator_threshold: int = 50,
        create_note: bool = True,
    ) -> list:
        """Return the new STIX objects; `stix_entity` is updated in place.

        `risk` is None when the lookup returned no security data: then no score,
        risk label or indicator is produced.
        """
        observable = Reference(id=stix_entity["id"])
        entities: list = [self.author, self.marking]
        relationships: list = []

        def link(rel_type, source, target, description):
            if create_relationships:
                relationships.append(
                    self._relationship(rel_type, source, target, description)
                )

        location = intel.location
        country = None
        if location.country_name:
            country = Country(
                name=location.country_name, author=self.author, markings=[self.marking]
            )
            entities.append(country)
            link("located-at", observable, country, "Geolocated by IPGeolocation.io")
        if location.city:
            city = City(name=location.city, author=self.author, markings=[self.marking])
            entities.append(city)
            link("located-at", observable, city, "Geolocated by IPGeolocation.io")
            if country:
                link(
                    "located-at",
                    city,
                    country,
                    f"{location.city} is in {location.country_name}",
                )

        autonomous_system = self._autonomous_system(intel)
        if autonomous_system:
            entities.append(autonomous_system)
            link(
                "belongs-to",
                observable,
                autonomous_system,
                "Announced by this autonomous system",
            )

        organization_name = (intel.asn.organization or intel.company.name).strip()
        if organization_name:
            details = [
                f"{label}: {value}"
                for label, value in (
                    ("Type", intel.company.type or intel.asn.type),
                    ("Domain", intel.company.domain or intel.asn.domain),
                )
                if value
            ]
            organization = Organization(
                name=organization_name,
                description=", ".join(details) or None,
                author=self.author,
                markings=[self.marking],
            )
            entities.append(organization)
            if autonomous_system:
                link(
                    "related-to",
                    autonomous_system,
                    organization,
                    "Operated by this organization",
                )
            else:
                link(
                    "related-to",
                    observable,
                    organization,
                    "Organization using this IP address",
                )

        cloud_provider = intel.security.cloud_provider_name.strip()
        if intel.security.is_cloud_provider and cloud_provider:
            provider = Organization(
                name=cloud_provider,
                description="Cloud or hosting provider",
                author=self.author,
                markings=[self.marking],
            )
            if provider.id not in {e.id for e in entities}:
                entities.append(provider)
            link("related-to", observable, provider, "Hosted by this provider")

        hostname_value = self._hostname(intel)
        if hostname_value:
            hostname = Hostname(
                value=hostname_value, author=self.author, markings=[self.marking]
            )
            entities.append(hostname)
            link("resolves-to", hostname, observable, "Hostname of the IP address")

        labels = self._labels(intel, risk) if create_labels else []
        if create_indicator and risk and risk.unified_score >= indicator_threshold:
            indicator = self._indicator(intel, risk, stix_entity, labels)
            entities.append(indicator)
            relationships.append(
                self._relationship(
                    "based-on", indicator, observable, "Created from the enrichment"
                )
            )

        if create_note:
            entities.append(
                Note(
                    abstract=f"IPGeolocation.io enrichment of {intel.ip}",
                    content=self.markdown.generate(intel, risk),
                    objects=[observable],
                    author=self.author,
                    markings=[self.marking],
                )
            )

        self._update_observable(stix_entity, intel, risk, labels)
        return [obj.to_stix2_object() for obj in entities + relationships]

    @staticmethod
    def _hostname(intel: IPIntelligence) -> str | None:
        """The reverse DNS name, or None.

        Without one, the API returns the address itself, possibly in another notation
        (e.g. a compressed IPv6), which is not a hostname.
        """
        hostname = (intel.hostname or "").strip().rstrip(".")
        try:
            ipaddress.ip_address(hostname)
            return None
        except ValueError:
            return hostname or None

    def _autonomous_system(self, intel: IPIntelligence):
        number = intel.asn.as_number.upper().removeprefix("AS").strip()
        if not number.isdigit():
            return None
        return AutonomousSystem(
            number=int(number),
            name=intel.asn.organization or intel.asn.asn_name or f"AS{number}",
            rir=intel.asn.rir or None,
            author=self.author,
            markings=[self.marking],
        )

    def _indicator(self, intel, risk, stix_entity, labels):
        observable_type = (
            "IPv6-Addr" if stix_entity["type"] == "ipv6-addr" else "IPv4-Addr"
        )
        reasons = (
            ", ".join(risk.contributing_factors)
            or f"threat score {intel.security.threat_score}"
        )
        return Indicator(
            name=intel.ip,
            pattern=f"[{stix_entity['type']}:value = '{intel.ip}']",
            pattern_type="stix",
            main_observable_type=observable_type,
            description=(
                f"IPGeolocation.io rates {intel.ip} as {risk.risk_level} risk "
                f"({risk.unified_score}/100): {reasons}."
            ),
            score=risk.opencti_score,
            labels=labels or None,
            external_references=[self._lookup_reference(intel.ip)],
            author=self.author,
            markings=[self.marking],
        )

    @staticmethod
    def _labels(intel: IPIntelligence, risk: RiskAssessment | None) -> list[str]:
        labels = [
            label for flag, label in _FLAG_LABELS if getattr(intel.security, flag)
        ]
        for network_type in (intel.company.type, intel.asn.type):
            if network_type and network_type.lower() not in labels:
                labels.append(network_type.lower())
        if intel.network.is_anycast:
            labels.append("anycast")
        if risk:
            labels.append(f"risk:{risk.risk_level.lower()}")
        return labels

    @staticmethod
    def _lookup_reference(ip: str) -> ExternalReference:
        return ExternalReference(
            source_name=SOURCE_NAME,
            url=f"https://ipgeolocation.io/what-is-my-ip/{ip}",
            description=f"IPGeolocation.io lookup of {ip}",
        )

    def _update_observable(self, stix_entity, intel, risk, labels) -> None:
        if risk:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", risk.opencti_score
            )
        for label in labels:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "labels", label, True
            )
        reference = self._lookup_reference(intel.ip)
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity,
            STIX_EXT_OCTI_SCO,
            "external_references",
            {
                "source_name": reference.source_name,
                "url": reference.url,
                "description": reference.description,
            },
            True,
        )
