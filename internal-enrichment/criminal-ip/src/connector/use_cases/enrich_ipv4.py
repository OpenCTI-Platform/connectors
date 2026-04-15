import logging
from typing import Any, List

import stix2
from connector.utils import _convert_score_to_confidence
from criminalip_client import CriminalIpClient
from pycti import Indicator as PyctiIndicator
from pycti import Location as PyctiLocation
from pycti import Location as PyctiVulnerability
from pycti import (
    StixCoreRelationship,
)


class Ipv4Enricher:
    def __init__(
        self, connector_logger: logging.Logger, client: CriminalIpClient, author
    ):
        self.connector_logger = connector_logger
        self.client = client
        self.author = author

    def process_ipv4_enrichment(self, obs_value: str) -> List[Any]:
        objects = []
        ip_data = self.client.get_data("/v1/asset/ip/report", {"ip": obs_value})

        if ip_data:
            ip_value = ip_data.get("ip")
            if not ip_value:
                return []

            # IPv4 observable
            ipv4_stix = stix2.IPv4Address(value=ip_value)
            objects.append(ipv4_stix)

            # Build labels from issues + categories + malicious info
            labels = []

            issues = ip_data.get("issues", {})
            for key, value in issues.items():
                if isinstance(value, bool) and value:
                    labels.append(key.replace("is_", "").upper())

            ip_category = ip_data.get("ip_category", {}).get("data", [])
            for category in ip_category:
                if category.get("type"):
                    labels.append(category.get("type").upper())

            malicious_info_data = self.client.get_data(
                "/v1/feature/ip/malicious-info", {"ip": obs_value}
            )
            if malicious_info_data:
                if malicious_info_data.get("is_malicious"):
                    labels.append("Malicious")
                if malicious_info_data.get("is_anonymous_vpn"):
                    labels.append("Anonymous VPN")
                if malicious_info_data.get("can_remote_access"):
                    labels.append("Remote Access")
                if malicious_info_data.get("is_vpn"):
                    labels.append("VPN")

            # Score -> confidence
            score_data = ip_data.get("score", {})
            inbound_score_str = score_data.get("inbound")
            outbound_score_str = score_data.get("outbound")
            inbound_confidence = _convert_score_to_confidence(inbound_score_str)
            outbound_confidence = _convert_score_to_confidence(outbound_score_str)
            overall_confidence = max(inbound_confidence, outbound_confidence)

            # Indicator
            indicator_pattern = f"[ipv4-addr:value = '{ip_value}']"
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(indicator_pattern),
                name=f"Criminal IP Reputation for {ip_value}",
                pattern_type="stix",
                pattern=indicator_pattern,
                confidence=overall_confidence,
                labels=list(set(labels)),
                created_by_ref=self.author.id,
                description=(
                    f"- x_criminalip_inbound_score: {inbound_score_str}\n"
                    f"- x_criminalip_outbound_score: {outbound_score_str}"
                ),
            )
            objects.append(indicator)

            # Indicator -> Observable (based-on)
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "based-on", indicator.id, ipv4_stix.id
                    ),
                    relationship_type="based-on",
                    source_ref=indicator.id,
                    target_ref=ipv4_stix.id,
                    created_by_ref=self.author.id,
                )
            )

            # Whois -> AS + Location
            as_stix = None
            loc_stix = None
            whois_data = ip_data.get("whois", {}).get("data")
            if whois_data:
                whois_entry = whois_data[0]
                as_number = whois_entry.get("as_no")
                if as_number:
                    as_stix = stix2.AutonomousSystem(
                        number=as_number, name=whois_entry.get("as_name")
                    )
                    objects.append(as_stix)

                country_code = whois_entry.get("org_country_code")
                if country_code:
                    loc_stix = stix2.Location(
                        id=PyctiLocation.generate_id(country_code.upper(), "Country"),
                        country=country_code.upper(),
                        city=whois_entry.get("city"),
                        region=whois_entry.get("region"),
                        latitude=whois_entry.get("latitude"),
                        longitude=whois_entry.get("longitude"),
                    )
                    objects.append(loc_stix)

            # Relationships
            if as_stix:
                objects.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "belongs-to", ipv4_stix.id, as_stix.id
                        ),
                        relationship_type="belongs-to",
                        source_ref=ipv4_stix.id,
                        target_ref=as_stix.id,
                        created_by_ref=self.author.id,
                    )
                )
            if loc_stix:
                objects.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "located-at", ipv4_stix.id, loc_stix.id
                        ),
                        relationship_type="located-at",
                        source_ref=ipv4_stix.id,
                        target_ref=loc_stix.id,
                        created_by_ref=self.author.id,
                    )
                )

            # Vulnerabilities
            vulnerabilities = ip_data.get("vulnerability", {}).get("data", [])
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve_id")
                if cve_id:
                    vuln_stix = stix2.Vulnerability(
                        id=PyctiVulnerability.generate_id(cve_id),
                        name=cve_id,
                        description=vuln.get("cve_description"),
                        created_by_ref=self.author.id,
                    )
                    objects.append(vuln_stix)
                    objects.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "indicates", indicator.id, vuln_stix.id
                            ),
                            relationship_type="indicates",
                            source_ref=indicator.id,
                            target_ref=vuln_stix.id,
                            created_by_ref=self.author.id,
                        )
                    )

        return objects
