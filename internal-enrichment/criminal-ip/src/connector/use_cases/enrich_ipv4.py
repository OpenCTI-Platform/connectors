import logging
from typing import Any, List

from criminalip_client import CriminalIpClient


class Ipv4Enricher:
    def __init__(
        self,
        connector_logger: logging.Logger,
        client: CriminalIpClient,
        converter_to_stix,
    ):
        self.connector_logger = connector_logger
        self.client = client
        self.converter_to_stix = converter_to_stix

    def process_ipv4_enrichment(self, obs_value: str) -> List[Any]:
        objects = []
        ip_data = self.client.get_data("/v1/asset/ip/report", {"ip": obs_value})

        if ip_data:
            ip_value = ip_data.get("ip")
            if not ip_value:
                return []

            author = self.converter_to_stix.create_author()
            objects.append(author.to_stix2_object())

            # IPv4 observable
            ipv4_stix = self.converter_to_stix.create_ipv4(ip=ip_value)
            objects.append(ipv4_stix.to_stix2_object())

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

            # Indicator
            indicator_pattern = f"[ipv4-addr:value = '{ip_value}']"
            indicator = self.converter_to_stix.create_indicator(
                name=f"Criminal IP Reputation for {ip_value}",
                pattern_type="stix",
                pattern=indicator_pattern,
                labels=list(set(labels)),
                description=(
                    f"- x_criminalip_inbound_score: {inbound_score_str}\n"
                    f"- x_criminalip_outbound_score: {outbound_score_str}"
                ),
            )
            objects.append(indicator.to_stix2_object())

            # Indicator -> Observable (based-on)
            objects.append(
                self.converter_to_stix.create_relationship(
                    relationship_type="based-on",
                    source_obj=indicator,
                    target_obj=ipv4_stix,
                ).to_stix2_object()
            )

            # Whois -> AS + Location
            autonomous_system = None
            loc_stix = None
            whois_data = ip_data.get("whois", {}).get("data")
            if whois_data:
                whois_entry = whois_data[0]
                as_number = whois_entry.get("as_no")
                if as_number:
                    autonomous_system = self.converter_to_stix.create_autonomous_system(
                        number=as_number, name=whois_entry.get("as_name")
                    )
                    objects.append(autonomous_system.to_stix2_object())

                country_code = whois_entry.get("org_country_code")
                if country_code:
                    loc_stix = self.converter_to_stix.create_city(
                        name=whois_entry.get("city"),
                        latitude=whois_entry.get("latitude"),
                        longitude=whois_entry.get("longitude"),
                    )
                    objects.append(loc_stix.to_stix2_object())

            # Relationships
            if autonomous_system:
                objects.append(
                    self.converter_to_stix.create_relationship(
                        relationship_type="belongs-to",
                        source_obj=ipv4_stix,
                        target_obj=autonomous_system,
                    ).to_stix2_object()
                )
            if loc_stix:
                objects.append(
                    self.converter_to_stix.create_relationship(
                        relationship_type="located-at",
                        source_obj=ipv4_stix,
                        target_obj=loc_stix,
                    ).to_stix2_object()
                )

            # Vulnerabilities
            vulnerabilities = ip_data.get("vulnerability", {}).get("data", [])
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve_id")
                if cve_id:
                    vuln_stix = self.converter_to_stix.create_vulnerability(
                        name=cve_id,
                        description=vuln.get("cve_description"),
                    )
                    objects.append(vuln_stix.to_stix2_object())
                    objects.append(
                        self.converter_to_stix.create_relationship(
                            relationship_type="indicates",
                            source_obj=indicator,
                            target_obj=vuln_stix,
                        ).to_stix2_object()
                    )

        return objects
