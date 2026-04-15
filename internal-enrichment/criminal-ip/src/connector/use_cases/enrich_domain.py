import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import stix2
from criminalip_client import CriminalIpClient
from pycti import Indicator as PyctiIndicator
from pycti import Location as PyctiLocation
from pycti import (
    StixCoreRelationship,
)


class DomainEnricher:
    def __init__(
        self, connector_logger: logging.Logger, client: CriminalIpClient, author
    ):
        self.connector_logger = connector_logger
        self.client = client
        self.author = author

    def process_domain_scan(self, domain_value: str) -> list:
        scan_id = None

        reports_data = self.client.get_data(
            "/v1/domain/reports", {"query": domain_value, "offset": 0}
        )
        if reports_data:
            data = reports_data.get("data")
            if data:
                reports_list = data.get("reports", [])
                if reports_list:
                    report_time_str = reports_list[0].get("reg_dtime")
                    report_time = datetime.strptime(
                        report_time_str, "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                    one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)

                    if report_time >= one_week_ago:
                        scan_id = reports_list[0].get("scan_id")

        if scan_id is None:
            scan_response = self.client.post_data(
                "/v1/domain/scan", {"query": domain_value}
            )
            if scan_response and scan_response.get("data"):
                scan_id = scan_response["data"].get("scan_id")

                # Poll until scan completes (max 5 minutes)
                max_attempts = 100
                for _ in range(max_attempts):
                    status_data = self.client.get_data(f"/v1/domain/status/{scan_id}")
                    if status_data and status_data.get("data"):
                        if status_data["data"].get("scan_percentage", 0) >= 100:
                            break
                    time.sleep(3)

        if not scan_id:
            return []

        domain_data = self.client.get_data(f"/v2/domain/report/{scan_id}")
        if domain_data and domain_data.get("data"):
            return self.process_domain_enrichment(domain_value, domain_data["data"])

        return []

    def process_domain_enrichment(
        self, domain_name_value: str, domain_data: Dict[str, Any]
    ) -> List[Any]:
        objects = []
        domain_stix = stix2.DomainName(value=domain_name_value)
        objects.append(domain_stix)

        summary = domain_data.get("summary", {})
        phishing_prob = summary.get("url_phishing_prob", 0)

        if (
            phishing_prob > 20
            or summary.get("phishing_record", 0) > 0
            or summary.get("suspicious_file", 0) > 0
        ):
            labels = ["malicious-domain"]
            description_parts = ["Criminal IP URL Scan Report Findings:"]

            labels.append(f"phishing-record-{summary.get('phishing_record')}")
            description_parts.append("- Phishing record found.")
            labels.append(f"suspicious_file-{summary.get('suspicious_file')}")
            description_parts.append("- Suspicious file detected on the page.")
            labels.append(f"credential-input-field-{summary.get('cred_input')}")
            description_parts.append("- Page contains credential input fields.")
            labels.append(
                f"favicon-domain-mismatch-{summary.get('diff_domain_favicon')}"
            )
            description_parts.append("- Favicon domain does not match the page domain.")
            description_parts.append(f"- x_criminalip_phishing_prob: {phishing_prob}")

            indicator_pattern = f"[domain-name:value = '{domain_name_value}']"
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(indicator_pattern),
                name=f"Malicious domain: {domain_name_value}",
                pattern_type="stix",
                pattern=indicator_pattern,
                confidence=phishing_prob,
                labels=list(set(labels)),
                description="\n".join(description_parts),
                created_by_ref=self.author.id,
            )
            objects.append(indicator)

            # Indicator -> Observable (based-on)
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "based-on", indicator.id, domain_stix.id
                    ),
                    relationship_type="based-on",
                    source_ref=indicator.id,
                    target_ref=domain_stix.id,
                    created_by_ref=self.author.id,
                )
            )

        # Related IPs
        related_ips = domain_data.get("connected_ip", [])
        for ip_info in related_ips:
            ip_value = ip_info.get("ip")
            if ip_value:
                ip_stix = stix2.IPv4Address(value=ip_value)
                objects.append(ip_stix)
                objects.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "resolves-to", domain_stix.id, ip_stix.id
                        ),
                        relationship_type="resolves-to",
                        source_ref=domain_stix.id,
                        target_ref=ip_stix.id,
                        created_by_ref=self.author.id,
                    )
                )

        # Countries
        countries_data = summary.get("list_of_countries", [])

        # Prevent None values
        countries = list(filter(lambda x: x is not None, countries_data))

        for country_code in countries:
            loc_stix = stix2.Location(
                id=PyctiLocation.generate_id(country_code.upper(), "Country"),
                country=country_code.upper(),
                allow_custom=True,
            )
            objects.append(loc_stix)
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", domain_stix.id, loc_stix.id
                    ),
                    relationship_type="related-to",
                    source_ref=domain_stix.id,
                    target_ref=loc_stix.id,
                    description=(
                        f"Domain {domain_name_value} associated with"
                        f" servers in {country_code.upper()}."
                    ),
                    created_by_ref=self.author.id,
                )
            )

        return objects
