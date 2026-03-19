import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import requests
import stix2
from connector.settings import ConnectorSettings
from connectors_sdk.models import OrganizationAuthor
from pycti import (
    Indicator,
    Location,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
)


class CriminalIPConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.base_url = "https://api.criminalip.io"
        self.token = self.config.criminal_ip.token.get_secret_value()
        self.max_tlp = self.config.criminal_ip.max_tlp
        self.session = requests.Session()
        self.session.headers.update({"x-api-key": self.token})

        self.author = OrganizationAuthor(
            name="Criminal IP",
            description="Criminal IP Cyber Threat Intelligence",
        )

    def _call_api(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.get(url, params=params or {}, timeout=20)
            self.helper.connector_logger.info(
                "[API] GET request", {"url_path": endpoint}
            )
            response.raise_for_status()
            result = response.json()
            if result.get("status") and result["status"] != 200:
                self.helper.connector_logger.error(
                    "[API] Criminal IP API returned error",
                    {
                        "url_path": endpoint,
                        "status": result.get("status"),
                        "message": result.get("message"),
                    },
                )
                return None
            return result
        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "[API] Error calling Criminal IP API",
                {"url": url, "error": str(e)},
            )
            return None

    def _call_api_post(
        self, endpoint: str, params: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.post(url, data=params or {}, timeout=20)
            self.helper.connector_logger.info(
                "[API] POST request", {"url_path": endpoint}
            )
            response.raise_for_status()
            result = response.json()
            if result.get("status") and result["status"] != 200:
                self.helper.connector_logger.error(
                    "[API] Criminal IP API returned error",
                    {
                        "url_path": endpoint,
                        "status": result.get("status"),
                        "message": result.get("message"),
                    },
                )
                return None
            return result
        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "[API] Error calling Criminal IP API",
                {"url": url, "error": str(e)},
            )
            return None

    @staticmethod
    def _convert_score_to_confidence(score_str: str) -> int:
        score_map = {
            "Critical": 95,
            "Dangerous": 85,
            "Moderate": 65,
            "Low": 35,
            "Safe": 10,
        }
        return score_map.get(score_str, 0)

    def _extract_and_check_markings(self, entity):
        tlp = "TLP:CLEAR"
        for marking_definition in entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        is_valid = OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp)
        if not is_valid:
            raise ValueError(
                "[CONNECTOR] TLP of the observable is greater than MAX TLP,"
                " skipping enrichment"
            )
        return tlp

    def _to_stix_objects_for_ip(
        self,
        ip_data: Dict[str, Any],
        malicious_info_data: Dict[str, Any] = None,
    ) -> List[Any]:
        objects = []
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
        inbound_confidence = self._convert_score_to_confidence(inbound_score_str)
        outbound_confidence = self._convert_score_to_confidence(outbound_score_str)
        overall_confidence = max(inbound_confidence, outbound_confidence)

        # Indicator
        indicator_pattern = f"[ipv4-addr:value = '{ip_value}']"
        indicator = stix2.Indicator(
            id=Indicator.generate_id(indicator_pattern),
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
                    id=Location.generate_id(country_code.upper(), "Country"),
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
                    id=Vulnerability.generate_id(cve_id),
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

    def process_message(self, data: dict) -> str:
        try:
            opencti_entity = data["enrichment_entity"]
            self._extract_and_check_markings(opencti_entity)

            stix_objects = data["stix_objects"]
            stix_entity = data["stix_entity"]

            obs_value = stix_entity["value"]
            obs_type = stix_entity["type"]

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing entity",
                {"type": obs_type, "value": obs_value},
            )

            # Add author to bundle
            enrichment_objects = [self.author.to_stix2_object()]

            if obs_type == "ipv4-addr":
                ip_data = self._call_api("/v1/asset/ip/report", {"ip": obs_value})
                malicious_data = self._call_api(
                    "/v1/feature/ip/malicious-info", {"ip": obs_value}
                )
                if ip_data:
                    enrichment_objects += self._to_stix_objects_for_ip(
                        ip_data, malicious_data
                    )

            elif obs_type == "domain-name":
                domain_objects = self._process_domain_scan(obs_value)
                enrichment_objects += domain_objects

            else:
                return f"[CONNECTOR] Unsupported type: {obs_type}"

            if len(enrichment_objects) <= 1:  # only author, no real data
                return f"[CONNECTOR] No enrichment data found for {obs_value}"

            # Merge with existing stix objects and send
            all_objects = stix_objects + enrichment_objects
            bundle = self.helper.stix2_create_bundle(all_objects)
            bundles_sent = self.helper.send_stix2_bundle(bundle)

            self.helper.connector_logger.info(
                "[CONNECTOR] Enrichment complete",
                {"bundles_sent": len(bundles_sent), "value": obs_value},
            )
            return f"Sent {len(bundles_sent)} bundle(s) for import"

        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Error during enrichment",
                {"error_message": str(e)},
            )
            # Send back original objects for playbook compatibility
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle(data["stix_objects"])
            )
            raise e

    def _to_stix_objects_for_domain(
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
                id=Indicator.generate_id(indicator_pattern),
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
        countries = summary.get("list_of_countries", [])
        for country_code in countries:
            loc_stix = stix2.Location(
                id=Location.generate_id(country_code.upper(), "Country"),
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

    def _process_domain_scan(self, domain_value: str) -> list:
        scan_id = None

        reports_data = self._call_api(
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
            scan_response = self._call_api_post(
                "/v1/domain/scan", {"query": domain_value}
            )
            if scan_response and scan_response.get("data"):
                scan_id = scan_response["data"].get("scan_id")

                # Poll until scan completes (max 5 minutes)
                max_attempts = 100
                for _ in range(max_attempts):
                    status_data = self._call_api(f"/v1/domain/status/{scan_id}")
                    if status_data and status_data.get("data"):
                        if status_data["data"].get("scan_percentage", 0) >= 100:
                            break
                    time.sleep(3)

        if not scan_id:
            return []

        domain_data = self._call_api(f"/v2/domain/report/{scan_id}")
        if domain_data and domain_data.get("data"):
            return self._to_stix_objects_for_domain(domain_value, domain_data["data"])

        return []

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
