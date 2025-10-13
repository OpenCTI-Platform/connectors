import os
import sys
import yaml
import requests
import time
from typing import Dict, Any, List

from stix2 import (
    DomainName,
    IPv4Address,
    AutonomousSystem,
    Location,
    Indicator,
    Bundle,
    Relationship,
    Vulnerability,
)
from pycti import OpenCTIConnectorHelper, get_config_variable
from datetime import datetime, timezone, timedelta

class CriminalIPConnector:

    def __init__(self):
        config_file_path = os.path.join(os.path.dirname(__file__), "config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_key = get_config_variable(
            "CRIMINALIP_TOKEN", ["criminalip", "api_key"], config
        )
        if self.api_key is None:
            msg = "Criminal IP API key is not set."
            self.helper.log_error(msg)
            raise ValueError(msg)
        self.base_url = "https://api.criminalip.io"

    def _call_api(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        headers = {"x-api-key": self.api_key}
        try:
            response = requests.get(url, headers=headers, params=params or {}, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"Error calling Criminal IP API for {url}: {e}")
            return None
        
    def _call_api_post(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        headers = {"x-api-key": self.api_key}
        try:
            response = requests.post(url, headers=headers, data=params or {}, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"Error calling Criminal IP API for {url}: {e}")
            return None
    
    def _convert_score_to_confidence(self, score_str: str) -> int:
        score_map = {
            "Critical": 95,
            "Dangerous": 85,
            "Moderate": 65,
            "Low": 35,
            "Safe": 10,
        }
        return score_map.get(score_str, 0)
    
    def _to_stix_objects_for_ip(self, ip_data: Dict[str, Any], malicious_info_data: Dict[str, Any] = None) -> List[Any]:
        
        self.helper.log_info("--- RUNNING LATEST CODE VERSION ---")
        
        try:
            tlp_clear_filter = {"mode": "and", "filters": [{"key": "definition", "values": ["TLP:CLEAR"]}], "filterGroups": []}
            tlp_marking = self.helper.api.marking_definition.read(filters=tlp_clear_filter)
            tlp_id = tlp_marking['standard_id'] if tlp_marking else None
            
            identity_filter = {"mode": "and", "filters": [{"key": "name", "values": ["CriminalIP Connector"]}], "filterGroups": []}
            identity = self.helper.api.identity.read(filters=identity_filter)
            identity_id = identity['standard_id'] if identity else None
        except Exception as e:
            self.helper.log_error(f"Error getting standard object IDs: {e}")
            return []

        objects = []
        ip_value = ip_data.get("ip")
        if not ip_value:
            return []

        ipv4_addr_stix = IPv4Address(value=ip_value)
        objects.append(ipv4_addr_stix)

        labels = []
        
        issues = ip_data.get("issues", {})
        for key, value in issues.items():
            if isinstance(value, bool) and value:
                label = key.replace("is_", "").upper()
                labels.append(label)

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

        score_data = ip_data.get("score", {})
        inbound_score_str = score_data.get("inbound")
        outbound_score_str = score_data.get("outbound")
        
        inbound_confidence = self._convert_score_to_confidence(inbound_score_str)
        outbound_confidence = self._convert_score_to_confidence(outbound_score_str)
        overall_confidence = max(inbound_confidence, outbound_confidence)

        indicator_score = Indicator(
            name=f"Criminal IP Reputation for {ip_value}",
            pattern_type="stix",
            pattern=f"[ipv4-addr:value = '{ip_value}']",
            confidence=overall_confidence,
            labels=list(set(labels)),
            object_marking_refs=[tlp_id],
            created_by_ref=identity_id,
            description="\n".join({
                f"- x_criminalip_inbound_score: {inbound_score_str}",
                f"- x_criminalip_outbound_score: {outbound_score_str}"
            })
        )
        objects.append(indicator_score)

        as_stix = None
        loc_stix = None

        whois_data = ip_data.get("whois", {}).get("data")

        if whois_data:
            whois_entry = whois_data[0]
            as_number = whois_entry.get("as_no")
            if as_number:
                as_stix = AutonomousSystem(number=as_number, name=whois_entry.get("as_name"))
                objects.append(as_stix)

            country_code = whois_entry.get("org_country_code")
            if country_code:
                loc_stix = Location(
                    country=country_code.upper(),
                    city=whois_entry.get("city"),
                    region=whois_entry.get("region"),
                    latitude=whois_entry.get("latitude"),
                    longitude=whois_entry.get("longitude"),
                )
                objects.append(loc_stix)
        
        if as_stix:
            self.helper.log_info(f"Created AS_STIX")
            as_rel = Relationship(ipv4_addr_stix, 'belongs-to', as_stix, created_by_ref=identity_id)
            objects.append(as_rel)

        if loc_stix:
            self.helper.log_info(f"Created LOC STIX")
            loc_rel = Relationship(ipv4_addr_stix, 'located-at', loc_stix, created_by_ref=identity_id)
            objects.append(loc_rel)

        vulnerabilities = ip_data.get("vulnerability", {}).get("data", [])
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            if cve_id:
                vuln_stix = Vulnerability(
                    name=cve_id,
                    description=vuln.get("cve_description"),
                    created_by_ref=identity_id,
                    object_marking_refs=[tlp_id]
                )
                objects.append(vuln_stix)
                
                rel_indicator_vuln = Relationship(
                    indicator_score.id,
                    'indicates',
                    vuln_stix.id,
                    created_by_ref=identity_id
                )
                objects.append(rel_indicator_vuln)
                
        return objects
    
    def _to_stix_objects_for_domain(self, domain_name_value: str, domain_data: Dict[str, Any]) -> List[Any]:
        """Convert Criminal IP API response for Domain to a list of STIX objects"""
        try:
            tlp_clear_filter = {"mode": "and", "filters": [{"key": "definition", "values": ["TLP:CLEAR"]}], "filterGroups": []}
            tlp_marking = self.helper.api.marking_definition.read(filters=tlp_clear_filter)
            tlp_id = tlp_marking['standard_id'] if tlp_marking else None
            
            identity_filter = {"mode": "and", "filters": [{"key": "name", "values": ["CriminalIP Connector"]}], "filterGroups": []}
            identity = self.helper.api.identity.read(filters=identity_filter)
            identity_id = identity['standard_id'] if identity else None
        except Exception as e:
            self.helper.log_error(f"Error getting standard object IDs: {e}")
            return []
        
        objects = []
        domain_stix = DomainName(value=domain_name_value)
        objects.append(domain_stix)

        summary = domain_data.get("summary", {})
        phishing_prob = summary.get("url_phishing_prob")

        if phishing_prob > 20 or summary.get("phishing_record") > 0 or summary.get("suspicious_file") > 0:
            labels = ["malicious-domain"]
            description_parts = ["Criminal IP URL Scan Report Findings:"]

            labels.append(f"phishing-record-{summary.get('phishing_record')}")
            description_parts.append("- Phishing record found.")
            labels.append(f"suspicious_file-{summary.get('suspicious_file')}")
            description_parts.append("- Suspicious file detected on the page.")
            labels.append(f"credential-input-field-{summary.get('cred_input')}")
            description_parts.append("- Page contains credential input fields (potential phishing).")
            labels.append(f"favicon-domain-mismatch-{summary.get('diff_domain_favicon')}")
            description_parts.append("- Favicon domain does not match the page domain.")

            description_parts.append(f"- x_criminalip_phishing_prob: {phishing_prob}")

            indicator = Indicator(
                name=f"Malicious domain: {domain_name_value}",
                pattern_type="stix",
                pattern=f"[domain-name:value = '{domain_name_value}']",
                confidence=phishing_prob,
                labels=list(set(labels)),
                description="\n".join(description_parts),
                object_marking_refs=[tlp_id],
                created_by_ref=identity_id,
            )
            objects.append(indicator)

        related_ips = domain_data.get("connected_ip", [])
        for ip_info in related_ips:
            ip_value = ip_info.get("ip")
            if ip_value:
                ip_stix = IPv4Address(value=ip_value)
                objects.append(ip_stix)
                
                resolves_to_rel = Relationship(
                    domain_stix,
                    'resolves-to',
                    ip_stix,
                    created_by_ref=identity_id
                )
                objects.append(resolves_to_rel)

        countries = summary.get("list_of_countries", [])
        for country_code in countries:
            loc_stix = Location(country=country_code.upper(), allow_custom=True)
            objects.append(loc_stix)

            related_to_rel = Relationship(
                domain_stix.id,
                'related-to',
                loc_stix.id,
                description=f"Domain {domain_name_value} is associated with servers in {country_code.upper()}.",
                created_by_ref=identity_id
            )
            objects.append(related_to_rel)
        
        return objects

    def _process_message(self, data):
        """Main method to process a message from the bus"""
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        
        if observable is None:
            self.helper.log_error(f"Observable not found with id {entity_id}.")
            return "Observable not found"
        
        observable_type = observable.get("entity_type")
        observable_value = observable.get("value") or observable.get("observable_value")

        stix_objects = []
        if observable_type == "IPv4-Addr":
            self.helper.log_info(f"Processing IP: {observable_value}")
            
            ip_report_endpoint = "/v1/asset/ip/report"
            params = {"ip": observable_value}
            ip_data = self._call_api(ip_report_endpoint, params)
            
            malicious_info_endpoint = "/v1/feature/ip/malicious-info"
            malicious_data = self._call_api(malicious_info_endpoint, params)
            
            if ip_data:
                stix_objects = self._to_stix_objects_for_ip(ip_data, malicious_data)

        elif observable_type == "Domain-Name":
            scan_id = -1
            self.helper.log_info(f"Processing Domain: {observable_value}")
            reports_endpoint = "/v1/domain/reports"
            reports_data = self._call_api(reports_endpoint, {"query": observable_value, "offset": 0})
            reports = reports_data.get("data")
            if reports and len(reports) > 0: 
                report_time_str = reports.get("reports", [])[0].get("reg_dtime")
                report_time = datetime.strptime(report_time_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)

                if report_time >= one_week_ago:
                    scan_id = reports.get("reports", [])[0].get("scan_id")
                else: 
                    endpoint = f"/v1/domain/scan"
                    domain_data = {"query": observable_value}
                    scan_id_data = self._call_api_post(endpoint, domain_data)
                    scan_id = scan_id_data.get("data").get("scan_id")

                    flag = True
                    while flag:
                        endpoint = f"/v1/domain/status/{scan_id}"
                        scan_data = self._call_api(endpoint)

                        scan_result = scan_data.get("data")
                        if scan_result:
                            score = scan_result.get("scan_percentage")
                            if (score >= 100):
                                flag = False
                                break
                        
                        time.sleep(3) 
            
            if scan_id:
                endpoint = f"/v2/domain/report/{scan_id}"
                domain_data = self._call_api(endpoint) 
                if domain_data:
                    stix_objects = self._to_stix_objects_for_domain(observable_value, domain_data.get("data"))
        
        else:
            self.helper.log_info(f"Unsupported observable type: {observable_type}")
            return "Unsupported observable type"

        if not stix_objects:
            return f"No STIX objects created for {observable_value}."
        
        self.helper.log_info(f"STIX_Objects: {stix_objects}")
        
        bundle = Bundle(objects=stix_objects, allow_custom=True).serialize()
        self.helper.send_stix2_bundle(bundle, entity_id=observable.get("id"))

        self.helper.log_info(f"Successfully enriched {observable_type} {observable_value} with {len(stix_objects)} STIX objects.")
        return "Success"
    
    def start(self):
        self.helper.listen(self._process_message)

if __name__ == "__main__":
    try:
        connector = CriminalIPConnector()
        connector.start()
    except Exception as e:
        print(e)
        sys.exit(1)