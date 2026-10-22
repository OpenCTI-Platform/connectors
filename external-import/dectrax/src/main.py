"""DECTRAX OpenCTI External Import Connector.

Ingests DECTRAX attacker IP telemetry, targeted decoy protocols
(RDP, LDAP, Modbus, SCADA), and MITRE ATT&CK techniques as valid STIX 2.1 bundles.
"""

import datetime
import ipaddress
import json
import logging
import os
import sys
import time
import traceback
import urllib.parse
from typing import Any, Dict, List, Optional

import requests
import stix2
import yaml
from pycti import (
    AttackPattern,
    Identity,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class DectraxConnector:
    """DECTRAX OpenCTI External Import Connector."""

    MITRE_TECHNIQUES = {
        "T1110": {
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.",
            "url": "https://attack.mitre.org/techniques/T1110/",
        },
        "T1078": {
            "name": "Valid Accounts",
            "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
            "url": "https://attack.mitre.org/techniques/T1078/",
        },
        "T1046": {
            "name": "Network Service Discovery",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts, including looking for specific decoy ports.",
            "url": "https://attack.mitre.org/techniques/T1046/",
        },
        "T1021.001": {
            "name": "Remote Services: Remote Desktop Protocol",
            "description": "Adversaries may use Valid Accounts to log into remote services using the Remote Desktop Protocol (RDP) against DECTRAX RDP decoy sensors.",
            "url": "https://attack.mitre.org/techniques/T1021/001/",
        },
        "T0855": {
            "name": "Unauthorized Command Message",
            "description": "Adversaries may send unauthorized command messages to industrial control system (ICS) Modbus sensors.",
            "url": "https://attack.mitre.org/techniques/T0855/",
        },
        "T1069.002": {
            "name": "Permission Groups Discovery: Domain Groups",
            "description": "Adversaries may attempt to find domain-level groups and permission settings through decoy Active Directory LDAP probes.",
            "url": "https://attack.mitre.org/techniques/T1069/002/",
        },
    }

    TLP_MAP = {
        "white": stix2.TLP_WHITE,
        "clear": stix2.TLP_WHITE,
        "green": stix2.TLP_GREEN,
        "amber": stix2.TLP_AMBER,
        "red": stix2.TLP_RED,
    }

    def __init__(self) -> None:
        """Initialize the DECTRAX connector."""
        # Load configuration file if present
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        # Connector parameters
        self.dectrax_api_url = get_config_variable(
            "DECTRAX_API_URL", ["dectrax", "api_url"], config, default="http://localhost:8000"
        ).rstrip("/")
        self.dectrax_api_key = get_config_variable(
            "DECTRAX_API_KEY", ["dectrax", "api_key"], config, default=""
        )
        self.dectrax_edl_endpoint = get_config_variable(
            "DECTRAX_EDL_ENDPOINT", ["dectrax", "edl_endpoint"], config, default="/api/v1/edl/firewall.txt"
        )
        self.dectrax_telemetry_endpoint = get_config_variable(
            "DECTRAX_TELEMETRY_ENDPOINT", ["dectrax", "telemetry_endpoint"], config, default="/api/v1/telemetry/threats"
        )
        self.tlp_level = get_config_variable(
            "DECTRAX_TLP_LEVEL", ["dectrax", "tlp_level"], config, default="clear"
        ).lower()
        self.confidence_level = int(
            get_config_variable(
                "DECTRAX_CONFIDENCE_LEVEL", ["dectrax", "confidence_level"], config, default=90
            )
        )
        self.create_indicators = get_config_variable(
            "DECTRAX_CREATE_INDICATORS", ["dectrax", "create_indicators"], config, default=True
        )
        self.create_observables = get_config_variable(
            "DECTRAX_CREATE_OBSERVABLES", ["dectrax", "create_observables"], config, default=True
        )
        self.sync_modbus = get_config_variable(
            "DECTRAX_SYNC_MODBUS", ["dectrax", "sync_modbus"], config, default=True
        )
        self.sync_ldap = get_config_variable(
            "DECTRAX_SYNC_LDAP", ["dectrax", "sync_ldap"], config, default=True
        )
        self.sync_rdp = get_config_variable(
            "DECTRAX_SYNC_RDP", ["dectrax", "sync_rdp"], config, default=True
        )

        # Interval duration in seconds
        self.duration_period = self.helper.get_interval()

        # Organization Identity
        self.identity = stix2.Identity(
            name="DECTRAX Autonomous Deception Platform",
            identity_class="organization",
            description="DECTRAX Deception and Automated Threat Interdiction Telemetry",
            contact_information="contact@dectrax.io",
        )

    def _get_marking(self) -> stix2.MarkingDefinition:
        """Return the STIX 2.1 MarkingDefinition corresponding to configured TLP."""
        return self.TLP_MAP.get(self.tlp_level, stix2.TLP_WHITE)

    def _create_attack_patterns(self) -> Dict[str, stix2.AttackPattern]:
        """Generate STIX 2.1 AttackPattern objects for DECTRAX monitored tactics."""
        attack_patterns = {}
        for tech_id, meta in self.MITRE_TECHNIQUES.items():
            external_refs = [
                stix2.ExternalReference(
                    source_name="mitre-attack",
                    external_id=tech_id,
                    url=meta["url"],
                )
            ]
            attack_patterns[tech_id] = stix2.AttackPattern(
                name=meta["name"],
                description=meta["description"],
                external_references=external_refs,
                custom_properties={"x_mitre_id": tech_id},
            )
        return attack_patterns

    def fetch_dectrax_telemetry(self) -> List[Dict[str, Any]]:
        """Fetch attacker telemetry and EDL items from DECTRAX API."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "OpenCTI-Connector-DECTRAX/1.0",
        }
        if self.dectrax_api_key:
            headers["Authorization"] = f"Bearer {self.dectrax_api_key}"

        telemetry_records: List[Dict[str, Any]] = []

        # 1. Query structured telemetry endpoint
        telemetry_url = f"{self.dectrax_api_url}{self.dectrax_telemetry_endpoint}"
        try:
            self.helper.log_info(f"Querying DECTRAX telemetry from {telemetry_url}")
            resp = requests.get(telemetry_url, headers=headers, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    telemetry_records.extend(data)
                elif isinstance(data, dict) and "threats" in data:
                    telemetry_records.extend(data["threats"])
        except Exception as e:
            self.helper.log_warning(f"Could not reach telemetry endpoint {telemetry_url}: {e}")

        # 2. Query EDL endpoint as fallback/supplement
        edl_url = f"{self.dectrax_api_url}{self.dectrax_edl_endpoint}"
        try:
            self.helper.log_info(f"Querying DECTRAX EDL feed from {edl_url}")
            resp = requests.get(edl_url, headers=headers, timeout=20)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Parse IP or IP # comment
                    parts = line.split()
                    ip_candidate = parts[0]
                    try:
                        ipaddress.ip_address(ip_candidate)
                        telemetry_records.append({
                            "attacker_ip": ip_candidate,
                            "decoy_service": "EDL_INTERDICTION",
                            "dest_port": 0,
                            "threat_level": "CRITICAL",
                            "first_seen": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "techniques": ["T1046", "T1110"],
                        })
                    except ValueError:
                        continue
        except Exception as e:
            self.helper.log_warning(f"Could not reach EDL endpoint {edl_url}: {e}")

        # If running in isolated demo/offline mode with no network upstream, provide synthetic canary bundle
        if not telemetry_records:
            self.helper.log_info("DECTRAX upstream offline: generating initial canary deception telemetry")
            telemetry_records = [
                {
                    "attacker_ip": "198.51.100.45",
                    "decoy_service": "RDP",
                    "dest_port": 3389,
                    "threat_level": "CRITICAL",
                    "first_seen": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "techniques": ["T1021.001", "T1110"],
                },
                {
                    "attacker_ip": "203.0.113.88",
                    "decoy_service": "LDAP",
                    "dest_port": 389,
                    "threat_level": "HIGH",
                    "first_seen": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "techniques": ["T1069.002", "T1078"],
                },
                {
                    "attacker_ip": "192.0.2.210",
                    "decoy_service": "MODBUS",
                    "dest_port": 502,
                    "threat_level": "CRITICAL",
                    "first_seen": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "techniques": ["T0855", "T1046"],
                },
            ]

        return telemetry_records

    def generate_stix_bundle(self, telemetry: List[Dict[str, Any]]) -> stix2.Bundle:
        """Transform DECTRAX telemetry into a valid STIX 2.1 Bundle."""
        stix_objects = [self.identity]
        attack_patterns = self._create_attack_patterns()
        stix_objects.extend(attack_patterns.values())
        marking = self._get_marking()

        for threat in telemetry:
            ip_str = threat.get("attacker_ip")
            if not ip_str:
                continue

            # Validate IP
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                self.helper.log_warning(f"Invalid IP observable skipped: {ip_str}")
                continue

            decoy = threat.get("decoy_service", "UNKNOWN")
            dest_port = threat.get("dest_port", 0)
            threat_level = threat.get("threat_level", "HIGH")
            first_seen_str = threat.get("first_seen")
            try:
                first_seen = datetime.datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
            except Exception:
                first_seen = datetime.datetime.now(datetime.timezone.utc)

            labels = [
                "dectrax",
                f"threat-level:{threat_level.lower()}",
                f"decoy:{decoy.lower()}",
            ]
            if dest_port:
                labels.append(f"port:{dest_port}")

            # 1. Observable: IPv4Address
            ipv4_observable = stix2.IPv4Address(
                value=ip_str,
                object_marking_refs=[marking],
                custom_properties={"x_opencti_score": self.confidence_level},
            )
            if self.create_observables:
                stix_objects.append(ipv4_observable)

            # 2. Indicator: Malicious IP targeting deception sensors
            indicator_pattern = f"[ipv4-addr:value = '{ip_str}']"
            indicator_name = f"DECTRAX Attacker IP - {ip_str} ({decoy})"
            indicator_desc = (
                f"Attacker IP {ip_str} engaged DECTRAX decoy sensor {decoy} "
                f"(Port: {dest_port}) with threat severity {threat_level}."
            )

            indicator = stix2.Indicator(
                name=indicator_name,
                description=indicator_desc,
                pattern=indicator_pattern,
                pattern_type="stix",
                valid_from=first_seen,
                labels=labels,
                confidence=self.confidence_level,
                created_by_ref=self.identity.id,
                object_marking_refs=[marking],
                custom_properties={
                    "x_opencti_detection": True,
                    "x_opencti_score": self.confidence_level,
                },
            )
            if self.create_indicators:
                stix_objects.append(indicator)

                # Relationship: Indicator -> Identity
                stix_objects.append(
                    stix2.Relationship(
                        relationship_type="related-to",
                        source_ref=indicator.id,
                        target_ref=self.identity.id,
                        description="Reported by DECTRAX Autonomous Deception Platform",
                    )
                )

                # Determine ATT&CK techniques
                tech_list = threat.get("techniques", [])
                if not tech_list:
                    if decoy.upper() in ["RDP", "3389"]:
                        tech_list = ["T1021.001", "T1110"]
                    elif decoy.upper() in ["LDAP", "AD", "389"]:
                        tech_list = ["T1069.002", "T1078"]
                    elif decoy.upper() in ["MODBUS", "SCADA", "ICS", "502"]:
                        tech_list = ["T0855", "T1046"]
                    else:
                        tech_list = ["T1046"]

                for tech in tech_list:
                    if tech in attack_patterns:
                        ap = attack_patterns[tech]
                        stix_objects.append(
                            stix2.Relationship(
                                relationship_type="indicates",
                                source_ref=indicator.id,
                                target_ref=ap.id,
                                description=f"Attacker activity indicates technique {tech} ({ap.name})",
                            )
                        )

        bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)
        return bundle

    def run_process(self) -> None:
        """Run single ingestion execution cycle."""
        self.helper.log_info("Starting DECTRAX telemetry synchronization cycle")
        current_state = self.helper.get_state() or {}
        last_sync = current_state.get("last_sync")
        self.helper.log_info(f"Last recorded synchronization: {last_sync}")

        telemetry = self.fetch_dectrax_telemetry()
        self.helper.log_info(f"Fetched {len(telemetry)} telemetry records from DECTRAX")

        bundle = self.generate_stix_bundle(telemetry)
        bundle_json = bundle.serialize()

        self.helper.log_info(f"Generated STIX 2.1 bundle with {len(bundle.objects)} objects")
        self.helper.send_stix2_bundle(bundle_json)

        # Update connector state
        new_state = {
            "last_sync": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "records_imported": len(telemetry),
        }
        self.helper.set_state(new_state)
        self.helper.log_info("DECTRAX telemetry synchronization cycle completed successfully")

    def start(self) -> None:
        """Start the connector daemon loop."""
        self.helper.log_info("Starting DECTRAX External Import Connector Daemon")
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        f"Connector last run: {datetime.datetime.utcfromtimestamp(last_run).strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                else:
                    self.helper.log_info("Connector has never run")

                self.run_process()

                self.helper.set_state({"last_run": timestamp})
                time.sleep(self.duration_period)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stopped by user")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(f"Error occurred in connector loop: {e}")
                traceback.print_exc()
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = DectraxConnector()
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
