"""DECTRAX OpenCTI External Import Connector.

Ingests DECTRAX attacker IP telemetry, active decoy sensor engagements
(RDP, LDAP, Modbus, SCADA), and MITRE ATT&CK techniques as valid STIX 2.1 bundles.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import sys
import traceback
from typing import Any, Dict, List, Optional

import requests
import stix2
import yaml
from pycti import (
    AttackPattern,
    Identity,
    Indicator,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)

# Supported TLP marking levels in OpenCTI
SUPPORTED_TLP_LEVELS = {"clear", "white", "green", "amber", "amber+strict", "red"}


def _to_bool(val: Any) -> bool:
    """Normalize config value to boolean."""
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("true", "1", "yes", "on")


def validate_ipv4_address(ip_candidate: str) -> bool:
    """Validate string strictly as an IPv4 address.

    IPv6 addresses and malformed strings return False to avoid
    constructor errors in STIX IPv4Address observables.
    """
    if not isinstance(ip_candidate, str):
        return False
    try:
        ipaddress.IPv4Address(ip_candidate.strip())
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def statement_marking(definition: str) -> stix2.MarkingDefinition:
    """Generate OpenCTI statement marking definition for custom TLP markings."""
    marking_id = MarkingDefinition.generate_id("TLP", definition)
    return stix2.MarkingDefinition(
        id=marking_id,
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        custom_properties={
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": definition,
        },
    )


def resolve_tlp_marking(tlp_str: str) -> stix2.MarkingDefinition:
    """Resolve configured TLP string into standard or statement STIX MarkingDefinition.

    Rejects unsupported markings with ValueError to avoid fail-open behavior.
    """
    normalized = tlp_str.strip().lower()
    if normalized == "clear":
        return statement_marking("TLP:CLEAR")
    elif normalized == "white":
        return stix2.TLP_WHITE
    elif normalized == "green":
        return stix2.TLP_GREEN
    elif normalized == "amber":
        return stix2.TLP_AMBER
    elif normalized == "amber+strict":
        return statement_marking("TLP:AMBER+STRICT")
    elif normalized == "red":
        return stix2.TLP_RED
    else:
        raise ValueError(
            f"Unsupported TLP marking: '{tlp_str}'. "
            f"Supported levels are: {', '.join(sorted(SUPPORTED_TLP_LEVELS))}"
        )


class DectraxConnector:
    """DECTRAX OpenCTI External Import Connector."""

    MITRE_TECHNIQUES = {
        "T1110": {
            "name": "Brute Force",
            "description": (
                "Adversaries may use brute force techniques to attempt access to "
                "accounts when passwords are unknown or when password hashes are obtained."
            ),
            "url": "https://attack.mitre.org/techniques/T1110/",
        },
        "T1078": {
            "name": "Valid Accounts",
            "description": (
                "Adversaries may obtain and abuse credentials of existing accounts "
                "as a means of gaining Initial Access, Persistence, Privilege Escalation, "
                "or Defense Evasion."
            ),
            "url": "https://attack.mitre.org/techniques/T1078/",
        },
        "T1046": {
            "name": "Network Service Discovery",
            "description": (
                "Adversaries may attempt to get a listing of services running on "
                "remote hosts, including looking for specific decoy ports."
            ),
            "url": "https://attack.mitre.org/techniques/T1046/",
        },
        "T1021.001": {
            "name": "Remote Services: Remote Desktop Protocol",
            "description": (
                "Adversaries may use Valid Accounts to log into remote services "
                "using the Remote Desktop Protocol (RDP) against DECTRAX RDP decoy sensors."
            ),
            "url": "https://attack.mitre.org/techniques/T1021/001/",
        },
        "T0855": {
            "name": "Unauthorized Command Message",
            "description": (
                "Adversaries may send unauthorized command messages to industrial "
                "control system (ICS) Modbus sensors."
            ),
            "url": "https://attack.mitre.org/techniques/T0855/",
        },
        "T1069.002": {
            "name": "Permission Groups Discovery: Domain Groups",
            "description": (
                "Adversaries may attempt to find domain-level groups and permission "
                "settings through decoy Active Directory LDAP probes."
            ),
            "url": "https://attack.mitre.org/techniques/T1069/002/",
        },
    }

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        helper: Optional[OpenCTIConnectorHelper] = None,
    ) -> None:
        """Initialize the DECTRAX connector."""
        if config is None:
            config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
            config = (
                yaml.load(open(config_file_path), Loader=yaml.FullLoader)
                if os.path.isfile(config_file_path)
                else {}
            )

        if "connector" not in config:
            config["connector"] = {}
        config["connector"]["type"] = "EXTERNAL_IMPORT"

        self.helper = helper if helper is not None else OpenCTIConnectorHelper(config)

        # Connector parameters
        self.dectrax_api_url = get_config_variable(
            "DECTRAX_API_URL",
            ["dectrax", "api_url"],
            config,
            default="http://localhost:8000",
        ).rstrip("/")
        self.dectrax_api_key = get_config_variable(
            "DECTRAX_API_KEY",
            ["dectrax", "api_key"],
            config,
            default="",
        )
        self.dectrax_edl_endpoint = get_config_variable(
            "DECTRAX_EDL_ENDPOINT",
            ["dectrax", "edl_endpoint"],
            config,
            default="/api/v1/edl/firewall.txt",
        )
        self.dectrax_telemetry_endpoint = get_config_variable(
            "DECTRAX_TELEMETRY_ENDPOINT",
            ["dectrax", "telemetry_endpoint"],
            config,
            default="/api/v1/telemetry/threats",
        )

        # TLP Configuration with startup validation (reject fail-open)
        raw_tlp = get_config_variable(
            "DECTRAX_TLP_LEVEL",
            ["dectrax", "tlp_level"],
            config,
            default="clear",
        )
        self.tlp_level = str(raw_tlp).strip().lower()
        if self.tlp_level not in SUPPORTED_TLP_LEVELS:
            raise ValueError(
                f"Unsupported DECTRAX_TLP_LEVEL: '{self.tlp_level}'. "
                f"Supported values are: {', '.join(sorted(SUPPORTED_TLP_LEVELS))}"
            )
        self.tlp_marking = resolve_tlp_marking(self.tlp_level)

        self.create_indicators = _to_bool(
            get_config_variable(
                "DECTRAX_CREATE_INDICATORS",
                ["dectrax", "create_indicators"],
                config,
                default=True,
            )
        )
        self.create_observables = _to_bool(
            get_config_variable(
                "DECTRAX_CREATE_OBSERVABLES",
                ["dectrax", "create_observables"],
                config,
                default=True,
            )
        )
        self.sync_modbus = _to_bool(
            get_config_variable(
                "DECTRAX_SYNC_MODBUS",
                ["dectrax", "sync_modbus"],
                config,
                default=True,
            )
        )
        self.sync_ldap = _to_bool(
            get_config_variable(
                "DECTRAX_SYNC_LDAP",
                ["dectrax", "sync_ldap"],
                config,
                default=True,
            )
        )
        self.sync_rdp = _to_bool(
            get_config_variable(
                "DECTRAX_SYNC_RDP",
                ["dectrax", "sync_rdp"],
                config,
                default=True,
            )
        )

        # Duration period in ISO 8601 format
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            config,
            default="PT1H",
        )

        # Deterministic Organization Identity ID
        identity_id = Identity.generate_id(
            name="DECTRAX Autonomous Deception Platform",
            identity_class="organization",
        )
        self.identity = stix2.Identity(
            id=identity_id,
            name="DECTRAX Autonomous Deception Platform",
            identity_class="organization",
            description="DECTRAX Deception and Automated Threat Interdiction Telemetry",
            contact_information="contact@dectrax.io",
        )

    def _create_attack_patterns(self) -> Dict[str, stix2.AttackPattern]:
        """Generate STIX 2.1 AttackPattern objects with deterministic IDs."""
        attack_patterns = {}
        for tech_id, meta in self.MITRE_TECHNIQUES.items():
            external_refs = [
                stix2.ExternalReference(
                    source_name="mitre-attack",
                    external_id=tech_id,
                    url=meta["url"],
                )
            ]
            ap_id = AttackPattern.generate_id(meta["name"], tech_id)
            attack_patterns[tech_id] = stix2.AttackPattern(
                id=ap_id,
                name=meta["name"],
                description=meta["description"],
                external_references=external_refs,
                custom_properties={"x_mitre_id": tech_id},
            )
        return attack_patterns

    def collect(self) -> List[Dict[str, Any]]:
        """Collect attacker telemetry and EDL items from upstream DECTRAX API.

        An empty upstream feed remains empty (no synthetic canary fallback).
        """
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
            self.helper.connector_logger.info(
                f"Querying DECTRAX telemetry from {telemetry_url}",
                {"url": telemetry_url},
            )
            resp = requests.get(telemetry_url, headers=headers, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    telemetry_records.extend(data)
                elif isinstance(data, dict) and "threats" in data:
                    telemetry_records.extend(data["threats"])
        except Exception as e:
            self.helper.connector_logger.warning(
                f"Could not reach telemetry endpoint {telemetry_url}: {e}",
                {"error": str(e)},
            )

        # 2. Query EDL endpoint
        edl_url = f"{self.dectrax_api_url}{self.dectrax_edl_endpoint}"
        try:
            self.helper.connector_logger.info(
                f"Querying DECTRAX EDL feed from {edl_url}",
                {"url": edl_url},
            )
            resp = requests.get(edl_url, headers=headers, timeout=20)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    ip_candidate = parts[0]
                    if validate_ipv4_address(ip_candidate):
                        telemetry_records.append({
                            "attacker_ip": ip_candidate,
                            "decoy_service": "EDL_INTERDICTION",
                            "dest_port": 0,
                            "threat_level": "CRITICAL",
                            "first_seen": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "techniques": ["T1046", "T1110"],
                        })
        except Exception as e:
            self.helper.connector_logger.warning(
                f"Could not reach EDL endpoint {edl_url}: {e}",
                {"error": str(e)},
            )

        return telemetry_records

    def transform(self, telemetry: List[Dict[str, Any]]) -> List[Any]:
        """Transform DECTRAX telemetry records into STIX 2.1 objects.

        Strictly enforces protocol flags (sync_rdp, sync_ldap, sync_modbus),
        validates IP addresses strictly as IPv4, and uses deterministic STIX IDs.
        """
        if not telemetry:
            return []

        stix_objects: List[Any] = [self.identity]
        attack_patterns = self._create_attack_patterns()
        stix_objects.extend(attack_patterns.values())

        for threat in telemetry:
            ip_str = threat.get("attacker_ip")
            if not ip_str:
                continue

            # Strict IPv4 validation
            if not validate_ipv4_address(ip_str):
                self.helper.connector_logger.warning(
                    f"Invalid or non-IPv4 observable skipped: {ip_str}",
                    {"attacker_ip": ip_str},
                )
                continue

            decoy = str(threat.get("decoy_service", "UNKNOWN"))
            decoy_upper = decoy.upper()

            # Protocol flag filtering
            if not self.sync_rdp and decoy_upper in ["RDP", "3389"]:
                self.helper.connector_logger.info(
                    f"Skipping RDP telemetry due to sync_rdp=False: {ip_str}",
                    {"decoy": decoy, "ip": ip_str},
                )
                continue
            if not self.sync_ldap and decoy_upper in ["LDAP", "AD", "389"]:
                self.helper.connector_logger.info(
                    f"Skipping LDAP telemetry due to sync_ldap=False: {ip_str}",
                    {"decoy": decoy, "ip": ip_str},
                )
                continue
            if not self.sync_modbus and decoy_upper in ["MODBUS", "SCADA", "ICS", "502"]:
                self.helper.connector_logger.info(
                    f"Skipping Modbus telemetry due to sync_modbus=False: {ip_str}",
                    {"decoy": decoy, "ip": ip_str},
                )
                continue

            dest_port = threat.get("dest_port", 0)
            threat_level = threat.get("threat_level", "HIGH")
            first_seen_str = threat.get("first_seen")
            try:
                first_seen = datetime.datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
            except Exception:
                first_seen = datetime.datetime.now(datetime.timezone.utc)

            labels = [
                "dectrax",
                f"threat-level:{str(threat_level).lower()}",
                f"decoy:{decoy.lower()}",
            ]
            if dest_port:
                labels.append(f"port:{dest_port}")

            # 1. Observable: IPv4Address
            ipv4_observable = stix2.IPv4Address(
                value=ip_str,
                object_marking_refs=[self.tlp_marking],
            )
            if self.create_observables:
                stix_objects.append(ipv4_observable)

            # 2. Indicator: Malicious IP targeting deception sensors
            indicator_pattern = f"[ipv4-addr:value = '{ip_str}']"
            indicator_id = Indicator.generate_id(indicator_pattern)
            indicator_name = f"DECTRAX Attacker IP - {ip_str} ({decoy})"
            indicator_desc = (
                f"Attacker IP {ip_str} engaged DECTRAX decoy sensor {decoy} "
                f"(Port: {dest_port}) with threat severity {threat_level}."
            )

            indicator = stix2.Indicator(
                id=indicator_id,
                name=indicator_name,
                description=indicator_desc,
                pattern=indicator_pattern,
                pattern_type="stix",
                valid_from=first_seen,
                labels=labels,
                created_by_ref=self.identity.id,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "x_opencti_detection": True,
                },
            )
            if self.create_indicators:
                stix_objects.append(indicator)

                # Relationship: Indicator -> Identity
                rel_id = StixCoreRelationship.generate_id(
                    "related-to",
                    indicator.id,
                    self.identity.id,
                )
                stix_objects.append(
                    stix2.Relationship(
                        id=rel_id,
                        relationship_type="related-to",
                        source_ref=indicator.id,
                        target_ref=self.identity.id,
                        description="Reported by DECTRAX Autonomous Deception Platform",
                    )
                )

                # Determine ATT&CK techniques
                tech_list = threat.get("techniques", [])
                if not tech_list:
                    if decoy_upper in ["RDP", "3389"]:
                        tech_list = ["T1021.001", "T1110"]
                    elif decoy_upper in ["LDAP", "AD", "389"]:
                        tech_list = ["T1069.002", "T1078"]
                    elif decoy_upper in ["MODBUS", "SCADA", "ICS", "502"]:
                        tech_list = ["T0855", "T1046"]
                    else:
                        tech_list = ["T1046"]

                for tech in tech_list:
                    if tech in attack_patterns:
                        ap = attack_patterns[tech]
                        ap_rel_id = StixCoreRelationship.generate_id(
                            "indicates",
                            indicator.id,
                            ap.id,
                        )
                        stix_objects.append(
                            stix2.Relationship(
                                id=ap_rel_id,
                                relationship_type="indicates",
                                source_ref=indicator.id,
                                target_ref=ap.id,
                                description=f"Attacker activity indicates technique {tech} ({ap.name})",
                            )
                        )

        return stix_objects

    def send_bundle(self, stix_objects: List[Any], work_id: Optional[str] = None) -> List[Any]:
        """Bundle STIX objects and transmit to OpenCTI platform."""
        if not stix_objects:
            return []

        bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )
        return bundles_sent

    def process_message(self) -> None:
        """Connector processing execution cycle."""
        self.helper.connector_logger.info(
            f"Starting {self.helper.connect_name} synchronization cycle",
            {"connector_name": self.helper.connect_name},
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp = int(datetime.datetime.timestamp(now))
        current_state = self.helper.get_state() or {}
        last_run = current_state.get("last_run")
        last_sync = current_state.get("last_sync")

        self.helper.connector_logger.info(
            "Loaded current connector state",
            {"last_run": str(last_run), "last_sync": str(last_sync)},
        )

        friendly_name = f"DECTRAX run @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
        work_id = None
        try:
            if hasattr(self.helper, "api") and hasattr(self.helper.api, "work"):
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
        except Exception as e:
            self.helper.connector_logger.warning(
                f"Could not initiate work on OpenCTI platform: {e}",
                {"error": str(e)},
            )

        try:
            # 1. Collect telemetry
            telemetry = self.collect()
            self.helper.connector_logger.info(
                f"Collected {len(telemetry)} telemetry records from DECTRAX",
                {"count": len(telemetry)},
            )

            # 2. Transform into STIX objects
            stix_objects = self.transform(telemetry)

            # 3. Transmit bundle if objects exist
            if stix_objects:
                sent = self.send_bundle(stix_objects, work_id=work_id)
                self.helper.connector_logger.info(
                    f"Sent STIX bundle to OpenCTI ({len(sent)} bundle transmissions)",
                    {"bundles_sent": len(sent)},
                )

            # 4. State Persistence: merge new values preserving existing keys
            updated_state = dict(current_state)
            updated_state["last_run"] = timestamp
            updated_state["last_sync"] = now.isoformat()
            updated_state["records_imported"] = len(telemetry)
            self.helper.set_state(updated_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, "
                f"storing last_run={timestamp}, records_imported={len(telemetry)}"
            )
            if work_id and hasattr(self.helper, "api") and hasattr(self.helper.api, "work"):
                self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopping upon user/system request")
            if work_id and hasattr(self.helper, "api") and hasattr(self.helper.api, "work"):
                try:
                    self.helper.api.work.to_processed(work_id, "Interrupted", in_error=True)
                except Exception:
                    pass
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                f"Unexpected error during connector execution: {err}",
                {"error": str(err)},
            )
            if work_id and hasattr(self.helper, "api") and hasattr(self.helper.api, "work"):
                try:
                    self.helper.api.work.to_processed(work_id, f"Error: {err}", in_error=True)
                except Exception:
                    pass

    def run(self) -> None:
        """Run the main connector process encapsulated in the OpenCTI scheduler."""
        self.helper.connector_logger.info(
            f"Starting {self.helper.connect_name} with schedule {self.duration_period}",
            {"duration_period": self.duration_period},
        )
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.duration_period,
        )

    def start(self) -> None:
        """Backward-compatible alias for run."""
        self.run()


if __name__ == "__main__":
    try:
        connector = DectraxConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
