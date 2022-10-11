# -*- coding: utf-8 -*-
"""VirusTotal enrichment module."""
import json
from pathlib import Path

import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .builder import VirusTotalBuilder
from .client import VirusTotalClient
from .indicator_config import IndicatorConfig


class VirusTotalConnector:
    """VirusTotal connector."""

    _SOURCE_NAME = "VirusTotal"
    _API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"

        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        token = get_config_variable("VIRUSTOTAL_TOKEN", ["virustotal", "token"], config)
        self.max_tlp = get_config_variable(
            "VIRUSTOTAL_MAX_TLP", ["virustotal", "max_tlp"], config
        )
        self.author = stix2.Identity(
            name=self._SOURCE_NAME,
            identity_class="Organization",
            description="VirusTotal",
            confidence=self.helper.connect_confidence_level,
        )

        self.client = VirusTotalClient(self.helper, self._API_URL, token)

        # Cache to store YARA rulesets.
        self.yara_cache = {}

        self.bundle = [self.author]

        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            True,
        )

        # File/Artifact specific settings
        self.file_create_note_full_report = get_config_variable(
            "VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT",
            ["virustotal", "file_create_note_full_report"],
            config,
        )
        self.file_indicator_config = IndicatorConfig.load_indicator_config(
            config, "FILE"
        )

        # IP specific settings
        self.ip_indicator_config = IndicatorConfig.load_indicator_config(config, "IP")

        # Domain specific settings
        self.domain_indicator_config = IndicatorConfig.load_indicator_config(
            config, "DOMAIN"
        )

        # Url specific settings
        self.url_indicator_config = IndicatorConfig.load_indicator_config(config, "URL")

    def _retrieve_yara_ruleset(self, ruleset_id: str) -> dict:
        """
        Retrieve yara ruleset.

        If the yara is not in the cache, make an API call.

        Returns
        -------
        dict
            YARA ruleset object.
        """
        self.helper.log_debug(f"[VirusTotal] Retrieving ruleset {ruleset_id}")
        if ruleset_id in self.yara_cache:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from cache.")
            ruleset = self.yara_cache[ruleset_id]
        else:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from API.")
            ruleset = self.client.get_yara_ruleset(ruleset_id)
            self.yara_cache[ruleset_id] = ruleset
        return ruleset

    def _process_file(self, observable):
        json_data = self.client.get_file_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, observable, json_data["data"]
        )

        builder.update_hashes()

        # Set the size and names (main and additional)
        if observable["entity_type"] == "StixFile":
            builder.update_size()

        builder.update_names(
            observable["entity_type"] == "StixFile"
            and (observable["name"] is None or len(observable["name"]) == 0)
        )

        builder.create_indicator_based_on(
            self.file_indicator_config,
            f"""[file:hashes.'SHA-256' = '{json_data["data"]["attributes"]["sha256"]}']""",
        )

        # Create labels from tags
        builder.update_labels()

        # Add YARA rules (only if a rule is given).
        for yara in json_data["data"]["attributes"].get(
            "crowdsourced_yara_results", []
        ):
            ruleset = self._retrieve_yara_ruleset(
                yara.get("ruleset_id", "No ruleset id provided")
            )
            builder.create_yara(
                yara,
                ruleset,
                json_data["data"]["attributes"].get("creation_date", None),
            )

        # Create a Note with the full report
        if self.file_create_note_full_report:
            builder.create_note(
                "VirusTotal Report", f"```\n{json.dumps(json_data, indent=2)}\n```"
            )
        return builder.send_bundle()

    def _process_ip(self, observable):
        json_data = self.client.get_ip_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, observable, json_data["data"]
        )

        builder.create_asn_belongs_to()
        builder.create_location_located_at()

        builder.create_indicator_based_on(
            self.ip_indicator_config,
            f"""[ipv4-addr:value = '{observable["observable_value"]}']""",
        )
        builder.create_notes()
        return builder.send_bundle()

    def _process_domain(self, observable):
        json_data = self.client.get_domain_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, observable, json_data["data"]
        )

        # Create IPv4 address observables for each A record
        # and a Relationship between them and the observable.
        for ip in [
            r["value"]
            for r in json_data["data"]["attributes"]["last_dns_records"]
            if r["type"] == "A"
        ]:
            self.helper.log_debug(
                f'[VirusTotal] adding ip {ip} to domain {observable["observable_value"]}'
            )
            builder.create_ip_resolves_to(ip)

        builder.create_indicator_based_on(
            self.domain_indicator_config,
            f"""[domain-name:value = '{observable["observable_value"]}']""",
        )
        builder.create_notes()
        return builder.send_bundle()

    def _process_url(self, observable):
        json_data = self.client.get_url_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, observable, json_data["data"]
        )

        builder.create_indicator_based_on(
            self.ip_indicator_config,
            f"""[url:value = '{observable["observable_value"]}']""",
        )
        builder.create_notes()
        return builder.send_bundle()

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, "
                "check the group of the connector user)"
            )

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        self.helper.log_debug(
            f"[VirusTotal] starting enrichment of observable: {observable}"
        )
        match observable["entity_type"]:
            case "StixFile" | "Artifact":
                return self._process_file(observable)
            case "IPv4-Addr":
                return self._process_ip(observable)
            case "Domain-Name":
                return self._process_domain(observable)
            case "Url":
                return self._process_url(observable)
            case _:
                raise ValueError(
                    f'{observable["entity_type"]} is not a supported entity type.'
                )

    def start(self):
        """Start the main loop."""
        self.helper.listen(self._process_message)
