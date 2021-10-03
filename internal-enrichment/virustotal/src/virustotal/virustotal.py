# -*- coding: utf-8 -*-
"""VirusTotal enrichment module."""
import datetime
import json
from pathlib import Path
from time import sleep
from typing import Optional

import plyara
import plyara.utils
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Indicator
import yaml

from .client import VirusTotalClient


class VirusTotalConnector:
    """VirusTotal connector."""

    _CONNECTOR_RUN_INTERVAL_SEC = 60 * 60
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

        self.client = VirusTotalClient(self._API_URL, token)

        # Cache to store YARA rulesets.
        self.yara_cache = {}

    def _create_yara_indicator(
        self, yara: dict, valid_from: Optional[int] = None
    ) -> Optional[Indicator]:
        """Create an indicator containing the YARA rule from VirusTotal."""
        valid_from_date = (
            datetime.datetime.min
            if valid_from is None
            else datetime.datetime.utcfromtimestamp(valid_from)
        )
        ruleset_id = yara.get("ruleset_id", "No ruleset id provided")
        self.helper.log_info(f"[VirusTotal] Retrieving ruleset {ruleset_id}")

        # Lookup in the cache for the ruleset id, otherwise, request VirusTotal API.
        if ruleset_id in self.yara_cache:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from cache.")
            ruleset = self.yara_cache[ruleset_id]
        else:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from API.")
            ruleset = self.client.get_yara_ruleset(ruleset_id)
            self.yara_cache[ruleset_id] = ruleset

        # Parse the rules to find the correct one.
        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset["data"]["attributes"]["rules"])
        rule_name = yara.get("rule_name", "No ruleset name provided")
        rule = [r for r in rules if r["rule_name"] == rule_name]
        if len(rule) == 0:
            self.helper.log_warning(f"No YARA rule for rule name {rule_name}")
            return None

        return self.helper.api.indicator.create(
            name=yara.get("rule_name", "No rulename provided"),
            description=json.dumps(
                {
                    "description": yara.get("description", "No description provided"),
                    "author": yara.get("author", "No author provided"),
                    "source": yara.get("source", "No source provided"),
                    "ruleset_id": ruleset_id,
                    "ruleset_name": yara.get(
                        "ruleset_name", "No ruleset name provided"
                    ),
                }
            ),
            pattern=plyara.utils.rebuild_yara_rule(rule[0]),
            pattern_type="yara",
            valid_from=self.helper.api.stix2.format_date(valid_from_date),
            x_opencti_main_observable_type="StixFile",
        )

    def _process_file(self, observable):
        json_data = self.client.get_file_info(observable["observable_value"])
        if json_data is None:
            raise ValueError("An error has occurred")
        if "error" in json_data:
            if json_data["error"]["message"] == "Quota exceeded":
                self.helper.log_info("Quota reached, waiting 1 hour.")
                sleep(self._CONNECTOR_RUN_INTERVAL_SEC)
            elif "not found" in json_data["error"]["message"]:
                self.helper.log_info("File not found on VirusTotal.")
                return "File not found on VirusTotal."
            else:
                raise ValueError(json_data["error"]["message"])
        if "data" in json_data:
            data = json_data["data"]
            attributes = data["attributes"]
            # Update the current observable
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=observable["id"],
                input={"key": "hashes.MD5", "value": attributes["md5"]},
            )
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=final_observable["id"],
                input={"key": "hashes.SHA-1", "value": attributes["sha1"]},
            )
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=final_observable["id"],
                input={"key": "hashes.SHA-256", "value": attributes["sha256"]},
            )
            if observable["entity_type"] == "StixFile":
                self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={"key": "size", "value": str(attributes["size"])},
                )
                if observable["name"] is None and len(attributes["names"]) > 0:
                    self.helper.api.stix_cyber_observable.update_field(
                        id=final_observable["id"],
                        input={"key": "name", "value": attributes["names"][0]},
                    )
                    del attributes["names"][0]

            if len(attributes["names"]) > 0:
                self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={
                        "key": "x_opencti_additional_names",
                        "value": attributes["names"],
                    },
                )

            # Create external reference
            external_reference = self.helper.api.external_reference.create(
                source_name="VirusTotal",
                url="https://www.virustotal.com/gui/file/" + attributes["sha256"],
                description=attributes["magic"],
            )

            # Create tags
            for tag in attributes["tags"]:
                tag_vt = self.helper.api.label.create(value=tag, color="#0059f7")
                self.helper.api.stix_cyber_observable.add_label(
                    id=final_observable["id"], label_id=tag_vt["id"]
                )

            self.helper.api.stix_cyber_observable.add_external_reference(
                id=final_observable["id"],
                external_reference_id=external_reference["id"],
            )

            if "crowdsourced_yara_results" in attributes:
                self.helper.log_info("[VirusTotal] adding yara results to file.")

                # Add YARA rules (only if a rule is given).
                yaras = list(
                    filter(
                        None,
                        [
                            self._create_yara_indicator(
                                yara, attributes.get("creation_date", None)
                            )
                            for yara in attributes["crowdsourced_yara_results"]
                        ],
                    )
                )

                self.helper.log_debug(f"[VirusTotal] Indicators created: {yaras}")

                # Create the relationships (`related-to`) between the yaras and the file.
                for yara in yaras:
                    self.helper.api.stix_core_relationship.create(
                        fromId=final_observable["id"],
                        toId=yara["id"],
                        relationship_type="related-to",
                    )

            return "File found on VirusTotal, knowledge attached."

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        return self._process_file(observable)

    def start(self):
        """Start the main loop."""
        self.helper.listen(self._process_message)
