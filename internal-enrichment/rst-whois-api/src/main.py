import ipaddress
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict
from urllib.parse import urlparse

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Note
from stix2.canonicalization.Canonicalize import canonicalize


class RSTWhoisApiConnector:
    def __init__(self):
        # Load config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.safe_load(open(config_file_path, encoding="UTF-8"))
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
        self.base_url = str(
            get_config_variable(
                "RST_WHOIS_API_BASE_URL",
                ["rst-whois-api", "base_url"],
                config,
                default="https://api.rstcloud.net/v1/",
            )
        )
        self.api_key = str(
            get_config_variable(
                "RST_WHOIS_API_API_KEY", ["rst-whois-api", "api_key"], config
            )
        )
        self.max_tlp = str(
            get_config_variable(
                "RST_WHOIS_API_MAX_TLP",
                ["rst-whois-api", "max_tlp"],
                config,
                default="TLP:AMBER+STRICT",
            )
        )

        self.domain_pattern = re.compile(r"value\s*=\s*(\'|\")([^\'\"]+)(\'|\")")

        self.whois_output_object = str(
            get_config_variable(
                "RST_WHOIS_API_WHOIS_OUTPUT_OBJECT",
                ["rst-whois-api", "whois_output_object"],
                config,
                default="note",
            ).lower()
        )

        self.update_output_action = str(
            get_config_variable(
                "RST_WHOIS_API_UPDATE_OUTPUT_ACTION",
                ["rst-whois-api", "update_output_action"],
                config,
                default="overwrite",
            ).lower()
        )

        self.output_format = str(
            get_config_variable(
                "RST_WHOIS_API_OUTPUT_FORMAT",
                ["rst-whois-api", "output_format"],
                config,
                default="standard",
            )
        ).lower()

        self.include_raw = bool(
            get_config_variable(
                "RST_WHOIS_API_OUTPUT_INCLUDE_RAW",
                ["rst-whois-api", "output_include_raw"],
                config,
                default=False,
            )
        )

        self.timeout = int(
            get_config_variable(
                "RST_WHOIS_API_TIMEOUT",
                ["rst-whois-api", "timeout"],
                config,
                default=10,
            )
        )

        self.connector_auto = bool(
            get_config_variable(
                "CONNECTOR_AUTO",
                ["connector", "auto"],
                config,
                default=False,
            )
        )

        self.helper.log_info(f"connector_auto {self.connector_auto}")

    @staticmethod
    def opencti_generate_id(obj_type, data):
        """to map objects into the correct IDs in OpenCTI"""
        data = canonicalize(data, utf8=False)
        opencti_uuid = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
        new_id = str(uuid.uuid5(opencti_uuid, data))
        return f"{obj_type}--{new_id}"

    @staticmethod
    def get_current_utc():
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def format_whois_data(self, whois_json, indent=0):
        """Formats hierarchical WHOIS JSON data as readable Markdown."""
        formatted = ""
        indent_space = "  " * indent  # Indentation for nested levels

        if isinstance(whois_json, dict):  # Handle dictionaries
            for key, value in whois_json.items():
                formatted += f"{indent_space}- **{key}**:\n"
                formatted += self.format_whois_data(value, indent + 1)  # Recursive call

        elif isinstance(whois_json, list):  # Handle lists
            for item in whois_json:
                formatted += (
                    f"{indent_space}- {self.format_whois_data(item, indent + 1)}\n"
                )

        else:  # Handle string, number, or other primitive types
            formatted += f"{indent_space}  {whois_json}\n"

        return formatted

    @staticmethod
    def is_valid_ipv4(text):
        try:
            return isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address)
        except ValueError:
            return False

    @staticmethod
    def is_valid_ipv6(text):
        try:
            return isinstance(ipaddress.ip_address(text), ipaddress.IPv6Address)
        except ValueError:
            return False

    def get_valid_domain(self, candidate):
        try:
            hostname = urlparse(candidate).hostname
            if self.is_valid_ipv6(hostname) or self.is_valid_ipv4(hostname):
                return None
            else:
                return hostname
        except ValueError:
            return None

    def update_stix_object(self, value, stix_objects, whois_json):
        """
        Updates a STIX Indicator, ObservedData, or Note with WHOIS data.

        :param stix_obj: STIX object (Indicator, ObservedData, or Note)
        :param whois_json: WHOIS data in JSON format
        :return: Updated STIX object (or new Note if applicable)
        """
        formatted_whois = self.format_whois_data(whois_json)
        marking_ids = []
        stix_obj = {}
        # stix_objects contains one entity to be enriches and one or many marking definitions
        for obj in stix_objects:
            if obj["type"] == "marking-definition":
                marking_ids.append(obj["id"])
            else:
                stix_obj = obj

        if stix_obj["type"] in ["domain-name", "url", "indicator"]:
            if self.whois_output_object == "description":
                desc_name = (
                    "description"
                    if stix_obj["type"] == "indicator"
                    else "x_opencti_description"
                )
                stix_obj.setdefault(desc_name, "")
                if self.update_output_action == "overwrite":
                    stix_obj[desc_name] = formatted_whois
                elif self.update_output_action == "append":
                    stix_obj[desc_name] = f"{stix_obj[desc_name]}\n\n{formatted_whois}"
                return stix_obj

            elif self.whois_output_object == "note":
                if self.update_output_action == "overwrite":
                    abstract = f"Whois Data for {value}"
                elif self.update_output_action == "append":
                    run_time_str = self.get_current_utc()
                    abstract = f"Whois Data for {value} on {run_time_str}"
                obj_id = self.opencti_generate_id("note", abstract)
                note = Note(
                    id=obj_id,
                    abstract=abstract,
                    content=formatted_whois,
                    object_refs=[stix_obj["id"]],
                    object_marking_refs=marking_ids,
                )
                return note  # Return a new Note object

        elif stix_obj["type"] == "note":
            stix_obj["content"] = formatted_whois
            return stix_obj

        return None  # Invalid object type

    def _process_message(self, data: Dict) -> str:
        opencti_entity = data["enrichment_entity"]

        # if not specified assign TLP:WHITE
        tlp = "TLP:WHITE"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError("TLP of the value is greater than MAX TLP")

        self.helper.log_debug(f"Data Entity {data}")

        # get whois for a Domain or the hostname part of a URL
        value = ""

        if opencti_entity["entity_type"] == "Domain-Name":
            value = opencti_entity["value"]
        elif opencti_entity["entity_type"] == "Url":
            # opencti_entity whois for a URL
            value = self.get_valid_domain(opencti_entity["value"])
        elif (
            opencti_entity["entity_type"] == "Indicator"
            and opencti_entity.get("x_opencti_main_observable_type", "")
            == "Domain-Name"
        ):
            # Extract the domain name using regex
            match = self.domain_pattern.search(opencti_entity["pattern"])
            value = match.group(2) if match else None
        elif (
            opencti_entity["entity_type"] == "Indicator"
            and opencti_entity.get("x_opencti_main_observable_type", "") == "Url"
        ):
            # Extract the domain name using regex
            match = self.domain_pattern.search(opencti_entity["pattern"])
            value = self.get_valid_domain(match.group(2)) if match else None
        else:
            value = None

        if not value:
            return "[CONNECTOR] Nothing to check"

        if self.output_format not in ["standard", "extended"]:
            raise ValueError(
                "Unsupported output format selected. Use 'standard' or 'extended'"
            )
        if self.update_output_action not in ["append", "overwrite"]:
            raise ValueError(
                "Unsupported output action selected. Use 'append' or 'overwrite'"
            )
        if self.whois_output_object not in ["note", "description"]:
            raise ValueError(
                "Unsupported output object selected. "
                "Use 'note' to use a Note object or 'description' "
                "to update this field in Indicators or Observables'"
            )
        if self.include_raw and self.output_format == "standard":
            # the standard format but with raw field
            url = self.base_url + "/whois/raw/"
        elif self.include_raw and self.output_format == "extended":
            # the extended format with raw field
            url = self.base_url + "/whois/full/raw/"
        elif self.output_format == "extended":
            # the extended format
            url = self.base_url + "/whois/full/"
        else:
            # the standard format by default
            url = self.base_url + "/whois/"

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "opencti_rst_whois_api",
            "x-api-key": self.api_key,
        }
        url = url + value
        self.helper.log_debug(f"Requesting url: {url}")
        r = requests.get(url, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        resp = r.json()
        if "dataError" in resp or "domain" in resp:
            self.helper.log_debug(f"Response {resp}")
            stix_objects = data["stix_objects"]
            stix_object = self.update_stix_object(value, stix_objects, resp)
            self.helper.log_debug(f"Result {stix_object}")
            serialized_bundle = self.helper.stix2_create_bundle([stix_object])
            self.helper.send_stix2_bundle(serialized_bundle)
            return (
                f"[CONNECTOR] Sent STIX bundle to update for {value.replace('.','[.]')}"
            )
        else:
            return "[CONNECTOR] No changes required"

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    RSTWhoisApiInstance = RSTWhoisApiConnector()
    RSTWhoisApiInstance.start()
