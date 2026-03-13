# -*- coding: utf-8 -*-
"""IPQS enrichment module."""  # pylint: disable=invalid-name

import sys
import time
from os import path
from typing import Any, Dict, List

import stix2
from pycti import Identity as PyctiIdentity
from pycti import Note as PyctiNote
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Identity
from yaml import FullLoader, load

from ipqs.builder import IPQSBuilder  # pylint: disable=import-error
from ipqs.client import IPQSClient  # pylint: disable=import-error


class IPQSFileAnalyzerConnector:  # pylint: disable=too-many-instance-attributes
    """IPQS connector."""

    _SOURCE_NAME = "IPQS"
    _CONFIDENCE_LEVEL = 100

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = path.dirname(path.abspath(__file__)) + "/config.yml"

        if path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as f:
                config = load(f, Loader=FullLoader)
        else:
            config = {}
        self.helper = OpenCTIConnectorHelper(config)

        self.api_key = get_config_variable(
            "IPQS_ANALYZER_API_KEY", ["ipqs_analyzer", "api_key"], config
        )
        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )

        self.base_url = get_config_variable(
            "IPQS_ANALYZER_SERVER", ["ipqs_analyzer", "server"], config
        )

        default_tlp = get_config_variable(
            "IPQS_ANALYZER_DEFAULT_TLP", ["ipqs_analyzer", "default_tlp"], config
        ).lower()

        # map string values to stix2 constants; fallback to amber if unknown
        tlp_map = {
            "tlp:clear": stix2.TLP_WHITE,
            "tlp:white": stix2.TLP_WHITE,
            "tlp:green": stix2.TLP_GREEN,
            "tlp:amber": stix2.TLP_AMBER,
            "tlp:red": stix2.TLP_RED,
        }
        self.default_tlp = tlp_map.get(default_tlp, stix2.TLP_AMBER)
        self.default_tlp_string = default_tlp.upper().replace(
            "TLP:", "TLP:"
        )  # ensure format

        self.max_tlp = get_config_variable(
            "IPQS_ANALYZER_MAX_TLP",
            ["ipqs_analyzer", "max_tlp"],
            self.helper.config,
            default="TLP:AMBER",
        )

        self.author = Identity(
            id=PyctiIdentity.generate_id(self._SOURCE_NAME, "organization"),
            name=self._SOURCE_NAME,
            identity_class="organization",
            description="IPQS",
            confidence=self.helper.connect_confidence_level,
        )
        self.client = IPQSClient(self.helper, self.base_url, self.api_key)

    @staticmethod
    def flatten_json(
        data: Dict[str, Any],
        parent_key: str = "",
        sep: str = "_",
    ) -> Dict[str, Any]:
        """Recursively flatten nested dictionaries/lists into a single level.

        Keys are joined using ``sep``. Lists are indexed.
        """
        items: Dict[str, Any] = {}

        for key, value in data.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            if isinstance(value, dict):
                items.update(
                    IPQSFileAnalyzerConnector.flatten_json(value, new_key, sep)
                )
            elif isinstance(value, list):
                for idx, element in enumerate(value):
                    if isinstance(element, dict):
                        items.update(
                            IPQSFileAnalyzerConnector.flatten_json(
                                element, f"{new_key}{sep}{idx}", sep
                            )
                        )
                    else:
                        items[f"{new_key}{sep}{idx}"] = element
            else:
                items[new_key] = value
        return items

    def _process_file(self, observable):
        """Download the artifact and submit it to IPQS for enrichment."""
        if observable.get("entity_type") != "Artifact":
            raise ValueError(
                (
                    f"Failed to process observable, "
                    f"{observable.get('entity_type')} is not a supported "
                    "entity type."
                )
            )

        import_files = observable.get("importFiles")
        if (
            not import_files
            or not isinstance(import_files, list)
            or len(import_files) == 0
        ):
            self.helper.log_error("No importFiles found in observable. Skipping.")
            return

        file_info = import_files[0]
        file_name = file_info["name"]
        self.helper.log_info(f"Processing file observable: {file_name}")
        file_id = file_info["id"]
        file_uri = f"{self.octi_api_url}/storage/get/{file_id}"

        try:
            file_content = self.helper.api.fetch_opencti_file(file_uri, True)
            response = self.client.get_ipqs_info(
                file={"file": (file_name, file_content)}
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.helper.log_error(f"Failed to process file {file_name}: {e}")
            return

        if not response.get("success"):
            self._send_failure_note(response, observable)
            return
        engine = self.build_ipqs_result_summary(response)
        response = self.flatten_json(response)
        self._summarize_enrichment(response, observable, file_name, engine)

    def _process_url(self, observable):
        if observable.get("entity_type") != "Url":
            self.helper.log_error(
                (
                    f"Observable type {observable.get('entity_type')} "
                    "is not 'Url'. Skipping processing."
                )
            )
            return

        try:
            response = self.client.get_ipqs_info(
                params={
                    "url": observable["value"],
                }
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.helper.log_error(f"Error processing URL observable: {e}")
            return

        if not response.get("success"):
            self._send_failure_note(response, observable)
            return

        engine = self.build_ipqs_result_summary(response)
        response = self.flatten_json(response)
        self._summarize_enrichment(
            response,
            observable,
            observable["value"],
            engine,
        )

    def build_ipqs_result_summary(self, ipqs: Dict[str, Any]) -> str:
        """Return a formatted summary of each engine result.

        Falls back gracefully if data is missing or malformed.
        """
        lines: List[str] = []
        for engine in ipqs.get("result", []) or []:
            if not isinstance(engine, dict):
                continue
            name = engine.get("name", "Unknown Engine")
            detected = engine.get("detected", False)
            error = engine.get("error", False)
            lines.append(f"- {name}:    ")
            lines.append(f"    Detected - {detected} | ")
            lines.append(f"    Error    - {error}\n")
        return "\n".join(lines) if lines else "No engine results available."

    def _send_failure_note(
        self, response: Dict[str, Any], observable: Dict[str, Any]
    ) -> None:
        """Create and send a note object when the IPQS enrichment failed."""
        message = response.get("message", "")
        labels = ["enrichment-failed"]
        if "Invalid URL" in message:
            labels.append("ipqs-invalid-url")
        if "Could not download" in message:
            labels.append("ipqs-no-downloadable-file")

        content = f"IPQS enrichment failed: {message}"
        note_id = PyctiNote.generate_id(created=None, content=content)
        note = stix2.Note(
            id=note_id,
            content=content,
            object_refs=[observable["standard_id"]],
            created_by_ref=self.author,
            confidence=50,
            labels=labels,
        )
        self.helper.send_stix2_bundle(stix2.Bundle(note).serialize())

    def _summarize_enrichment(
        self,
        response: Dict[str, Any],
        observable: Dict[str, Any],
        indicator_value: str,
        engine_summary: str,
    ) -> None:
        """Build indicator from API response and send bundle."""
        builder = IPQSBuilder(
            self.helper, self.author, observable, self._CONFIDENCE_LEVEL
        )

        res_format = ""
        for field, label in self.client.file_enrich_fields.items():
            if field in response:
                res_format += f"- {label} :  {response.get(field)}\n"
        res_format += engine_summary

        file_sha256 = response.get("file_hash")
        if file_sha256:
            pattern = f"[file:hashes.'SHA-256' = '{file_sha256}']"
        else:
            pattern = None

        labels = builder.malware_file_detection(response.get("detected", False))
        builder.create_indicator_based_on(
            labels=labels,
            pattern=pattern,
            indicator_value=indicator_value,
            description=res_format,
            detection=response.get("detected", False),
        )
        # propagate reference to IPQS scan
        builder.add_reference(response, observable)
        builder.send_bundle()

    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]

        # determine TLP, defaulting to configured default if none present
        tlp = self.default_tlp_string
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition.get("definition_type") == "TLP":
                tlp = marking_definition.get(
                    "definition", self.default_tlp_string
                ).upper()
                break
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                ("Do not send any data, TLP of the observable is greater than MAX TLP")
            )

        otype = observable.get("entity_type")
        if otype == "Url":
            return self._process_url(observable)
        if otype == "Artifact":
            return self._process_file(observable)
        self.helper.log_error(
            (f"Observable type {otype} not supported for enrichment.")
        )
        return None

    # Start the main loop
    def start(self):
        """Main method to start."""
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        IPQSFileAnalyzerConnector().start()
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(e)
        time.sleep(10)
        sys.exit(1)
