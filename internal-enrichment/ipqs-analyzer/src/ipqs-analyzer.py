# -*- coding: utf-8 -*-
"""IPQS enrichment module."""  # pylint: disable=invalid-name

import sys
import time
import traceback
from os import path
from typing import Any, Dict, List, Optional

import stix2
from ipqs.builder import IPQSBuilder  # pylint: disable=import-error
from ipqs.client import IPQSClient  # pylint: disable=import-error
from pycti import Identity as PyctiIdentity
from pycti import Note as PyctiNote
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Identity
from yaml import FullLoader, load


def _flatten_json(
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
            items.update(_flatten_json(value, new_key, sep))
        elif isinstance(value, list):
            for idx, element in enumerate(value):
                if isinstance(element, dict):
                    items.update(_flatten_json(element, f"{new_key}{sep}{idx}", sep))
                else:
                    items[f"{new_key}{sep}{idx}"] = element
        else:
            items[new_key] = value
    return items


def _normalize_tlp(value: Optional[str], fallback: str = "TLP:CLEAR") -> str:
    """Normalize a TLP marking string to OpenCTI's ``TLP:LEVEL`` format."""
    if not value or not isinstance(value, str):
        return fallback
    normalized = value.strip().upper()
    if not normalized.startswith("TLP:"):
        normalized = f"TLP:{normalized}"
    return normalized


class IPQSFileAnalyzerConnector:  # pylint: disable=too-many-instance-attributes
    """IPQS connector."""

    _SOURCE_NAME = "IPQS"
    _DEFAULT_SCORE = 50
    _MALICIOUS_SCORE = 100

    _TLP_MAP = {
        "TLP:CLEAR": stix2.TLP_WHITE,
        "TLP:WHITE": stix2.TLP_WHITE,
        "TLP:GREEN": stix2.TLP_GREEN,
        "TLP:AMBER": stix2.TLP_AMBER,
        "TLP:AMBER+STRICT": stix2.TLP_AMBER,
        "TLP:RED": stix2.TLP_RED,
    }

    def __init__(self):
        config_file_path = path.dirname(path.abspath(__file__)) + "/config.yml"
        if path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as f:
                config = load(f, Loader=FullLoader)
        else:
            config = {}
        self.helper = OpenCTIConnectorHelper(config)

        self.api_key = get_config_variable(
            "IPQS_ANALYZER_API_KEY",
            ["ipqs_analyzer", "api_key"],
            config,
            required=True,
        )
        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config, required=True
        )
        self.base_url = get_config_variable(
            "IPQS_ANALYZER_SERVER",
            ["ipqs_analyzer", "server"],
            config,
            default="https://www.ipqualityscore.com/api/json",
        )

        self.default_tlp_string = _normalize_tlp(
            get_config_variable(
                "IPQS_ANALYZER_DEFAULT_TLP",
                ["ipqs_analyzer", "default_tlp"],
                config,
                default="TLP:CLEAR",
            )
        )
        self.default_tlp = self._TLP_MAP.get(self.default_tlp_string, stix2.TLP_AMBER)

        self.max_tlp = _normalize_tlp(
            get_config_variable(
                "IPQS_ANALYZER_MAX_TLP",
                ["ipqs_analyzer", "max_tlp"],
                config,
                default="TLP:AMBER",
            )
        )

        self.author = Identity(
            id=PyctiIdentity.generate_id(self._SOURCE_NAME, "organization"),
            name=self._SOURCE_NAME,
            identity_class="organization",
            description="IPQualityScore (IPQS)",
            confidence=self.helper.connect_confidence_level,
        )
        self.client = IPQSClient(self.helper, self.base_url, self.api_key)

    @staticmethod
    def _is_detected(response: Dict[str, Any]) -> bool:
        """Return ``True`` if at least one engine result reports a detection."""
        results = response.get("result", [])
        if not isinstance(results, list):
            return False
        for item in results:
            if isinstance(item, dict) and item.get("detected") is True:
                return True
        return False

    @staticmethod
    def _build_result_summary(response: Dict[str, Any]) -> str:
        """Return a formatted summary of each engine result.

        Falls back gracefully if data is missing or malformed.
        """
        lines: List[str] = []
        for engine in response.get("result", []) or []:
            if not isinstance(engine, dict):
                continue
            name = engine.get("name", "Unknown Engine")
            detected = engine.get("detected", False)
            error = engine.get("error", False)
            lines.append(f"- {name}:    ")
            lines.append(f"    Detected - {detected} | ")
            lines.append(f"    Error    - {error}\n")
        return "\n".join(lines) if lines else "No engine results available."

    def _get_observable_marking_refs(self, observable: Dict[str, Any]) -> List[str]:
        """Extract marking IDs from an enrichment observable.

        Falls back to the connector's configured default TLP when none are
        present so that downstream STIX objects are never accidentally
        unmarked.
        """
        refs: List[str] = []
        raw_markings = observable.get("objectMarking")
        if raw_markings is None:
            raw_markings = observable.get("object_marking_refs")
        if isinstance(raw_markings, list):
            for marking in raw_markings:
                if isinstance(marking, dict) and "standard_id" in marking:
                    refs.append(marking["standard_id"])
                elif isinstance(marking, str):
                    refs.append(marking)
        if not refs and self.default_tlp is not None:
            refs.append(self.default_tlp["id"])
        return refs

    def _process_file(self, observable: Dict[str, Any]) -> None:
        """Download the artifact and submit it to IPQS for enrichment."""
        if observable.get("entity_type") != "Artifact":
            raise ValueError(
                f"Failed to process observable, {observable.get('entity_type')} "
                "is not a supported entity type."
            )

        import_files = observable.get("importFiles")
        if not isinstance(import_files, list) or not import_files:
            self.helper.log_error(
                "No importFiles found in observable; skipping enrichment."
            )
            return

        file_info = import_files[0]
        file_name = file_info.get("name")
        file_id = file_info.get("id")
        if not file_id or not file_name:
            self.helper.log_error(
                "Artifact import file is missing 'id' or 'name'; skipping."
            )
            return

        self.helper.log_info(f"Processing file observable: {file_name}")
        file_uri = f"{self.octi_api_url}/storage/get/{file_id}"

        try:
            file_content = self.helper.api.fetch_opencti_file(file_uri, True)
            response = self.client.get_ipqs_info(
                file={"file": (file_name, file_content)}
            )
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.helper.log_error(f"Failed to process file {file_name}: {error}")
            return

        if response is None:
            self.helper.log_error(
                f"No response received from IPQS for file {file_name}; "
                "skipping enrichment."
            )
            self._send_failure_note(
                {
                    "success": False,
                    "message": "No response received from IPQS API.",
                },
                observable,
            )
            return
        if not response.get("success"):
            self._send_failure_note(response, observable)
            return

        engine_summary = self._build_result_summary(response)
        detected = self._is_detected(response)
        score = self._MALICIOUS_SCORE if detected else self._DEFAULT_SCORE
        flat_response = _flatten_json(response)
        self._summarize_enrichment(
            response,
            flat_response,
            observable,
            file_name,
            engine_summary,
            score,
            detected,
        )

    def _process_url(self, observable: Dict[str, Any]) -> None:
        """Submit a URL observable to IPQS for enrichment."""
        if observable.get("entity_type") != "Url":
            self.helper.log_error(
                f"Observable type {observable.get('entity_type')} is not 'Url'; "
                "skipping processing."
            )
            return

        url_value = observable.get("value")
        if not url_value:
            self.helper.log_error(
                "URL observable is missing 'value'; skipping enrichment."
            )
            return

        try:
            response = self.client.get_ipqs_info(params={"url": url_value})
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.helper.log_error(f"Error processing URL observable: {error}")
            return

        if response is None:
            self.helper.log_error(
                f"No response received from IPQS for URL {url_value}; "
                "skipping enrichment."
            )
            self._send_failure_note(
                {
                    "success": False,
                    "message": "No response received from IPQS API.",
                },
                observable,
            )
            return

        if not isinstance(response, dict):
            self.helper.log_error(
                "IPQS client returned an invalid or empty response for URL observable."
            )
            return

        if not response.get("success"):
            self._send_failure_note(response, observable)
            return

        engine_summary = self._build_result_summary(response)
        detected = self._is_detected(response)
        score = self._MALICIOUS_SCORE if detected else self._DEFAULT_SCORE
        flat_response = _flatten_json(response)
        self._summarize_enrichment(
            response,
            flat_response,
            observable,
            url_value,
            engine_summary,
            score,
            detected,
        )

    def _send_failure_note(
        self,
        response: Dict[str, Any],
        observable: Dict[str, Any],
    ) -> None:
        """Create and send a Note object when the IPQS enrichment failed."""
        message = response.get("message", "")
        labels = ["enrichment-failed"]
        if "Invalid URL" in message:
            labels.append("ipqs-invalid-url")
        if "Could not download" in message:
            labels.append("ipqs-no-downloadable-file")

        content = f"IPQS enrichment failed: {message}"
        note_id = PyctiNote.generate_id(created=None, content=content)
        object_marking_refs = self._get_observable_marking_refs(observable)
        note = stix2.Note(
            id=note_id,
            abstract="IPQS enrichment failed",
            content=content,
            object_refs=[observable["standard_id"]],
            created_by_ref=self.author,
            confidence=self.helper.connect_confidence_level,
            labels=labels,
            object_marking_refs=object_marking_refs,
        )
        self.helper.send_stix2_bundle(
            stix2.Bundle(self.author, note, allow_custom=True).serialize()
        )

    def _default_marking_refs(self) -> List[str]:
        """Return the configured default marking reference as a list."""
        if self.default_tlp is None:
            return []
        return [self.default_tlp["id"]]

    def _summarize_enrichment(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        response: Dict[str, Any],
        flat_response: Dict[str, Any],
        observable: Dict[str, Any],
        indicator_value: str,
        engine_summary: str,
        score: int,
        detected: bool,
    ) -> None:
        """Build an Indicator from the IPQS response and send the bundle."""
        builder = IPQSBuilder(
            helper=self.helper,
            author=self.author,
            observable=observable,
            score=score,
            default_object_marking_refs=self._default_marking_refs(),
        )

        description_lines: List[str] = []
        for field, label in self.client.file_enrich_fields.items():
            if field in flat_response:
                description_lines.append(f"- {label} :  {flat_response.get(field)}")
        description = "\n".join(description_lines + [engine_summary])

        pattern = self._build_pattern(flat_response, observable, indicator_value)
        labels = builder.malware_file_detection(detected)

        if pattern is not None:
            builder.create_indicator_based_on(
                labels=labels,
                pattern=pattern,
                indicator_value=indicator_value,
                description=description,
                detection=detected,
            )
        else:
            self.helper.log_warning(
                "[IPQS] Could not build a STIX pattern for the observable; "
                "no indicator will be created."
            )

        builder.add_reference(response, observable)
        builder.send_bundle()

    @staticmethod
    def _build_pattern(
        flat_response: Dict[str, Any],
        observable: Dict[str, Any],
        indicator_value: str,
    ) -> Optional[str]:
        """Return a STIX pattern based on the observable type and IPQS data.

        Returns ``None`` if no valid pattern can be built (in which case the
        caller should skip indicator creation).
        """
        entity_type = observable.get("entity_type")
        if entity_type == "Artifact":
            file_sha256 = flat_response.get("file_hash")
            if file_sha256:
                return f"[file:hashes.'SHA-256' = '{file_sha256}']"
            return None
        if entity_type == "Url" and indicator_value:
            safe_value = indicator_value.replace("\\", "\\\\").replace("'", "\\'")
            return f"[url:value = '{safe_value}']"
        return None

    def _process_message(self, data: Dict[str, Any]) -> Optional[None]:
        """Entry point called by the connector helper for each enrichment job."""
        observable = data["enrichment_entity"]

        tlp = self.default_tlp_string
        for marking_definition in observable.get("objectMarking", []) or []:
            if marking_definition.get("definition_type") == "TLP":
                tlp = _normalize_tlp(
                    marking_definition.get("definition"),
                    fallback=self.default_tlp_string,
                )
                break

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        entity_type = observable.get("entity_type")
        if entity_type == "Url":
            return self._process_url(observable)
        if entity_type == "Artifact":
            return self._process_file(observable)
        self.helper.log_error(
            f"Observable type {entity_type} not supported for enrichment."
        )
        return None

    def start(self) -> None:
        """Start listening for enrichment messages."""
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        IPQSFileAnalyzerConnector().start()
    except Exception:  # pylint: disable=broad-exception-caught
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
