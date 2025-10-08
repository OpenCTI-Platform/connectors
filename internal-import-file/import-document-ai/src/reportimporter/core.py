"""
===============================================================================
OpenCTI ImportDocumentAI Connector – Core Logic
===============================================================================

Description:
    This module implements the core processing logic for the ImportDocumentAI
    connector. It manages the full lifecycle of document ingestion from the
    OpenCTI platform, including:

        - Secure file retrieval via the OpenCTI API.
        - Text and metadata extraction (with optional OCR).
        - Parsing of structured entities and relationships via Ariane or OpenAI.
        - Construction, validation, and submission of STIX 2.1 bundles.

    The connector automatically links extracted objects into contextual
    containers (e.g., Reports, Groupings, or Cases) and enforces allowed
    relationship rules defined in `relations_allowed.py`.

Key Classes:
    ReportImporter: Main connector class handling extraction, parsing,
                    and STIX bundle assembly.

===============================================================================
"""

# Standard library
import base64
import hashlib
import json
import os
import random
import re
import sys
import threading
import time
import traceback
from collections import OrderedDict
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import requests.exceptions as req_exc
import stix2
from pycti import OpenCTIConnectorHelper, Report, StixCoreRelationship
from reportimporter.configparser import ConfigParser
from reportimporter.openai import OpenAIHelper
from reportimporter.preprocessor import (
    FilePreprocessor,
)
from reportimporter.preprocessor import set_helper as set_preproc_helper
from reportimporter.relations_allowed import (
    is_relation_allowed,
    load_allowed_relations,
    stix_lookup_type,
)
from reportimporter.util import (
    compose_indicators_from_observables,
    create_stix_object,
)
from reportimporter.util import set_helper as set_util_helper
from stix2.exceptions import STIXError

# Type aliases and constants
RESULT_FORMAT_TYPE = "type"
RESULT_FORMAT_CATEGORY = "category"
RESULT_FORMAT_MATCH = "match"
STIX_ID_PATTERN = re.compile(r"^[a-z0-9-]+--[0-9a-f-]{36}$")
STIXObject = dict[str, Any]
RelationItem = dict[str, Any]


class ReportImporter:
    """
    OpenCTI connector for importing and parsing threat intelligence reports.

    Handles file retrieval, text extraction, parsing via AI or web service,
    and STIX bundle creation and submission.
    """

    def __init__(self, config: dict | None = None) -> None:
        """
        Initialize the connector.

        Args:
            config: Optional configuration dictionary. If None, loads from environment.
        """
        try:
            self.config: ConfigParser = ConfigParser(config)
        except ValueError as e:
            print(
                f"FATAL: Failed to initialize configuration: {e}",
                file=sys.stderr,
                flush=True,
            )
            sys.exit(0)

        self.helper: OpenCTIConnectorHelper = OpenCTIConnectorHelper(
            self.config._config
        )
        set_util_helper(self.helper)
        set_preproc_helper(self.helper)

        self.data_file = None
        self.create_indicator = self.config.create_indicator

        # Cache and runtime settings
        self._attack_pattern_cache: dict[str, dict] = {}
        self._attack_pattern_last_refresh: float = 0
        self._attack_pattern_ttl: int = 86400
        self._attack_pattern_lock = threading.Lock()

        # Retry policy
        self.max_retries = int(getattr(self.config, "max_retries", 3))
        self.backoff_base = int(getattr(self.config, "retry_backoff_base", 2))

        # Instance ID for header authentication
        self.instance_id = (
            self.helper.api.query(
                """
                query SettingsQuery {
                    settings { id }
                }
                """
            )
            .get("data", {})
            .get("settings", {})
            .get("id", "")
        )

        # Cache OpenCTI “allowed relationship” matrix
        # Loading this mapping costs one GraphQL call at startup,
        # and subsequent lookups are constant time in Python dict.
        try:
            self.allowed_relations = load_allowed_relations(self.helper)
        except Exception as err:
            self.helper.connector_logger.warning(
                f"Failed to load allowed relations mapping: {err}"
            )
            self.allowed_relations = {}

    @staticmethod
    def _sanitise_name(raw_text: Optional[str]) -> Optional[str]:
        """Trim and normalize text; return None if too short."""
        if not raw_text:
            return None
        cleaned = raw_text.strip().rstrip(",")
        return cleaned if len(cleaned) >= 2 else None

    def _process_message(self, data: dict) -> str:
        """Entry point when a new message arrives on the connector’s queue.

        Args:
            data (dict): Payload from OpenCTI

        Returns:
            str: A human-readable summary of what was imported or why it was skipped.
        """
        self.helper.connector_logger.info("Processing new message")
        self.data_file: dict | None = None
        try:
            return self._process_import(data)
        except Exception as e:
            tb = traceback.format_exc()
            self.helper.connector_logger.error(
                f"[FATAL] Unexpected failure in _process_import: {e}\n{tb}"
            )
            return f"Fatal error during processing: {e}"

    def _validate_import_request(self, data: dict) -> bool:
        """Validate the import message has required, non-empty fields.

        Args:
            data (dict): Import message payload from OpenCTI.

        Returns:
            bool: True if the payload is valid, False otherwise.
        """
        if not isinstance(data, dict):
            self.helper.connector_logger.error("Import data must be a dict.")
            return False

        required_keys = ("file_id", "file_fetch", "file_mime")
        missing_or_empty = [
            k
            for k in required_keys
            if k not in data or not isinstance(data[k], str) or not data[k].strip()
        ]

        if missing_or_empty:
            self.helper.connector_logger.error(
                f"Import data missing required fields: {missing_or_empty}"
            )
            return False

        return True

    def _extract_and_parse_file(
        self,
        data: dict,
        file_name: str,
        file_buffer,
        trace_id: str,
    ) -> Optional[dict]:
        """Extract text and structured entities from an imported document.

        Performs text extraction (via _extract_text_and_meta) followed by parsing
        using OpenAI or an external web service.
        """
        try:
            _, _, file_text, _ = self._extract_text_and_meta(
                data, file_name, file_buffer
            )
        except Exception as e:
            self.helper.connector_logger.error(
                f"[TRACE {trace_id}] [EXTRACT] Text extraction failed: {e}"
            )
            return None

        doc_hash = hashlib.sha256(
            file_text.encode("utf-8", errors="ignore")
        ).hexdigest()
        self.helper.connector_logger.info(
            f"[TRACE {trace_id}] [EXTRACT] Text extracted successfully "
            f"(chars={len(file_text)}, hash={doc_hash})"
        )

        parsed = None

        # --- OpenAI path ---
        if self.config.is_azure_openai or self.config.is_openai:
            self.helper.connector_logger.info(
                f"[TRACE {trace_id}] [PARSE] Using provider={self.config.ai_provider}, "
                f"model={self.config.ai_model}, "
                f"deployment={self.config.openai_deployment if self.config.is_azure_openai else 'n/a'}"
            )
            try:
                openai_helper = OpenAIHelper(
                    config=self.config, opencti_connector_helper=self.helper
                )
                parsed = openai_helper.openai_extract_relations(file_text)
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[TRACE {trace_id}] [PARSE] OpenAI extraction failed: {e}"
                )
                return None

        # --- Web service path ---
        else:
            self.helper.connector_logger.info(
                f"[TRACE {trace_id}] [PARSE] Using provider={self.config.ai_provider}"
            )
            for attempt in range(self.max_retries):
                try:
                    file_buffer.seek(0)
                    response = requests.post(
                        url=f"{self.config.web_service_url}/extract_entities_relations",
                        files={
                            "file": (
                                data["file_id"],
                                file_buffer,
                                data["file_mime"],
                            )
                        },
                        headers={
                            "X-OpenCTI-Certificate": self.config.licence_key_base64,
                            "X-OpenCTI-instance-id": self.instance_id,
                        },
                        timeout=180,
                    )
                    response.raise_for_status()
                    parsed = response.json()
                    self.helper.connector_logger.info(
                        f"[TRACE {trace_id}] [PARSE] Webservice parse successful (attempt {attempt + 1})."
                    )
                    break
                except json.JSONDecodeError as e:
                    self.helper.connector_logger.error(
                        f"[TRACE {trace_id}] [PARSE] Invalid JSON from webservice (attempt {attempt + 1}): {e}"
                    )
                    parsed = None
                except (
                    req_exc.ConnectionError,
                    req_exc.HTTPError,
                    req_exc.Timeout,
                    req_exc.RequestException,
                ) as e:
                    self.helper.connector_logger.error(
                        f"[TRACE {trace_id}] [PARSE] Webservice error (attempt {attempt + 1}): {e}"
                    )
                    if attempt < self.max_retries - 1:
                        delay = min(self.backoff_base**attempt, 8) + random.uniform(
                            0, 1
                        )
                        self.helper.connector_logger.debug(
                            f"[TRACE {trace_id}] [PARSE] Retrying after {delay:.2f}s backoff"
                        )
                        time.sleep(delay)
                    else:
                        self.helper.connector_logger.error(
                            f"[TRACE {trace_id}] [PARSE] All retry attempts exhausted."
                        )
                        return None

        if not parsed:
            self.helper.connector_logger.warning(
                f"[TRACE {trace_id}] [PARSE] No structured data extracted from report."
            )
        else:
            self.helper.connector_logger.info(
                f"[TRACE {trace_id}] [PARSE] Extraction and parsing completed successfully."
            )

        return parsed

    def _download_import_file(self, data: Dict) -> Tuple[str, BytesIO]:
        """Download and validate a file from OpenCTI for import.

        This function fetches the binary file referenced in the import message,
        validates it, and returns its name and an in-memory buffer.

        Args:
            data (Dict): Import message containing the file metadata and URL.

        Returns:
            Tuple[str, BytesIO]: (file_name, in-memory buffer).

        Raises:
            ValueError: If required metadata is missing or the file is empty.
            RuntimeError: If the download operation fails.
        """
        if not self._validate_import_request(data):
            raise ValueError("Invalid import data: missing required keys")

        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch
        file_name = os.path.basename(file_fetch)

        self.helper.connector_logger.info(f"Importing file {file_uri}")

        try:
            file_content = self.helper.api.fetch_opencti_file(file_uri, True)
        except Exception as e:
            raise RuntimeError(f"Failed to download file {file_uri}: {e}") from e

        if not file_content:
            raise ValueError(f"Downloaded file {file_name} is empty")

        file_buffer = BytesIO(file_content)
        file_buffer.seek(0)
        return file_name, file_buffer

    @staticmethod
    def _trace_id_for(data: dict) -> str:
        """Generate short trace ID from file_id or timestamp."""
        source = data.get("file_id") or str(time.time())
        return hashlib.sha1(source.encode("utf-8")).hexdigest()[:8]

    def _process_import(self, data: Dict) -> str:
        """Main entry point for processing a single file import.

        Handles the full ingestion lifecycle: file download, text extraction,
        parsing via OpenAI or web service, and STIX bundle submission.

        Args:
            data (Dict): Import message payload from OpenCTI.

        Returns:
            str: Human-readable status message for the connector runtime.
        """
        trace_id = self._trace_id_for(data)
        self.helper.connector_logger.info(
            f"[TRACE {trace_id}] Begin processing {data.get('file_id')}"
        )

        if not self._validate_import_request(data):
            return f"[TRACE {trace_id}] Invalid import message: required file metadata missing"

        bypass_validation = bool(data.get("bypass_validation", False))

        try:
            file_name, file_buffer = self._download_import_file(data)
        except Exception as e:
            self.helper.connector_logger.error(
                f"[TRACE {trace_id}] File download failed: {e}"
            )
            if bypass_validation:
                return f"[TRACE {trace_id}] ERROR: File download failed (bypass active): {e}"
            return f"[TRACE {trace_id}] ERROR: File download failed: {e}"

        entity_id = data.get("entity_id")
        entity = (
            self.helper.api.stix_core_object.read(id=entity_id) if entity_id else None
        )

        if self.helper.get_only_contextual() and entity is None:
            return f"[TRACE {trace_id}] Connector is contextual-only and no entity is provided."

        # Handle file attachment metadata
        if data.get("file_id", "").startswith("import/global"):
            try:
                encoded = base64.b64encode(file_buffer.read()).decode()
                self.data_file = {
                    "name": data["file_id"].replace("import/global/", ""),
                    "data": encoded,
                    "mime_type": data["file_mime"],
                }
                file_buffer.seek(0)
            except Exception as e:
                self.helper.connector_logger.warning(
                    f"[TRACE {trace_id}] Failed to attach file metadata: {e}"
                )
                self.data_file = None

        # Extract and parse document content
        try:
            parsed = self._extract_and_parse_file(
                data, file_name, file_buffer, trace_id
            )
        except Exception as e:
            self.helper.connector_logger.error(
                f"[TRACE {trace_id}] Extraction or parsing failed: {e}"
            )
            return f"[TRACE {trace_id}] Extraction or parsing failed: {e}"

        if not parsed:
            self.helper.connector_logger.warning(
                f"[TRACE {trace_id}] No information extracted from report."
            )
            return f"[TRACE {trace_id}] WARNING: No information extracted from report"

        # Handle modern (span-based) and legacy formats
        if (
            isinstance(parsed, dict)
            and isinstance(parsed.get("metadata"), dict)
            and isinstance(parsed["metadata"].get("span_based_entities"), list)
        ):
            return self._process_span_payload(
                parsed,
                entity,
                bypass_validation,
                file_name,
                data.get("file_id", ""),
                trace_id,
            )

        observables, entities, _ = self._process_parsing_results(
            parsed, entity, trace_id
        )
        predicted_rels = parsed.get("relations") if isinstance(parsed, dict) else []

        counts = self._process_parsed_objects(
            entity,
            observables,
            entities,
            predicted_rels,
            bypass_validation,
            file_name,
            trace_id,
        )
        entity_cnt = counts["entities"]
        observable_cnt = counts["observables"]

        self.helper.connector_logger.debug(
            f"[TRACE {trace_id}] Entities={entity_cnt}, Observables="
            f"{observable_cnt}, Predicted Relationships={len(predicted_rels)}"
        )

        if self.helper.get_validate_before_import() and not bypass_validation:
            return f"[TRACE {trace_id}] Generated bundle sent for validation"

        return (
            f"[TRACE {trace_id}] SUCCESS: Sent {observable_cnt} observables, "
            f"1 report update, and {entity_cnt} entity connections as STIX bundle"
        )

    def _extract_text_and_meta(
        self, data: Dict, file_name: str, file_buffer: BytesIO
    ) -> tuple[str, str, str, Optional[dict]]:
        """From a file, extract text, and prepare metadata for analysis.

        Performs preprocessing and hashing while returning a decoded text
        representation and optional attachment metadata.

        Args:
            data (Dict): Import message containing file details.

        Returns:
            Tuple[str, str, str, Optional[dict]]:
                file_name, file_id, extracted_text, and optional attachment metadata.

        Raises:
            ValueError: If text extraction fails or the file is invalid.
        """
        # Reset buffer position before reading
        file_buffer.seek(0)

        attachment: Optional[dict] = None
        if data["file_id"].startswith("import/global"):
            encoded = base64.b64encode(file_buffer.read()).decode()
            attachment = {
                "name": data["file_id"].replace("import/global/", ""),
                "data": encoded,
                "mime_type": data["file_mime"],
            }
            file_buffer.seek(0)

        file_bytes = file_buffer.read()
        file_mime = data.get("file_mime", "")
        file_name_in_data = data.get("file_id", "")
        input_hash = hashlib.sha256(file_bytes).hexdigest()

        self.helper.connector_logger.info(
            f"Extracting text from file: name={file_name_in_data}, mime={file_mime}, "
            f"size={len(file_bytes)} bytes, hash={input_hash}"
        )

        file_text = (
            FilePreprocessor.preprocess_file(
                file_bytes,
                file_mime,
                file_name_in_data,
                pdf_ocr_enabled=self.config.pdf_ocr_enabled,
                pdf_ocr_config=self.config,
            )
            or ""
        )

        doc_hash = hashlib.sha256(
            file_text.encode("utf-8", errors="ignore")
        ).hexdigest()

        if not file_text:
            self.helper.connector_logger.error(
                f"Failed to extract text from {file_name or 'unknown'} (hash={doc_hash})"
            )
            raise ValueError("File could not be decoded or extracted as text.")

        self.helper.connector_logger.info(
            f"Extracted {len(file_text)} characters of text from {file_name or 'unknown'} "
            f"(hash={doc_hash})"
        )

        return file_name, file_name_in_data, file_text, attachment

    def start(self) -> None:
        """
        Start the connector and listen for incoming messages.
        """
        self.helper.listen(self._process_message)

    def _log_invalid_ids(self, objects: List[dict]) -> None:
        """Log any objects that contain invalid or missing STIX IDs.

        Args:
            objects (List[dict]): List of STIX objects to validate.
        """
        for obj in objects:
            obj_id = obj.get("id")
            if not obj_id or not STIX_ID_PATTERN.match(str(obj_id)):
                self.helper.connector_logger.error(
                    f"Object with invalid STIX ID leaked through: {obj_id} ({obj.get('type')})"
                )

    def _dedupe_parsed(self, parsed: dict) -> dict:
        """Deduplicate span-based entities and remap relations accordingly.

        Args:
            parsed (dict): Parsed span-based data structure containing entities and relations.

        Returns:
            dict: Deduplicated and normalized parsed structure.
        """
        metadata = parsed.get("metadata") or {}
        span_entities = metadata.get("span_based_entities") or []
        relations = parsed.get("relations") or []

        buckets: "OrderedDict[tuple[str, str, str | None], dict]" = OrderedDict()
        id_map: dict[str, str] = {}

        for item in span_entities:
            label = str(item.get("label", "")).strip()
            text_value = str(item.get("text", "")).strip()
            item_type = item.get("type")
            key = (label.lower(), text_value.lower(), item_type)
            item_id = item.get("id")

            if key not in buckets:
                new_item = dict(item)
                positions = item.get("positions") or []
                if isinstance(positions, list):
                    uniq_positions = sorted(
                        {
                            (int(p.get("start", 0)), int(p.get("end", 0)))
                            for p in positions
                        }
                    )
                    new_item["positions"] = [
                        {"start": s, "end": e} for (s, e) in uniq_positions if e >= s
                    ]
                buckets[key] = new_item
                if isinstance(item_id, str):
                    id_map[item_id] = item_id
            elif isinstance(item_id, str):
                kept_id = buckets[key].get("id")
                if isinstance(kept_id, str):
                    id_map[item_id] = kept_id
                pos_keep = buckets[key].get("positions") or []
                pos_new = item.get("positions") or []
                if isinstance(pos_keep, list) or isinstance(pos_new, list):
                    merged = {
                        (int(p.get("start", 0)), int(p.get("end", 0)))
                        for p in (pos_keep or [])
                        if isinstance(p, dict)
                    }
                    merged.update(
                        {
                            (int(p.get("start", 0)), int(p.get("end", 0)))
                            for p in (pos_new or [])
                            if isinstance(p, dict)
                        }
                    )
                    buckets[key]["positions"] = [
                        {"start": s, "end": e} for (s, e) in sorted(merged)
                    ]

        new_relations: list[dict] = []
        for relation in relations:
            new_relation = dict(relation)
            from_id = relation.get("from_id")
            to_id = relation.get("to_id")
            if isinstance(from_id, str) and from_id in id_map:
                new_relation["from_id"] = id_map[from_id]
            if isinstance(to_id, str) and to_id in id_map:
                new_relation["to_id"] = id_map[to_id]
            new_relations.append(new_relation)

        if len(span_entities) != len(buckets):
            self.helper.connector_logger.debug(
                f"Deduplicated {len(span_entities)} → {len(buckets)} span entities; remapped {len(new_relations)} relations."
            )

        new_parsed = dict(parsed)
        new_metadata = dict(metadata)
        new_metadata["span_based_entities"] = list(buckets.values())
        new_parsed["metadata"] = new_metadata
        new_parsed["relations"] = new_relations
        return new_parsed

    def _process_span_entities(
        self,
        parsed: dict,
        context_entity: Optional[Dict],
    ) -> tuple[
        list[dict],
        list[dict],
        dict[str, list[str]],
        dict[str, str],
        Optional[str],
        Optional[str],
    ]:
        """Convert span-based LLM output into structured STIX entities and observables.

        Args:
            parsed (dict): Parsed LLM output with metadata and spans.
            context_entity (Optional[Dict]): Parent OpenCTI entity for inherited markings and authorship.

        Returns:
            tuple: (observables, entities, uuid_to_stix, uuid_to_text, report_title, author)
        """
        metadata = parsed.get("metadata") or {}
        report_title = metadata.get("report_title")
        span_entities = metadata.get("span_based_entities") or []

        observables: list[dict] = []
        entities: list[dict] = []
        uuid_to_stix: dict[str, list[str]] = {}
        uuid_to_text: dict[str, str] = {}

        object_markings = []
        author = None
        if context_entity:
            object_markings = [
                x.get("standard_id")
                for x in context_entity.get("objectMarking", [])
                if isinstance(x, dict) and x.get("standard_id")
            ]
            if isinstance(context_entity.get("createdBy"), dict):
                author = context_entity["createdBy"].get("standard_id")

        for match in span_entities:
            category = str(match.get("label", ""))
            match_type = match.get("type")
            match_id = match.get("id")
            cleaned_text = self._sanitise_name(match.get("text"))

            if category == "Report" and cleaned_text:
                report_title = cleaned_text
                continue
            if not cleaned_text:
                self.helper.connector_logger.debug(
                    f"Skipping invalid span entity with text: {match.get('text')!r}"
                )
                continue

            # Entity creation
            if match_type == "entity":
                if category in {"Attack-Pattern", "Attack-Pattern.x_mitre_id"}:
                    # Try to resolve from cached ATT&CK patterns
                    stix_object = self._get_attack_pattern(cleaned_text)
                    if stix_object:
                        stix_objects = [stix_object]
                        self.helper.connector_logger.debug(
                            f"Resolved ATT&CK pattern {cleaned_text!r} -> {stix_object.get('id')}"
                        )
                    else:
                        # Fallback if not found in cache
                        self.helper.connector_logger.warning(
                            f"Skipping unknown ATT&CK pattern: {cleaned_text!r}"
                        )
                        continue
                else:
                    stix_objects = create_stix_object(
                        category,
                        cleaned_text,
                        object_markings,
                        custom_properties={"created_by_ref": author} if author else {},
                    )
            elif match_type == "observable":
                base_props = {"created_by_ref": author} if author else {}
                stix_objects = create_stix_object(
                    category,
                    cleaned_text,
                    object_markings,
                    custom_properties={
                        **base_props,
                        "x_opencti_create_indicator": self.create_indicator,
                    },
                )
            else:
                self.helper.connector_logger.debug(
                    f"Unsupported match type {match_type!r} for {category!r}"
                )
                continue

            if isinstance(stix_objects, dict) or stix_objects is None:
                stix_objects = [stix_objects] if stix_objects else []

            for stix_object in stix_objects:
                processed = self._coerce_stix_to_dict(
                    stix_object, category, cleaned_text
                )
                if not processed:
                    continue
                if match_type == "observable":
                    observables.append(processed)
                else:
                    entities.append(processed)

                if isinstance(match_id, str):
                    uuid_to_stix.setdefault(match_id, []).append(str(processed["id"]))
                    uuid_to_text[match_id] = cleaned_text

                    # Add semantic and hash token mappings for relation resolution
                    if category and cleaned_text:
                        semantic_token = f"id={category};name={cleaned_text}"
                        uuid_to_stix.setdefault(semantic_token, []).append(
                            str(processed["id"])
                        )
                        uuid_to_text[semantic_token] = cleaned_text

                    for part in [p for p in match_id.split(";") if p.startswith("h=")]:
                        hval = part.split("=", 1)[1]
                        if hval:
                            uuid_to_stix.setdefault(hval, []).append(
                                str(processed["id"])
                            )

        return observables, entities, uuid_to_stix, uuid_to_text, report_title, author

    def _process_span_payload(
        self,
        parsed: dict,
        context_entity: Optional[dict],
        bypass_validation: bool,
        file_name: str,
        _file_id: str,
        trace_id: str,
    ) -> str:
        """Process modern (span-based) extraction results and submit as a STIX bundle.

        Args:
            parsed (dict): Parsed JSON containing 'metadata' and 'relations'.
            context_entity (Optional[dict]): Existing OpenCTI entity to link objects to.
            bypass_validation (bool): Whether to bypass OpenCTI validation.
            file_name (str): Original imported file name.
            file_id (str): File identifier from OpenCTI.
            trace_id (str): Trace identifier for structured logging.

        Returns:
            str: Human-readable summary of the import process.
        """
        trace = f"[TRACE {trace_id}]"
        deduped = self._dedupe_parsed(parsed)

        (
            observables,
            entities,
            uuid_to_stix,
            uuid_to_text,
            _report_title,
            author,
        ) = self._process_span_entities(deduped, context_entity)

        predicted_rels = deduped.get("relations", [])
        by_id = {
            o["id"]: o
            for o in observables + entities
            if isinstance(o, dict) and "id" in o
        }

        relationships, skipped_rels = self._build_predicted_relationships(
            predicted_rels,
            uuid_to_stix=uuid_to_stix,
            uuid_to_text=uuid_to_text,
            by_id=by_id,
            author=author,
        )

        indicators = compose_indicators_from_observables(
            observables,
            object_markings=[],
            created_by_ref=author,
        )

        # Add based-on relationships from indicators to their corresponding observables
        for ind in indicators:
            ind_id = ind.get("id")
            if not ind_id:
                continue

            pattern = ind.get("pattern") or ""
            if not pattern:
                continue

            for obs in observables:
                obs_id = obs.get("id")
                obs_value = obs.get("value")
                if not (obs_id and obs_value):
                    continue

                # Only link if the observable value appears in the indicator pattern
                if obs_value in pattern:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", ind_id, obs_id
                            ),
                            relationship_type="based-on",
                            source_ref=ind_id,
                            target_ref=obs_id,
                            allow_custom=True,
                        )
                    )

        all_objects = observables + entities + indicators + relationships
        all_objects = [d for d in (self._as_dict(o) for o in all_objects) if d]

        container_objects = self._link_to_container(
            file_name=file_name,
            entity=context_entity,
            objects=all_objects,
            file_attachment=self.data_file,
        )

        # Expand temporary IDs within the container
        container_objects = [
            (
                self._resolve_ids_in_container(obj, uuid_to_stix)
                if isinstance(obj, dict)
                else obj
            )
            for obj in container_objects
        ]

        final_objects = self._dedupe_objects(container_objects)

        try:
            bundle = stix2.Bundle(objects=final_objects, allow_custom=True).serialize()
            self.helper.send_stix2_bundle(
                bundle=bundle,
                bypass_validation=bypass_validation,
                file_name=f"import-document-ai-{Path(file_name).name}",
                entity_id=context_entity["id"] if context_entity else None,
            )
        except Exception as e:
            self.helper.connector_logger.error(
                f"{trace} [BUNDLE] Failed to send STIX bundle: {e}"
            )
            return f"{trace} ERROR: STIX bundle send failure: {e}"

        self.helper.connector_logger.info(
            f"{trace} [FINAL] STIX bundle sent for {file_name}: "
            f"{len(final_objects)} total objects, "
            f"{len(observables)} observables, {len(entities)} entities, "
            f"{len(relationships)} relationships, {len(indicators)} indicators, "
            f"{len(skipped_rels)} skipped."
        )

        return (
            f"{trace} SUCCESS: Sent {len(final_objects)} total objects, "
            f"{len(relationships)} relationships, and {len(indicators)} indicators"
        )

    def _coerce_stix_to_dict(
        self, stix_object: Any, category: str, value: str
    ) -> Optional[dict]:
        """Ensure a STIX object is safely serialized into a dictionary.

        Args:
            stix_object (Any): A STIX2 object or dict.
            category (str): Entity or observable type.
            value (str): The raw text or name value.

        Returns:
            Optional[dict]: Serialized STIX dictionary, or None if invalid.
        """
        if not stix_object:
            return None
        if isinstance(stix_object, dict):
            if "id" in stix_object:
                return stix_object
            self.helper.connector_logger.warning(
                f"Dict STIX object missing 'id' field for {category} ({value}) (object: {stix_object})"
            )
            return None
        if hasattr(stix_object, "serialize"):
            try:
                serialized = stix_object.serialize()
            except (ValueError, TypeError, STIXError) as err:
                self.helper.connector_logger.warning(
                    f"Failed to serialize STIX object for {category} ({value}): {err}"
                )
                return None
            try:
                data = (
                    json.loads(serialized)
                    if isinstance(serialized, str)
                    else serialized
                )
            except json.JSONDecodeError as exc:
                self.helper.connector_logger.warning(
                    f"Failed to decode serialized STIX JSON for {category} ({value}): {exc}"
                )
                return None
            return data if "id" in data else None
        return None

    def _as_dict(self, obj: Any) -> Optional[dict]:
        if isinstance(obj, dict):
            return obj if obj.get("id") else None
        if hasattr(obj, "serialize"):
            try:
                s = obj.serialize()
                return json.loads(s) if isinstance(s, str) else s
            except Exception as e:
                self.helper.connector_logger.debug(
                    f"Failed to serialize STIX object: {e}"
                )
                return None
        return None

    def _dedupe_objects(self, objects: list[dict]) -> list[dict]:
        """Deduplicate a list of STIX objects based on (id, type).

        Args:
            objects (list[dict]): List of STIX objects.

        Returns:
            list[dict]: Deduplicated list containing only valid STIX objects.
        """
        final, seen = [], set()
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_id = obj.get("id")
            if not obj_id or "--" not in obj_id:
                continue
            key = (obj_id, obj.get("type"))
            if key in seen:
                continue
            seen.add(key)
            final.append(obj)
        return final

    def _process_parsing_results(
        self,
        parsed: List[Dict],
        context_entity: Optional[Dict],
        trace_id: str,
    ) -> Tuple[List[Dict], List[Dict], Optional[str]]:
        """Convert parsed LLM results into STIX entities and observables.

        This method processes non-span (legacy) parsed results from the AI model or
        web service, generating STIX-compatible observables and entities.

        Args:
            parsed (List[Dict]): Parsed entities and observables.
            context_entity (Optional[Dict]): Context entity from OpenCTI.
            trace_id (str): Trace identifier for structured logging.

        Returns:
            Tuple[List[Dict], List[Dict], Optional[str]]: Observables, entities, and optional report title.
        """
        observables: List[Dict] = []
        entities: List[Dict] = []
        report_title: Optional[str] = None
        skipped_count = 0
        invalid_items = []

        # Extract context markings and author
        object_markings = []
        author = None
        if context_entity:
            object_markings = [
                x.get("standard_id")
                for x in context_entity.get("objectMarking", [])
                if "standard_id" in x
            ]
            author_obj = context_entity.get("createdBy")
            if isinstance(author_obj, dict):
                author = author_obj.get("standard_id")

        for match in parsed:
            if not all(
                key in match
                for key in (
                    RESULT_FORMAT_TYPE,
                    RESULT_FORMAT_CATEGORY,
                    RESULT_FORMAT_MATCH,
                )
            ):
                skipped_count += 1
                invalid_items.append({"reason": "missing_keys", "match": match})
                continue

            match_type = match.get(RESULT_FORMAT_TYPE)
            category = match.get(RESULT_FORMAT_CATEGORY)
            value = match.get(RESULT_FORMAT_MATCH)

            if not category or not value or not match_type:
                skipped_count += 1
                invalid_items.append(
                    {"reason": "missing_or_empty_fields", "match": match}
                )
                continue

            # --- Entity Handling ---
            if match_type == "entity":
                if category == "Report":
                    report_title = value
                    self.helper.connector_logger.info(
                        f"[TRACE {trace_id}] Extracted report title: {report_title}"
                    )
                    continue

                # MITRE ATT&CK patterns
                if category in {"Attack-Pattern", "Attack-Pattern.x_mitre_id"}:
                    mitre_id = value.strip()
                    stix_object = self._get_attack_pattern(mitre_id)

                    if stix_object:
                        entities.append(stix_object)
                        self.helper.connector_logger.debug(
                            f"[TRACE {trace_id}] Resolved ATT&CK pattern {mitre_id!r} -> {stix_object.get('id')}"
                        )
                        continue

                    # ATT&CK pattern not in cache
                    self.helper.connector_logger.warning(
                        f"[TRACE {trace_id}] Skipping unknown ATT&CK pattern: {mitre_id!r}"
                    )

                    skipped_count += 1
                    invalid_items.append(
                        {"reason": "attack_pattern_not_found", "match": match}
                    )
                    continue

                # Standard entity creation
                stix_objects = create_stix_object(
                    category,
                    value,
                    object_markings,
                    custom_properties={"created_by_ref": author} if author else {},
                )
                if not stix_objects:
                    self.helper.connector_logger.warning(
                        f"[TRACE {trace_id}] Failed to create STIX object for entity {category!r} = {value!r}"
                    )
                    skipped_count += 1
                    invalid_items.append(
                        {"reason": "stix_object_creation_failed", "match": match}
                    )
                    continue

                if isinstance(stix_objects, dict):
                    stix_objects = [stix_objects]

                for stix_object in stix_objects:
                    if isinstance(stix_object, dict) and "id" in stix_object:
                        entities.append(stix_object)
                    else:
                        self.helper.connector_logger.warning(
                            f"[TRACE {trace_id}] Invalid STIX entity created for {category!r} = {value!r}"
                        )
                        skipped_count += 1
                        invalid_items.append(
                            {"reason": "stix_object_invalid", "match": match}
                        )

            # --- Observable Handling ---
            elif match_type == "observable":
                stix_objects = create_stix_object(
                    category,
                    value,
                    object_markings,
                    custom_properties={
                        "x_opencti_create_indicator": self.create_indicator,
                        "created_by_ref": author,
                    },
                )
                if not stix_objects:
                    self.helper.connector_logger.warning(
                        f"[TRACE {trace_id}] Failed to create STIX observable for {category!r} = {value!r}"
                    )
                    skipped_count += 1
                    invalid_items.append(
                        {"reason": "stix_object_creation_failed", "match": match}
                    )
                    continue

                if isinstance(stix_objects, dict):
                    stix_objects = [stix_objects]

                for stix_object in stix_objects:
                    if isinstance(stix_object, dict) and "id" in stix_object:
                        observables.append(stix_object)
                    else:
                        self.helper.connector_logger.warning(
                            f"[TRACE {trace_id}] Invalid STIX observable for {category!r} = {value!r}"
                        )
                        skipped_count += 1
                        invalid_items.append(
                            {"reason": "stix_object_invalid", "match": match}
                        )

        total = len(parsed)
        self.helper.connector_logger.info(
            f"[TRACE {trace_id}] Parsing summary: total={total}, entities={len(entities)}, "
            f"observables={len(observables)}, skipped={skipped_count}"
        )

        if skipped_count > 0:
            self.helper.connector_logger.warning(
                f"[TRACE {trace_id}] Skipped {skipped_count} items due to errors. "
                f"Sample={invalid_items[:5]}"
            )

        return observables, entities, report_title

    def _link_to_container(
        self,
        file_name: str,
        entity: Optional[dict],
        objects: list[dict],
        file_attachment: Optional[dict] = None,
    ) -> list[dict]:
        """Link parsed STIX objects into a container (e.g., Report, Case, Grouping).

        If a contextual entity is provided, the objects are linked to it.
        Otherwise, a new Report container is created automatically.

        Args:
            file_name (str): Original file name being processed.
            entity (Optional[dict]): Contextual OpenCTI entity to link objects into.
            objects (list[dict]): STIX objects to include in the bundle.
            file_attachment (Optional[dict]): Optional attachment metadata.

        Returns:
            list[dict]: The updated STIX object list including the container or relationships.
        """
        if not objects:
            return []

        object_ids = []
        for o in objects:
            if not isinstance(o, dict):
                continue
            t = (o.get("type") or "").lower()
            if t == "relationship":
                continue  # skip relationship objects entirely
            oid = o.get("standard_id") or o.get("id")
            if (
                isinstance(oid, str)
                and "--" in oid
                and not oid.startswith("relationship--")
            ):
                object_ids.append(oid)

        # --------------------------------------------------------------
        # Case 1: Link into an existing container entity
        # --------------------------------------------------------------
        if entity:
            container_types = {
                "report",
                "grouping",
                "x-opencti-case-incident",
                "x-opencti-case-rfi",
                "x-opencti-case-rft",
                "note",
                "opinion",
                "observed-data",
            }

            entity_type = entity.get("entity_type") or entity.get("type", "")
            standard_id = entity.get("standard_id")

            if not standard_id:
                self.helper.connector_logger.error(
                    f"Context entity {entity.get('id')} missing standard_id; skipping container link"
                )
                return objects

            stix_entity = None
            try:
                bundle = (
                    self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                        entity_type=entity_type,
                        entity_id=entity.get("id"),
                    )
                    or {}
                )
                obj = bundle.get("objects") or []
                if obj:
                    stix_entity = dict(obj[0])
            except Exception as err:
                self.helper.connector_logger.warning(
                    f"Failed to export context entity {entity.get('id')}: {err}"
                )
                stix_entity = None

            gql_to_stix = {
                "Report": "report",
                "Grouping": "grouping",
                "Case-Incident": "x-opencti-case-incident",
                "Case-Rfi": "x-opencti-case-rfi",
                "Case-Rft": "x-opencti-case-rft",
                "Note": "note",
                "Opinion": "opinion",
                "Observed-Data": "observed-data",
            }
            stix_type = (
                stix_entity.get("type")
                if stix_entity
                else gql_to_stix.get(entity_type, entity_type.lower())
            )

            if not stix_entity:
                stix_entity = {"type": stix_type, "id": standard_id}

            refs_to_add = [oid for oid in object_ids if oid != standard_id]

            if stix_type in container_types:
                existing_refs = stix_entity.get("object_refs") or []
                if not isinstance(existing_refs, list):
                    existing_refs = []
                stix_entity["object_refs"] = list(
                    dict.fromkeys(existing_refs + refs_to_add)
                )

                if file_attachment:
                    stix_entity["x_opencti_files"] = [file_attachment]

                objects.append(stix_entity)

                for oid in refs_to_add:
                    if isinstance(oid, str) and "--" in oid:
                        rel = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", oid, standard_id
                            ),
                            relationship_type="related-to",
                            source_ref=oid,
                            target_ref=standard_id,
                            allow_custom=True,
                        )
                        objects.append(rel)

                self.helper.connector_logger.debug(
                    f"Linked {len(refs_to_add)} objects into {stix_type} ({standard_id})"
                )
            else:
                for oid in refs_to_add:
                    if isinstance(oid, str) and "--" in oid:
                        rel = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", oid, standard_id
                            ),
                            relationship_type="related-to",
                            source_ref=oid,
                            target_ref=standard_id,
                            allow_custom=True,
                        )
                        objects.append(rel)

                objects.append({"type": stix_type, "id": standard_id})
                self.helper.connector_logger.debug(
                    f"Linked {len(refs_to_add)} objects to non-container {stix_type} ({standard_id})"
                )

            return objects

        # --------------------------------------------------------------
        # Case 2: No context entity — create new Report container
        # --------------------------------------------------------------
        now = datetime.now(timezone.utc)
        report = stix2.Report(
            id=Report.generate_id(file_name, now),
            name=f"import-document-ai_{file_name}",
            description="Automatic import",
            published=now,
            report_types=["threat-report"],
            object_refs=object_ids,
            allow_custom=True,
            custom_properties={
                "x_opencti_files": [file_attachment] if file_attachment else []
            },
        )
        objects.append(report)
        self.helper.connector_logger.debug(
            f"Created new Report container for {file_name} with {len(object_ids)} object_refs"
        )
        return objects

    def _get_attack_pattern(self, mitre_id: str) -> Optional[dict]:
        """Retrieve a MITRE ATT&CK pattern from cache or refresh it if stale.

        Args:
            mitre_id (str): The MITRE ATT&CK ID or name.

        Returns:
            Optional[dict]: The corresponding ATT&CK pattern object, if found.
        """
        now = time.time()
        if (
            not self._attack_pattern_cache
            or (now - self._attack_pattern_last_refresh) > self._attack_pattern_ttl
        ):
            self._refresh_attack_pattern_cache()

        key = (mitre_id or "").strip()
        obj = self._attack_pattern_cache.get(key) or self._attack_pattern_cache.get(
            key.lower()
        )
        return dict(obj) if obj else None

    def _refresh_attack_pattern_cache(self) -> None:
        """Refresh the local MITRE ATT&CK pattern cache from OpenCTI."""
        try:
            self.helper.connector_logger.info(
                "[ATTACK] Refreshing ATT&CK pattern cache..."
            )
            all_ttps = self.helper.api.attack_pattern.list(get_all=True) or []

            new_cache: dict[str, dict] = {}
            for ttp in all_ttps:
                if not ttp.get("x_mitre_id") or not ttp.get("standard_id"):
                    continue

                obj = {
                    "type": "attack-pattern",
                    "id": ttp["standard_id"],
                    "spec_version": "2.1",
                    "name": ttp.get("name"),
                    "x_mitre_id": ttp.get("x_mitre_id"),
                    "description": ttp.get("description"),
                    "x_mitre_platforms": ttp.get("x_mitre_platforms"),
                    "x_mitre_domains": ttp.get("x_mitre_domains"),
                }

                # Index by both MITRE ID and name for convenience
                new_cache[ttp["x_mitre_id"]] = obj
                if ttp.get("name"):
                    new_cache[ttp["name"]] = obj
                    new_cache[ttp["name"].lower()] = obj
            with self._attack_pattern_lock:
                self._attack_pattern_cache = new_cache
                self._attack_pattern_last_refresh = time.time()
            self.helper.connector_logger.info(
                f"[ATTACK] Cached {len(new_cache)} ATT&CK patterns."
            )
        except Exception as e:
            self.helper.connector_logger.error(f"[ATTACK] Cache refresh failed: {e}")

    def _resolve_ids_in_container(
        self, container: dict, id_map: dict[str, list[str]]
    ) -> dict:
        """Resolve and expand object_refs within a container using a mapping of LLM IDs to STIX IDs.

        Args:
            container (dict): STIX container object (e.g., Report or Grouping).
            id_map (dict[str, list[str]]): Mapping of temporary LLM IDs to one or more STIX IDs.

        Returns:
            dict: The updated container with expanded and deduplicated object_refs, preserving order.
        """
        if not isinstance(container, dict):
            return container

        refs = container.get("object_refs")
        if not isinstance(refs, list):
            return container

        resolved_ordered: list[str] = []
        seen: set[str] = set()

        for rid in refs:
            # Expand temporary IDs to real STIX IDs if available
            expanded = id_map.get(rid)
            if expanded:
                for eid in expanded:
                    if eid not in seen:
                        seen.add(eid)
                        resolved_ordered.append(eid)
            elif isinstance(rid, str) and "--" in rid and rid not in seen:
                seen.add(rid)
                resolved_ordered.append(rid)

        container["object_refs"] = resolved_ordered
        return container

    def _build_predicted_relationships(
        self,
        predicted_rels: list[dict],
        uuid_to_stix: dict[str, list[str]],
        uuid_to_text: dict[str, str],
        by_id: dict[str, dict],
        author: Optional[str],
    ) -> tuple[list[stix2.Relationship], list[tuple[str, str, str, str, str]]]:
        """Convert model-predicted or webservice relationships into valid STIX relationships.

        Args:
            predicted_rels (list[dict]): Relationship objects predicted by the LLM or webservice.
            uuid_to_stix (dict[str, list[str]]): Mapping from temporary LLM identifiers to STIX IDs.
            uuid_to_text (dict[str, str]): Mapping from LLM IDs to raw text for logging.
            by_id (dict[str, dict]): Dictionary of STIX objects indexed by their IDs.
            author (Optional[str]): STIX ID of the author to associate with relationships.

        Returns:
            tuple[list[stix2.Relationship], list[tuple[str, str, str, str, str]]]:
                - Valid STIX relationships.
                - Skipped relationships (unauthorized or invalid).
        """
        relationships: list[stix2.Relationship] = []
        skipped: list[tuple[str, str, str, str, str]] = []
        seen: set[tuple[str, str, str, str, str]] = set()

        def _resolve(token: str) -> list[str]:
            """Resolve a temporary token or STIX ID to valid STIX IDs."""
            if not isinstance(token, str):
                return []

            resolved: list[str] = []
            for part in token.split(";"):
                if part.startswith("h="):
                    hval = part.split("=", 1)[1]
                    resolved.extend(uuid_to_stix.get(hval, []))
            if token in uuid_to_stix:
                resolved.extend(uuid_to_stix[token])
            if token in by_id:
                resolved.append(token)

            # Deduplicate while preserving order
            ordered: dict[str, None] = {}
            for rid in resolved:
                ordered.setdefault(rid, None)
            return list(ordered.keys())

        def _describe(token: str, resolved_id: Optional[str]) -> str:
            """Return a readable label for diagnostics and skipped relations."""
            if isinstance(token, str):
                for part in token.split(";"):
                    if part.startswith("h="):
                        value = uuid_to_text.get(part.split("=", 1)[1])
                        if value:
                            return value
            if resolved_id and resolved_id in by_id:
                obj = by_id[resolved_id]
                return obj.get("name") or obj.get("value") or "<unknown>"
            return "<unknown>"

        for rel in predicted_rels or []:
            rel_type = str(rel.get("label") or "").strip().upper()
            if not rel_type:
                continue

            src_candidates = _resolve(rel.get("from_id"))
            tgt_candidates = _resolve(rel.get("to_id"))
            if not src_candidates or not tgt_candidates:
                continue

            for src_id in src_candidates:
                for tgt_id in tgt_candidates:
                    if src_id == tgt_id:
                        continue
                    src_obj, tgt_obj = by_id.get(src_id), by_id.get(tgt_id)
                    if not src_obj or not tgt_obj:
                        continue

                    src_type = stix_lookup_type(src_obj)
                    tgt_type = stix_lookup_type(tgt_obj)
                    pair_key = (src_id, src_type, rel_type, tgt_id, tgt_type)
                    if pair_key in seen:
                        continue

                    self.helper.connector_logger.debug(
                        f"Processing predicted relationship: {src_id} ({src_type}) -[{rel_type}]-> {tgt_id} ({tgt_type})"
                    )
                    if is_relation_allowed(
                        self.allowed_relations, src_type, tgt_type, rel_type
                    ):
                        try:
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        rel_type.lower(), src_id, tgt_id
                                    ),
                                    relationship_type=rel_type.lower(),
                                    source_ref=src_id,
                                    target_ref=tgt_id,
                                    created_by_ref=author,
                                    allow_custom=True,
                                )
                            )
                            seen.add(pair_key)
                        except Exception as e:
                            self.helper.connector_logger.debug(
                                f"Failed to build relationship {rel_type} {src_id}->{tgt_id}: {e}"
                            )
                    else:
                        skipped.append(
                            (
                                _describe(rel.get("from_id"), src_id),
                                src_type,
                                rel_type,
                                _describe(rel.get("to_id"), tgt_id),
                                tgt_type,
                            )
                        )
                        self.helper.connector_logger.debug(
                            f"Skipped unauthorized relationship: {src_id} ({src_type}) -[{rel_type}]-> {tgt_id} ({tgt_type})"
                        )

        if skipped:
            self.helper.connector_logger.info(
                f"Skipped {len(skipped)} unauthorized or invalid relationships"
            )
            self.helper.connector_logger.debug(f"Skipped relationships: {skipped}")

        return relationships, skipped

    def _process_parsed_objects(
        self,
        entity: Optional[Dict],
        observables: List[dict],
        entities: List[dict],
        predicted_rels: List[dict],
        bypass_validation: bool,
        file_name: str,
        trace_id: str,
    ) -> dict[str, int]:
        """Process parsed observables and entities, build relationships, and send a STIX bundle.

        Args:
            entity (Optional[Dict]): Optional OpenCTI context entity.
            observables (List[dict]): List of parsed observables.
            entities (List[dict]): List of parsed entities.
            predicted_rels (List[dict]): Predicted relationships between objects.
            bypass_validation (bool): Skip OpenCTI validation if True.
            file_name (str): Original file name.
            trace_id (str): Correlation trace ID for logging.

        Returns:
            dict[str, int]: Summary of processed objects.
        """
        if not observables and not entities:
            self.helper.connector_logger.warning(
                f"[TRACE {trace_id}] [BUNDLE] No observables or entities to process."
            )
            return {
                "observables": 0,
                "entities": 0,
                "relationships": 0,
                "indicators": 0,
                "skipped_rels": 0,
                "total_sent": 0,
            }

        self.helper.connector_logger.info(
            f"[TRACE {trace_id}] [BUNDLE] Preparing bundle for {file_name}: "
            f"entities={len(entities)}, observables={len(observables)}"
        )

        by_id = {
            o["id"]: o
            for o in observables + entities
            if isinstance(o, dict) and "id" in o
        }
        relationships, skipped_rels = self._build_predicted_relationships(
            predicted_rels, uuid_to_stix={}, uuid_to_text={}, by_id=by_id, author=None
        )

        indicators = compose_indicators_from_observables(
            observables, object_markings=[], created_by_ref=None
        )

        for ind in indicators:
            ind_id = ind.get("id")
            if not ind_id:
                continue
            pattern = ind.get("pattern") or ""
            if not pattern:
                continue
            for obs in observables:
                obs_id = obs.get("id")
                obs_value = obs.get("value")
                if obs_id and obs_value and obs_value in pattern:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", ind_id, obs_id
                            ),
                            relationship_type="based-on",
                            source_ref=ind_id,
                            target_ref=obs_id,
                            allow_custom=True,
                        )
                    )

        all_objects = observables + entities + indicators + relationships
        all_objects = [d for d in (self._as_dict(o) for o in all_objects) if d]

        bundle_objects = self._link_to_container(
            file_name=file_name,
            entity=entity,
            objects=all_objects,
            file_attachment=self.data_file,
        )

        final_objects = self._dedupe_objects(bundle_objects)

        try:
            bundle = stix2.Bundle(objects=final_objects, allow_custom=True).serialize()
            self.helper.send_stix2_bundle(
                bundle=bundle,
                bypass_validation=bypass_validation,
                file_name=f"import-document-ai-{Path(file_name).name}",
                entity_id=entity["id"] if entity else None,
            )
        except Exception as err:
            self.helper.connector_logger.error(
                f"[TRACE {trace_id}] [BUNDLE] Failed to send STIX bundle: {err}"
            )
            return {
                "observables": 0,
                "entities": 0,
                "relationships": 0,
                "indicators": 0,
                "skipped_rels": 0,
                "total_sent": 0,
            }

        counts = {
            "observables": len(observables),
            "entities": len(entities),
            "relationships": len(relationships),
            "indicators": len(indicators),
            "skipped_rels": len(skipped_rels),
            "total_sent": len(final_objects),
        }

        self.helper.connector_logger.info(
            f"[TRACE {trace_id}] [FINAL] STIX bundle sent for {file_name}: {counts}"
        )
        return counts
