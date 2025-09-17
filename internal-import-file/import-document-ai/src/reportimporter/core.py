import base64
import os
from collections import OrderedDict
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import requests
import stix2
import yaml
from pycti import (
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    get_config_variable,
)
from reportimporter.relations_allowed import (
    is_relation_allowed,
    load_allowed_relations,
    stix_lookup_type,
)
from reportimporter.util import (
    compute_bundle_stats,
    create_stix_object,
    remove_all_relationships,
)
from requests.exceptions import ConnectionError, HTTPError

# ---------------------------------------------------------------------------
# Helper aliases (typing)

UUID = str  # Orion entity UUID
UuidToStix = dict[UUID, str]  # quick lookup when building relations


class ReportImporter:
    """Handles the import of a document into OpenCTI:
    1) Downloads the file from OpenCTI
    2) Calls an ML web service to extract entities/relationships
    3) Constructs a STIX bundle containing:
         - Observables (e.g., IPv4, DomainName, etc.)
         - Domain Entities (e.g., Malware, Individual, etc.)
         - Predicted Relationships or context-based relationships
         - A Report (if no context entity) or attaching to an existing entity
    4) Sends the final STIX bundle to OpenCTI for ingestion
    """

    def __init__(self) -> None:
        # Instantiate the connector helper from config
        base_path = os.path.dirname(os.path.abspath(__file__))
        config_file_path = base_path + "/../config.yml"
        if os.path.isfile(config_file_path):
            with open(config_file_path) as config_file:
                config = yaml.load(config_file, Loader=yaml.FullLoader)
            using_local_config = True
        else:
            config = {}
            using_local_config = False

        self.helper = OpenCTIConnectorHelper(config)

        if using_local_config:
            self.helper.connector_logger.error(
                "Using local config file. Use Environment Variables only in production."
            )

        # Read connector flags from config (create_indicator, web_service_url, etc.)
        self.create_indicator = get_config_variable(
            "IMPORT_DOCUMENT_CREATE_INDICATOR",
            ["import_document", "create_indicator"],
            config,
            default=False,
        )
        self.web_service_url = get_config_variable(
            "CONNECTOR_WEB_SERVICE_URL",
            ["connector", "web_service_url"],
            config,
            default="https://importdoc.ariane.testing.filigran.io",
        )
        license_key_pem = get_config_variable(
            "CONNECTOR_LICENCE_KEY_PEM", ["connector", "licence_key_pem"], config
        )
        self.licence_key_base64 = base64.b64encode(license_key_pem.encode())

        self.include_relationships = get_config_variable(
            "IMPORT_DOCUMENT_INCLUDE_RELATIONSHIPS",
            ["import_document", "include_relationships"],
            config,
            default=False,
        )

        # Retrieve the OpenCTI instance ID (used as a header for the ML service)
        # TODO make the connector more resilient to OpenCTI being down at startup,
        # by wraping the initial helper.api.query() in a try/except with retries and logging
        self.instance_id = (
            self.helper.api.query(
                """
                query SettingsQuery {
                    settings {
                        id
                        }
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
        self.allowed_relations = load_allowed_relations(self.helper)

    @staticmethod
    def _sanitise_name(raw_text: str | None) -> str | None:
        """Return a clean name or None if it is too short ( < 2 chars )."""
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
        self.file: dict | None = None
        return self._process_import(data)

    def _process_import(self, data: dict) -> str:
        """Main method to handle the import logic of a document file:
            - Downloads the file
            - Extracts entities and relationships via ML
            - Constructs and sends a STIX bundle to OpenCTI

        Args:
            data (dict): Payload provided by OpenCTI when triggering the connector.
                Must include:
                - 'file_id' (str): ID of the file to import.
                - 'file_mime' (str): MIME type of the file.
                - 'file_fetch' (str): Path used to download the file.
                Optionally includes:
                - 'entity_id' (str): ID of a contextual entity (e.g., Report, Case, Threat Actor).
                    If provided, the extracted entities/observables will be attached to this entity.
                - 'bypass_validation' (bool): If True, skips validation before import.

        Raises:
            ConnectionError: Raised when the ImportDocumentAI webservice is unreachable
            HTTPError: Raised when the webservice responds with an HTTP error code.

        Returns:
            str: Summary/log of the import action.
        """
        # Step 1: Download the file (returns filename and a BytesIO buffer)
        file_name, file_content_buffered = self._download_import_file(data)
        entity_id = data.get("entity_id", None)
        bypass_validation = data.get("bypass_validation", False)
        # If an entity_id was provided, fetch that STIX object
        entity = (
            self.helper.api.stix_core_object.read(id=entity_id)
            if entity_id is not None
            else None
        )
        if self.helper.get_only_contextual() and entity is None:
            return "Connector is only contextual and entity is not defined. Nothing was imported"

        # If the file ID starts with "import/global", attach it as x_opencti_files in the bundle
        if data["file_id"].startswith("import/global"):
            file_data_encoded = base64.b64encode(file_content_buffered.read())
            self.file = {
                "name": data["file_id"].replace("import/global/", ""),
                "data": file_data_encoded,
                "mime_type": data["file_mime"],
            }
            # Reset file offset
            file_content_buffered.seek(0)

        # Step 2: Call our ML service to extract entities & relationships
        try:
            response = requests.post(
                url=self.web_service_url + "/extract_entities_relations",
                files={
                    "file": (data["file_id"], file_content_buffered, data["file_mime"])
                },
                headers={
                    "X-OpenCTI-Certificate": self.licence_key_base64,
                    "X-OpenCTI-instance-id": self.instance_id,
                },
            )
            response.raise_for_status()
        except ConnectionError:
            raise ConnectionError(
                "ImportDocumentAI webservice seems to be unreachable, have you configured your connector properly ?"
            )
        except HTTPError as e:
            raise HTTPError(
                f"{response.status_code}, request failed with reason : {e}"
            ) from e
        parsed = response.json()
        if not parsed:
            return "No information extracted from report"

        # Early dedupe
        parsed = self._dedupe_parsed(parsed)

        # Step 3: Parse and build STIX entities / observables, and map text to STIX id (for relationship linking)
        observables, entities, uuid_to_stix, uuid_to_text = (
            self._process_parsing_results(parsed, entity)
        )
        predicted_rels = parsed.get("relations", [])

        # Step 4: Build the STIX bundle (attach to context or wrap in a new report) + send bundle
        counts = self._process_parsed_objects(
            entity,
            observables,
            entities,
            predicted_rels,
            bypass_validation,
            file_name,
            uuid_to_stix,
            uuid_to_text,
        )

        # Build an end‐user summary
        if all(
            counts[k] == 0
            for k in (
                "observables",
                "entities",
                "relationships",
                "report",
                "total_sent",
            )
        ):
            return "No STIX objects sent — empty extraction or all filtered out."

        skipped = counts.get("skipped_rels", [])
        summary_lines = []

        if self.helper.get_validate_before_import() and not bypass_validation:
            summary_lines.append(
                f"Generated STIX bundle (awaiting validation) with: "
                f"{counts['observables']} observables, "
                f"{counts['entities']} entities, "
                f"{counts['relationships']} relationships"
                + (f", {counts['report']} report" if counts["report"] else "")
            )
        else:
            summary_lines.append(
                f"Sent STIX bundle with: "
                f"{counts['observables']} observables, "
                f"{counts['entities']} entities, "
                f"{counts['relationships']} relationships"
                + (f", {counts['report']} report" if counts["report"] else "")
                + f" (total sent = {counts['total_sent']})"
            )
        if skipped:
            summary_lines.append(
                f", and {len(skipped)} unauthorized relationships were skipped."
            )

        return "\n".join(summary_lines)

    def start(self) -> None:
        """Begin listening for messages on the queue. Each message will trigger `_process_message`."""
        self.helper.listen(self._process_message)

    def _download_import_file(self, data: dict) -> tuple[str, BytesIO]:
        """Download the file from OpenCTI using the 'file_fetch' path.

        Args:
            data (dict): Payload provided by OpenCTI when triggering the connector.

        Returns:
            tuple[str, BytesIO]: The local filename and a buffer of its contents.
        """
        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch

        # Downloading and saving file to buffer
        self.helper.connector_logger.info(f"Importing the file {file_uri}")
        file_name = os.path.basename(file_fetch)
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)

        buffer = BytesIO()
        buffer.write(file_content)
        buffer.seek(0)

        return file_name, buffer

    def _dedupe_parsed(self, parsed: dict) -> dict:
        """Deduplicate span entities by (label, text, type) and remap relation IDs.

        - First occurrence wins (case-insensitive, text trimmed).
        - Rewrites relations' from_id/to_id to the kept ID.
        - Preserves all other top-level and metadata fields.

        Args:
            parsed (dict): Full JSON payload returned by the Import-Document-AI web service.

        Returns:
            dict: A new payload with:
                - `metadata.span_based_entities` deduplicated (first occurrence wins),
                - `relations` endpoints (`from_id`/`to_id`) rewritten to canonical IDs,
                - all other fields preserved unchanged.
        """
        metadata = parsed.get("metadata", {}) or {}
        span = parsed.get("metadata", {}).get("span_based_entities", [])
        rels = parsed.get("relations", [])

        # case-insensitive, whitespace-trimmed key; first occurrence wins
        buckets: "OrderedDict[tuple, dict]" = OrderedDict()
        id_map: dict[str, str] = {}

        for item in span:
            label = str(item.get("label", "")).strip()
            text = str(item.get("text", "")).strip()
            typ = item.get("type")
            key = (label.lower(), text.lower(), typ)
            if key not in buckets:
                buckets[key] = {
                    "id": item["id"],
                    "label": item["label"],
                    "text": item["text"],
                    "type": item["type"],
                }
            # map every original id to the kept id
            id_map[item["id"]] = buckets[key]["id"]

        new_rels = []
        for relation in rels:
            new_rels.append(
                {
                    **relation,
                    "from_id": id_map.get(
                        relation.get("from_id"), relation.get("from_id")
                    ),
                    "to_id": id_map.get(relation.get("to_id"), relation.get("to_id")),
                }
            )

        if len(span) != len(buckets):
            self.helper.connector_logger.debug(
                f"Deduped span entities: kept {len(buckets)} of {len(span)}; "
                f"remapped {len(new_rels)} relations."
            )

        new_parsed = dict(parsed)
        new_metadata = dict(metadata)
        new_metadata["span_based_entities"] = list(buckets.values())
        new_parsed["metadata"] = new_metadata
        new_parsed["relations"] = new_rels
        return new_parsed

    def _process_parsing_results(
        self, parsed: dict, context_entity: dict | None
    ) -> tuple[list[dict], list[dict], UuidToStix, dict[str, str]]:
        """Convert Model output to STIX objects and build lookup tables.

        The function iterates over ``parsed["metadata"]["span_based_entities"]`` and
        creates **one** STIX object (observable *or* domain entity) for each unique
        couple *(surface_string, label)*. Deduplication is performed on a
        lower-cased key, so the first occurrence wins — this guarantees that offsets
        returned by the web-service still match the object kept in STIX.

        Besides returning the newly created objects, the function builds three
        look-up maps used later when wiring relationships:

            * **uuid_to_stix** Mapping **Orion UUID → STIX ID**.
            * **uuid_to_text** Mapping **Orion UUID → original surface string**.

        Args:
            parsed (dict): Full JSON payload returned by the Import-Document-AI web-service.
            context_entity (dict | None): Optional STIX object from OpenCTI used as import context
                (e.g. an existing *Report* or *Incident*).
                Markings / author are copied from it when present.

        Returns:
            tuple[ list[dict], list[dict], dict[Key, StixID], dict[Key, StixObject],
            UuidToStix, dict[str, str], ]:
            Tuple with:

                * **observables** (list[dict]): New SCOs (IPv4, domain-name…).
                * **entities** (list[dict]): New SDOs (Malware, Vulnerability…).
                * **uuid_to_stix** (dict): Orion UUID ➜ STIX ID.
                * **uuid_to_text** (dict): Orion UUID ➜ surface string.
        """
        observables: list[dict] = []
        entities: list[dict] = []

        # Collect markings and author from the context entity, if any
        if context_entity is not None:
            object_markings = [
                x["standard_id"] for x in context_entity.get("objectMarking", [])
            ]
            created_by = context_entity.get("createdBy")
            author = created_by.get("standard_id") if created_by else None
        else:
            object_markings = []
            author = None

        # Iterate over entities/observables extracted by the ML model
        span_entities = parsed["metadata"]["span_based_entities"]
        uuid_to_stix: UuidToStix = {}
        uuid_to_text: dict[str, str] = {}

        for match in span_entities:
            category: str = match["label"]
            txt: str | None = self._sanitise_name(match["text"])
            if not txt:
                # text must be at least 2 characters in length
                # Skip objects like "." or empty strings: they would break GraphQL
                self.helper.connector_logger.debug(
                    f"Skip object with invalid name: {match["text"]!r}"
                )
                continue

            if match["type"] == "entity":
                # ATT&CK patterns: read-first (OR on x_mitre_id/name); create only if not found
                # If it's an MITRE TTP (Attack-Pattern.x_mitre_id) and already exists, fetch that instead
                if category == "Attack-Pattern.x_mitre_id":
                    ttp_object = self.helper.api.attack_pattern.read(
                        filters={
                            "mode": "or",
                            "filters": [
                                {"key": "x_mitre_id", "values": [txt]},
                                {"key": "name", "values": [txt]},
                            ],
                            "filterGroups": [],
                        }
                    )
                    if ttp_object:  # Handles the case of an existing TTP
                        stix_object = self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                            entity_type=ttp_object["entity_type"],
                            entity_id=ttp_object["id"],
                            only_entity=True,
                        )
                    else:
                        stix_object = create_stix_object(
                            category,
                            txt,
                            object_markings,
                            custom_properties={
                                "created_by_ref": author,
                            },
                        )
                else:
                    # Other SDOs: create directly; OpenCTI will merge on deterministic IDs
                    stix_object = create_stix_object(
                        category,
                        txt,
                        object_markings,
                        custom_properties={
                            "created_by_ref": author,
                        },
                    )

                if stix_object:
                    entities.append(stix_object)
                    # store full object
                    uuid_to_stix[match["id"]] = stix_object["id"]
                    uuid_to_text[match["id"]] = txt
                else:
                    self.helper.connector_logger.debug(
                        f"Unsupported entity category: {match}"
                    )

            elif match["type"] == "observable":
                # Create a STIX Cyber Observable (IPv4Address, DomainName, etc.)
                stix_object = create_stix_object(
                    category,
                    txt,
                    object_markings,
                    custom_properties={
                        "x_opencti_create_indicator": self.create_indicator,
                        "created_by_ref": author,
                    },
                )
                if stix_object:
                    observables.append(stix_object)
                    uuid_to_stix[match["id"]] = stix_object["id"]
                    uuid_to_text[match["id"]] = txt
                else:
                    self.helper.connector_logger.debug(
                        f"Unsupported observable category: {match}"
                    )

            else:
                self.helper.connector_logger.debug(
                    f"Unsupported match type: {match.get('type')!r} for {match}"
                )

        return (
            observables,
            entities,
            uuid_to_stix,
            uuid_to_text,
        )

    def _convert_id(self, type, standard_id):
        if type == "Case-Incident":
            return "x-opencti-" + standard_id
        if type == "Case-Rfi":
            return "x-opencti-" + standard_id
        if type == "Case-Rft":
            return "x-opencti-" + standard_id
        if type == "Feedback":
            return "x-opencti-" + standard_id
        if type == "Task":
            return "x-opencti-" + standard_id
        if type == "Data-Component":
            return "x-mitre-" + standard_id
        if type == "Data-Source":
            return "x-mitre-" + standard_id
        return standard_id

    def _process_parsed_objects(
        self,
        entity: dict | None,
        observables: list,
        entities: list,
        predicted_rels: list,
        bypass_validation: bool,
        file_name: str,
        uuid_to_stix: UuidToStix,
        uuid_to_text: dict[str, str],
    ) -> dict:
        """Create relationships, wrap in Report if needed, and push the bundle.

        Args:
            entity (dict | None): Contextual STIX object coming from OpenCTI, or ``None`` when
                the import should create a brand-new *Report*.
            observables (list): STIX Cyber Observables (SCOs) created from the file.
            entities (list): STIX Domain Objects (SDOs) created from the file.
            predicted_rels (list): Raw relations predicted by Orion
                (each item has ``from_id``, ``to_id`` and ``type``).
            bypass_validation (bool): If *True*, the connector skips OpenCTI
                GraphQL validation when sending the bundle.
            file_name (str): Original file name (used for the generated Report bundle).
            uuid_to_stix (UuidToStix): Map Orion UUID → STIX ID (used to resolve relations).
            uuid_to_text (dict[str, str]): Map Orion UUID → surface string (for logging only).

        Raises:
            ValueError: If the context *entity* cannot be fetched/exported.

        Returns:
            dict: Counters of what was finally sent to OpenCTI, e.g.::

            {
                "observables": 17,
                "entities": 9,
                "relationships": 6,
                "report": 1,          # 0 if context entity was used
                "total_sent": 33,
                "skipped_rels": [ ... ]  # list of 5-tuples logged & skipped
            }
        """
        # If no objects at all, return zeros
        if len(observables) == 0 and len(entities) == 0:
            return {
                "observables": 0,
                "entities": 0,
                "relationships": 0,
                "report": 0,
                "total_sent": 0,
            }

        ids: list[str] = []
        observables_ids: list[str] = []
        entities_ids: list[str] = []
        skipped_rels: set[tuple[str, str, str, str, str]] = set()

        for o in observables:
            if o["id"] not in ids:
                observables_ids.append(o["id"])
                ids.append(o["id"])
        for e in entities:
            if e["id"] not in ids:
                entities_ids.append(e["id"])
                ids.append(e["id"])

        relationships: list[stix2.Relationship] = []  # accumulate all relationships

        report_is_update = entity is not None

        # Build relationships defined by the connector's own rules
        # 1. Add relationships that stem from the contextual “entity”
        if entity is not None:
            entity_stix_bundle = (
                self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                    entity_type=entity["entity_type"], entity_id=entity["id"]
                )
            )
            if len(entity_stix_bundle["objects"]) == 0:
                raise ValueError("Entity cannot be found or exported")

            entity_stix = [
                obj
                for obj in entity_stix_bundle["objects"]
                if obj["id"]
                == self._convert_id(entity["entity_type"], entity["standard_id"])
            ][0]

            # Containers: put everything inside
            if entity_stix["type"] in {
                "report",
                "grouping",
                "x-opencti-case-incident",
                "x-opencti-case-rfi",
                "x-opencti-case-rft",
                "note",
                "opinion",
            }:
                entity_stix["object_refs"] = (
                    entity_stix.get("object_refs", []) + observables_ids + entities_ids
                )
                entity_stix["x_opencti_files"] = [self.file] if self.file else []

            # Observed-data: only observables
            elif entity_stix["type"] == "observed-data":
                entity_stix["object_refs"] = (
                    entity_stix.get("object_refs", []) + observables_ids
                )

            # Other entities: create “related-to” relationships
            else:
                for observable in observables:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable["id"], entity_stix["id"]
                            ),
                            relationship_type="related-to",
                            source_ref=observable["id"],
                            target_ref=entity_stix["id"],
                            allow_custom=True,
                        )
                    )

                # Additional hard-coded logic (incident/threat-actor) unchanged
                if entity_stix["type"] == "incident":
                    for eid in entities_ids:
                        if eid.startswith("intrusion-set"):
                            rel_type = "attributed-to"
                        elif eid.startswith("vulnerability"):
                            rel_type = "targets"
                        elif eid.startswith("attack-pattern"):
                            rel_type = "uses"
                        else:
                            rel_type = None

                        if rel_type:
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        rel_type, entity_stix["id"], eid
                                    ),
                                    relationship_type=rel_type,
                                    source_ref=entity_stix["id"],
                                    target_ref=eid,
                                    allow_custom=True,
                                )
                            )

                if entity_stix["type"] == "threat-actor":
                    for entity_id in entities_ids:
                        if entity_id.startswith("vulnerability"):
                            rel_type = "targets"
                        elif entity_id.startswith("attack-pattern"):
                            rel_type = "uses"
                        else:
                            rel_type = None

                        if rel_type:
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        rel_type, entity_stix["id"], entity_id
                                    ),
                                    relationship_type=rel_type,
                                    source_ref=entity_stix["id"],
                                    target_ref=entity_id,
                                    allow_custom=True,
                                )
                            )

            # Add entity back to observables for the bundle
            observables.append(entity_stix)

        # Process predicted relationships (always)
        # ------------------------------------------------------------
        # 2. Relationships predicted by the ML model
        # Create relationships predicted by the ML model
        for rel in predicted_rels:

            rel_type = rel.get("type")

            src_id = uuid_to_stix.get(rel.get("from_id"))
            tgt_id = uuid_to_stix.get(rel.get("to_id"))
            src_txt = uuid_to_text.get(rel.get("from_id"), "<unknown>")
            tgt_txt = uuid_to_text.get(rel.get("to_id"), "<unknown>")

            if not src_id or not tgt_id or src_id == tgt_id or not rel_type:
                self.helper.connector_logger.warning(
                    "Skipped relation (missing data): %s", rel
                )
                continue

            from_type = stix_lookup_type(
                next(o for o in observables + entities if o["id"] == src_id)
            )
            to_type = stix_lookup_type(
                next(o for o in observables + entities if o["id"] == tgt_id)
            )

            if is_relation_allowed(
                self.allowed_relations, from_type, to_type, rel_type
            ):
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(rel_type, src_id, tgt_id),
                        relationship_type=rel_type,
                        source_ref=src_id,
                        target_ref=tgt_id,
                        allow_custom=True,
                    )
                )
            else:
                self.helper.connector_logger.warning(
                    f"Skipping incompatible relationship {rel_type} between "
                    f"{src_txt} ({src_id}) and {tgt_txt} ({tgt_id})"
                )
                skipped_rels.add((src_txt, from_type, rel_type, tgt_txt, to_type))

        # Final relationships deduplication
        # Dedupe relationships before counting/report wrap
        relationships = list({r.id: r for r in relationships}.values())
        relationship_ids: list[str] = [rel["id"] for rel in relationships]

        # wrap in a Report if no context
        if entity is None:
            # No context entity: wrap everything in a freshly created Report
            now = datetime.now(timezone.utc)
            report = stix2.Report(
                id=Report.generate_id(file_name, now),
                name="import-document-ai_" + file_name,
                description="Automatic import",
                published=now,
                report_types=["threat-report"],
                object_refs=observables_ids + entities_ids + relationship_ids,
                allow_custom=True,
                custom_properties={"x_opencti_files": [self.file] if self.file else []},
            )
            observables += [report]

        # Final bundle: observables,  entities, relationships, report
        bundle_objects = observables + entities + relationships

        # ------------------------------------------------------------
        # (3) Deduplicate objects and send bundle
        # ------------------------------------------------------------
        # dedupe final objects by id
        final_ids: list[str] = []
        final_objects: list[dict] = []
        for obj in bundle_objects:
            # Keep only objects whose name field is OK
            bad_name = (
                "name" in obj and isinstance(obj["name"], str) and len(obj["name"]) < 2
            )
            if bad_name:
                self.helper.connector_logger.debug(
                    f"Skipping object with short name: {obj}"
                )
            if obj["id"] in final_ids:
                self.helper.connector_logger.debug(
                    f"Duplicate object skipped: {obj['id']}"
                )
            if obj["id"] not in final_ids and not bad_name:
                final_ids.append(obj["id"])
                final_objects.append(obj)

        bundle = stix2.Bundle(objects=final_objects, allow_custom=True)

        if not self.include_relationships:
            bundle = remove_all_relationships(bundle)

        bundles_sent = self.helper.send_stix2_bundle(
            bundle=bundle.serialize(),
            bypass_validation=bypass_validation,
            file_name="import-document-ai-" + Path(file_name).stem + ".json",
            entity_id=entity["id"] if entity else None,
        )

        return {
            **compute_bundle_stats(bundle),
            "skipped_rels": list(skipped_rels),
        }
