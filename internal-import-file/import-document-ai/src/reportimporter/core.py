import base64
import os
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
from reportimporter.constants import (
    RESULT_FORMAT_CATEGORY,
    RESULT_FORMAT_MATCH,
    RESULT_FORMAT_TYPE,
)
from reportimporter.util import create_stix_object
from requests.exceptions import ConnectionError, HTTPError


class ReportImporter:
    def __init__(self) -> None:
        # Instantiate the connector helper from config
        base_path = os.path.dirname(os.path.abspath(__file__))
        config_file_path = base_path + "/../config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
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

    @staticmethod
    def _sanitise_name(raw_text: str | None) -> str | None:
        """Return a clean name or None if it is too short ( < 2 chars )."""
        if not raw_text:
            return None
        cleaned = raw_text.strip().rstrip(",")
        return cleaned if len(cleaned) >= 2 else None

    def _process_message(self, data: dict) -> str:
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
        file_name, file_content_buffered = self._download_import_file(data)
        entity_id = data.get("entity_id", None)
        bypass_validation = data.get("bypass_validation", False)
        entity = (
            self.helper.api.stix_core_object.read(id=entity_id)
            if entity_id is not None
            else None
        )
        if self.helper.get_only_contextual() and entity is None:
            return "Connector is only contextual and entity is not defined. Nothing was imported"

        # Handles file attachment in the stix bundle
        if data["file_id"].startswith("import/global"):
            file_data_encoded = base64.b64encode(file_content_buffered.read())
            self.file = {
                "name": data["file_id"].replace("import/global/", ""),
                "data": file_data_encoded,
                "mime_type": data["file_mime"],
            }
            # Reset file offset
            file_content_buffered.seek(0)

        # Send to extract_entities_relations endpoint that also returns relationships by default
        try:
            response = requests.post(
                url=self.web_service_url + "/extract_entities_relations",
                params={"with_relations": "true"},
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

        # Parse and build STIX entities / observables, and map text to STIX id (for relationship linking)
        observables, entities, text_to_id = self._process_parsing_results(
            parsed, entity
        )
        predicted_rels = parsed.get("relationships", [])

        # Build and send STIX bundle to OpenCTI, including predicted relationships with relations handling fallback
        observable_cnt = self._process_parsed_objects(
            entity,
            observables,
            entities,
            predicted_rels,
            bypass_validation,
            file_name,
            text_to_id,
        )
        entity_cnt = len(entities)

        if self.helper.get_validate_before_import() and not bypass_validation:
            return "Generated bundle sent for validation"
        else:
            return (
                f"Sent {observable_cnt} observables, 1 report update and {entity_cnt} entity connections as stix "
                f"bundle for worker import "
            )

    def start(self) -> None:
        self.helper.listen(self._process_message)

    def _download_import_file(self, data: dict) -> tuple[str, BytesIO]:
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

    def _process_parsing_results(
        self, parsed: dict, context_entity: dict | None
    ) -> tuple[list[dict], list[dict], dict[str, str]]:
        observables = []
        entities = []
        text_to_id = {}  # text value -> STIX id

        # Collect markings and author from the context entity, if any
        if context_entity is not None:
            object_markings = [
                x["standard_id"] for x in context_entity.get("objectMarking", [])
            ]
            # external_references = [x['standard_id'] for x in report.get('externalReferences', [])]
            # labels = [x['standard_id'] for x in report.get('objectLabel', [])]
            author = context_entity.get("createdBy")
        else:
            object_markings = []
            author = None
        author = author.get("standard_id") if author else None

        # Iterate over entities/observables extracted by the ML model
        for match in parsed.get("entities", []):
            category = match[RESULT_FORMAT_CATEGORY]
            txt = self._sanitise_name(match[RESULT_FORMAT_MATCH])
            if not txt:
                # text must be at least 2 characters in length
                # Skip objects like "." or empty strings: they would break GraphQL
                self.helper.connector_logger.debug(
                    f"Skip object with invalid name: {match[RESULT_FORMAT_MATCH]!r}"
                )
                assert txt is not None

            if match[RESULT_FORMAT_TYPE] == "entity":
                stix_object = create_stix_object(
                    category,
                    txt,
                    object_markings,
                    custom_properties={
                        "created_by_ref": author,
                    },
                )
                # Fallback for MITRE ATT&CK IDs already existing in the database
                if category == "Attack-Pattern.x_mitre_id":
                    ttp_object = self.helper.api.attack_pattern.read(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "x_mitre_id",
                                    "values": [txt],
                                }
                            ],
                            "filterGroups": [],
                        }
                    )
                    if ttp_object:  # Handles the case of an existing TTP
                        stix_ttp = self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                            entity_type=ttp_object["entity_type"],
                            entity_id=ttp_object["id"],
                            only_entity=True,
                        )
                        stix_object = stix_ttp
                if stix_object:
                    entities.append(stix_object)
                    if txt not in text_to_id:
                        text_to_id[txt] = stix_object["id"]
                else:
                    self.helper.connector_logger.debug(
                        f"Unsupported entity category: {match}"
                    )

            if match[RESULT_FORMAT_TYPE] == "observable":
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
                    if txt not in text_to_id:
                        text_to_id[txt] = stix_object["id"]
                else:
                    self.helper.connector_logger.debug(
                        f"Unsupported observable category: {match}"
                    )

        return observables, entities, text_to_id

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
        text_to_id: dict,
    ) -> int:
        """Build STIX bundle: includes observables, entities, and predicted relationships.

        Args:
            entity (dict | None): The context STIX entity (e.g., report, case, threat actor).
                If provided, entities/observables will be attached to it accordingly.
            observables (list): A list of STIX Cyber Observables (e.g., IPv4, domain names).
            entities (list): A list of STIX Domain Objects (e.g., attack patterns, malware).
            predicted_rels (list): A list of predicted relationships (dicts with source/target text and relation type).
            bypass_validation (bool): If True, skips OpenCTI bundle validation before import.
            file_name (str): Name of the input file used for building the Report (if no context entity).
            text_to_id (dict): Mapping of matched text spans to their corresponding STIX IDs.

        Raises:
            ValueError: Raised if the context entity was expected but could not be found in OpenCTI.

        Returns:
            int: Number of objects successfully sent to OpenCTI (excluding report update, if any).
        """
        if len(observables) == 0 and len(entities) == 0:
            return 0

        ids: list[str] = []
        observables_ids: list[str] = []
        entities_ids: list[str] = []

        for o in observables:
            if o["id"] not in ids:
                observables_ids.append(o["id"])
                ids.append(o["id"])
        for e in entities:
            if e["id"] not in ids:
                entities_ids.append(e["id"])
                ids.append(e["id"])

        relationships: list[stix2.Relationship] = []  # accumulate all relationships

        # Build relationships defined by the connector's own rules
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

            observables = observables + relationships + [entity_stix]

        else:

            # ------------------------------------------------------------
            # Create relationships predicted by the ML model
            for rel in predicted_rels:
                src_txt = rel.get("source_text") or rel.get("from")
                dst_txt = rel.get("target_text") or rel.get("to")
                rel_type = rel.get("relation_type")

                src_id = text_to_id.get(src_txt)
                dst_id = text_to_id.get(dst_txt)

                if not src_id or not dst_id or not rel_type or (src_id == dst_id):
                    self.helper.connector_logger.warning(
                        f"Skipped relation (missing data): {rel}"
                    )
                    continue

                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(rel_type, src_id, dst_id),
                        relationship_type=rel_type,
                        source_ref=src_id,
                        target_ref=dst_id,
                        allow_custom=True,
                    )
                )

            observables = observables + entities + relationships

            relationship_ids = [rel["id"] for rel in relationships]

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
            observables = observables + [report] + relationships

        # ------------------------------------------------------------
        # (3) Deduplicate objects and send bundle
        # ------------------------------------------------------------
        final_ids: list[str] = []
        final_objects: list[dict] = []
        for obj in observables:
            # Keep only objects whose name field is OK
            bad_name = isinstance(obj, dict) and "name" in obj and len(obj["name"]) < 2
            if obj["id"] not in final_ids and not bad_name:
                final_ids.append(obj["id"])
                final_objects.append(obj)

        bundle = stix2.Bundle(objects=final_objects, allow_custom=True).serialize()
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=bundle,
            bypass_validation=bypass_validation,
            file_name="import-document-ai-" + Path(file_name).stem + ".json",
            entity_id=entity["id"] if entity else None,
        )

        # len() - 1 because a report update is counted as an observable by OpenCTI
        return len(bundles_sent) - 1
