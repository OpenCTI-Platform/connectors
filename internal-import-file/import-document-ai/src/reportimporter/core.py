import base64
import os
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Tuple

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
            default="https://importdoc.ariane.filigran.io",
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

    def _process_message(self, data: Dict) -> str:
        self.helper.connector_logger.info("Processing new message")
        self.file = None
        return self._process_import(data)

    def _process_import(self, data: Dict) -> str:
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
        # Parse report from web service
        try:
            response = requests.post(
                url=self.web_service_url + "/extract_entities",
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
        # Process parsing results
        self.helper.connector_logger.debug(f"Results: {parsed}")
        observables, entities = self._process_parsing_results(parsed, entity)
        # Send results to OpenCTI
        observable_cnt = self._process_parsed_objects(
            entity, observables, entities, bypass_validation, file_name
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

    def _download_import_file(self, data: Dict) -> Tuple[str, BytesIO]:
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
        self, parsed: List[Dict], context_entity: Dict
    ) -> Tuple[List[Dict], List[str]]:
        observables = []
        entities = []
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
        if author is not None:
            author = author.get("standard_id", None)

        for match in parsed:
            if match[RESULT_FORMAT_TYPE] == "entity":
                stix_object = create_stix_object(
                    match[RESULT_FORMAT_CATEGORY],
                    match[RESULT_FORMAT_MATCH],
                    object_markings,
                    custom_properties={
                        "created_by_ref": author,
                    },
                )
                if match[RESULT_FORMAT_CATEGORY] == "Attack-Pattern.x_mitre_id":
                    ttp_object = self.helper.api.attack_pattern.read(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "x_mitre_id",
                                    "values": [match[RESULT_FORMAT_MATCH]],
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
                entities.append(stix_object)
            if match[RESULT_FORMAT_TYPE] == "observable":
                stix_object = create_stix_object(
                    match[RESULT_FORMAT_CATEGORY],
                    match[RESULT_FORMAT_MATCH],
                    object_markings,
                    custom_properties={
                        "x_opencti_create_indicator": self.create_indicator,
                        "created_by_ref": author,
                    },
                )
                observables.append(stix_object)
        return observables, entities

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
        entity: Dict,
        observables: List,
        entities: List,
        bypass_validation: bool,
        file_name: str,
    ) -> int:
        if len(observables) == 0 and len(entities) == 0:
            return 0
        ids = []
        observables_ids = []
        entities_ids = []
        for o in observables:
            if o["id"] not in ids:
                observables_ids.append(o["id"])
                ids.append(o["id"])
        for e in entities:
            if e["id"] not in ids:
                entities_ids.append(e["id"])
                ids.append(e["id"])
        if entity is not None:
            entity_stix_bundle = (
                self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                    entity_type=entity["entity_type"], entity_id=entity["id"]
                )
            )
            if len(entity_stix_bundle["objects"]) == 0:
                raise ValueError("Entity cannot be found or exported")
            entity_stix = [
                object
                for object in entity_stix_bundle["objects"]
                if object["id"]
                == self._convert_id(entity["entity_type"], entity["standard_id"])
            ][0]
            relationships = []
            # For containers, just insert everything in it
            if (
                entity_stix["type"] == "report"
                or entity_stix["type"] == "grouping"
                or entity_stix["type"] == "x-opencti-case-incident"
                or entity_stix["type"] == "x-opencti-case-rfi"
                or entity_stix["type"] == "x-opencti-case-rft"
                or entity_stix["type"] == "note"
                or entity_stix["type"] == "opinion"
            ):
                entity_stix["object_refs"] = (
                    entity_stix["object_refs"] + observables_ids + entities_ids
                    if "object_refs" in entity_stix
                    else observables_ids + entities_ids
                )
                entity_stix["x_opencti_files"] = (
                    [self.file] if self.file is not None else []
                )
            # For observed data, just insert all observables in it
            elif entity_stix["type"] == "observed-data":
                entity_stix["object_refs"] = (
                    entity_stix["object_refs"] + observables_ids
                    if "object_refs" in entity_stix
                    else observables_ids
                )
            else:
                # For all other entities, relate all observables
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
                if entity_stix["type"] == "incident":
                    for entity_id in entities_ids:
                        # Incident attributed-to Threats
                        if entity_id.startswith("intrusion-set"):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "attributed-to",
                                        entity_stix["id"],
                                        entity_id,
                                    ),
                                    relationship_type="attributed-to",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity_id,
                                    allow_custom=True,
                                )
                            )
                        # Incident targets Vulnerabilities
                        elif entity_id.startswith("vulnerability"):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "targets",
                                        entity_stix["id"],
                                        entity_id,
                                    ),
                                    relationship_type="targets",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity_id,
                                    allow_custom=True,
                                )
                            )
                        # Incident uses Attack Patterns
                        elif entity_id.startswith("attack-pattern"):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses", entity_stix["id"], entity_id
                                    ),
                                    relationship_type="uses",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity_id,
                                    allow_custom=True,
                                )
                            )
                if entity_stix["type"] == "threat-actor":
                    for entity_id in entities_ids:
                        # Threat actor targets Vulnerabilities
                        if entity_id.startswith("vulnerability"):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "targets",
                                        entity_stix["id"],
                                        entity_id,
                                    ),
                                    relationship_type="targets",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity_id,
                                    allow_custom=True,
                                )
                            )
                        # Threat Actor uses Attack Patterns
                        elif entity_id.startswith("attack-pattern"):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses", entity_stix["id"], entity_id
                                    ),
                                    relationship_type="uses",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity_id,
                                    allow_custom=True,
                                )
                            )
            observables = observables + relationships
            observables.append(entity_stix)
        else:
            now = datetime.now(timezone.utc)
            report = stix2.Report(
                id=Report.generate_id(file_name, now),
                name="import-document-ai" + file_name,
                description="Automatic import",
                published=now,
                report_types=["threat-report"],
                object_refs=observables_ids + entities_ids,
                allow_custom=True,
                custom_properties={
                    "x_opencti_files": [self.file] if self.file is not None else []
                },
            )
            observables.append(report)
        observables = observables + entities
        bundles_sent = []
        if len(observables) > 0:
            ids = []
            final_objects = []
            for object in observables:
                if object["id"] not in ids:
                    ids.append(object["id"])
                    final_objects.append(object)
            bundle = stix2.Bundle(objects=final_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(
                bundle=bundle,
                bypass_validation=bypass_validation,
                file_name="import-document-ai-" + Path(file_name).stem + ".json",
                entity_id=entity["id"] if entity is not None else None,
            )

        # len() - 1 because the report update increases the count by one
        return len(bundles_sent) - 1
