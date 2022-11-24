import base64
import os
import time
from datetime import datetime
from typing import Callable, Dict, List

import humps
import stix2
import yaml
from pycti import (
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    get_config_variable,
)
from pydantic import BaseModel
from reportimporter.constants import (
    ENTITY_CLASS,
    OBSERVABLE_CLASS,
    RESULT_FORMAT_CATEGORY,
    RESULT_FORMAT_MATCH,
    RESULT_FORMAT_TYPE,
)
from reportimporter.models import Entity, EntityConfig, Observable
from reportimporter.report_parser import ReportParser
from reportimporter.util import MyConfigParser


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
        )
        self.current_file = None

        # Load Entity and Observable configs
        observable_config_file = base_path + "/config/observable_config.ini"
        entity_config_file = base_path + "/config/entity_config.ini"

        if os.path.isfile(observable_config_file) and os.path.isfile(
            entity_config_file
        ):
            self.observable_config = self._parse_config(
                observable_config_file, Observable
            )
        else:
            raise FileNotFoundError(f"{observable_config_file} was not found")

        if os.path.isfile(entity_config_file):
            self.entity_config = self._parse_config(entity_config_file, EntityConfig)
        else:
            raise FileNotFoundError(f"{entity_config_file} was not found")

        self.file = None

    def _process_message(self, data: Dict) -> str:
        self.helper.log_info("Processing new message")
        file_name = self._download_import_file(data)
        entity_id = data.get("entity_id", None)
        bypass_validation = data.get("bypass_validation", False)
        entity = (
            self.helper.api.stix_domain_object.read(id=entity_id)
            if entity_id is not None
            else None
        )
        if self.helper.get_only_contextual() and entity is None:
            return "Connector is only contextual and entity is not defined. Nothing was imported"

        # Retrieve entity set from OpenCTI
        entity_indicators = self._collect_stix_objects(self.entity_config)

        # Parse report
        parser = ReportParser(self.helper, entity_indicators, self.observable_config)

        if data["file_id"].startswith("import/global"):
            file_data = open(file_name, "rb").read()
            file_data_encoded = base64.b64encode(file_data)
            self.file = {
                "name": data["file_id"].replace("import/global/", ""),
                "data": file_data_encoded,
                "mime_type": "application/pdf",
            }
        parsed = parser.run_parser(file_name, data["file_mime"])
        os.remove(file_name)

        if not parsed:
            return "No information extracted from report"

        # Process parsing results
        self.helper.log_debug("Results: {}".format(parsed))
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

    def _download_import_file(self, data: Dict) -> str:
        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch

        # Downloading and saving file to connector
        self.helper.log_info("Importing the file " + file_uri)
        file_name = os.path.basename(file_fetch)
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)

        with open(file_name, "wb") as f:
            f.write(file_content)

        return file_name

    def _collect_stix_objects(
        self, entity_config_list: List[EntityConfig]
    ) -> List[Entity]:
        base_func = self.helper.api
        entity_list = []
        for entity_config in entity_config_list:
            func_format = entity_config.stix_class
            try:
                custom_function = getattr(base_func, func_format)
                entries = custom_function.list(
                    getAll=True,
                    filters=entity_config.filter,
                    customAttributes=entity_config.custom_attributes,
                )
                entity_list += entity_config.convert_to_entity(entries, self.helper)
            except AttributeError:
                e = "Selected parser format is not supported: {}".format(func_format)
                raise NotImplementedError(e)

        return entity_list

    @staticmethod
    def _parse_config(config_file: str, file_class: Callable) -> List[BaseModel]:
        config = MyConfigParser()
        config.read(config_file)

        config_list = []
        for section, content in config.as_dict().items():
            content["name"] = section
            config_object = file_class(**content)
            config_list.append(config_object)

        return config_list

    def _process_parsing_results(
        self, parsed: List[Dict], context_entity: Dict
    ) -> (List[Dict], List[str]):
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
            if match[RESULT_FORMAT_TYPE] == OBSERVABLE_CLASS:
                if match[RESULT_FORMAT_CATEGORY] == "Vulnerability.name":
                    entity = self.helper.api.vulnerability.read(
                        filters={"key": "name", "values": [match[RESULT_FORMAT_MATCH]]}
                    )
                    if entity is None:
                        self.helper.log_info(
                            f"Vulnerability with name '{match[RESULT_FORMAT_MATCH]}' could not be "
                            f"found. Is the CVE Connector activated?"
                        )
                        continue
                    entity_stix_bundle = self.helper.api.stix2.export_entity(
                        entity["entity_type"], entity["id"]
                    )
                    if len(entity_stix_bundle["objects"]) == 0:
                        raise ValueError("Entity cannot be found or exported")
                    entity_stix = [
                        object
                        for object in entity_stix_bundle["objects"]
                        if "x_opencti_id" in object
                        and object["x_opencti_id"] == entity["id"]
                    ][0]
                    entities.append(entity_stix)
                elif match[RESULT_FORMAT_CATEGORY] == "Attack-Pattern.x_mitre_id":
                    entity = self.helper.api.attack_pattern.read(
                        filters={
                            "key": "x_mitre_id",
                            "values": [match[RESULT_FORMAT_MATCH]],
                        }
                    )
                    if entity is None:
                        self.helper.log_info(
                            f"AttackPattern with MITRE ID '{match[RESULT_FORMAT_MATCH]}' could not be "
                            f"found. Is the MITRE Connector activated?"
                        )
                        continue
                    entity_stix_bundle = self.helper.api.stix2.export_entity(
                        entity["entity_type"], entity["id"]
                    )
                    if len(entity_stix_bundle["objects"]) == 0:
                        raise ValueError("Entity cannot be found or exported")
                    entity_stix = [
                        object
                        for object in entity_stix_bundle["objects"]
                        if "x_opencti_id" in object
                        and object["x_opencti_id"] == entity["id"]
                    ][0]
                    entities.append(entity_stix)
                else:
                    observable = None
                    if match[RESULT_FORMAT_CATEGORY] == "Autonomous-System.number":
                        observable = stix2.AutonomousSystem(
                            number=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Domain-Name.value":
                        observable = stix2.DomainName(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Email-Addr.value":
                        observable = stix2.EmailAddress(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "File.name":
                        observable = stix2.File(
                            name=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "IPv4-Addr.value":
                        observable = stix2.IPv4Address(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "IPv6-Addr.value":
                        observable = stix2.IPv6Address(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Mac-Addr.value":
                        observable = stix2.MACAddress(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "File.hashes.MD5":
                        observable = stix2.File(
                            hashes={"MD5": match[RESULT_FORMAT_MATCH]},
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "File.hashes.SHA-1":
                        observable = stix2.File(
                            hashes={"SHA-1": match[RESULT_FORMAT_MATCH]},
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "File.hashes.SHA-256":
                        observable = stix2.File(
                            hashes={"SHA-256": match[RESULT_FORMAT_MATCH]},
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Windows-Registry-Key.key":
                        observable = stix2.WindowsRegistryKey(
                            key=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Url.value":
                        observable = stix2.URL(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": self.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    if observable is not None:
                        observables.append(observable)

            elif match[RESULT_FORMAT_TYPE] == ENTITY_CLASS:
                stix_type = "-".join(
                    x[:1].upper() + x[1:]
                    for x in match[RESULT_FORMAT_CATEGORY].split("_")
                )
                entity_stix_bundle = self.helper.api.stix2.export_entity(
                    stix_type, match[RESULT_FORMAT_MATCH]
                )
                if len(entity_stix_bundle["objects"]) == 0:
                    raise ValueError("Entity cannot be found or exported")
                entity_stix = [
                    object
                    for object in entity_stix_bundle["objects"]
                    if object["id"] == match[RESULT_FORMAT_MATCH]
                ][0]
                entities.append(entity_stix)
            else:
                self.helper.log_info("Odd data received: {}".format(match))

        return observables, entities

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
            entity_stix_bundle = self.helper.api.stix2.export_entity(
                entity["entity_type"], entity["id"]
            )
            if len(entity_stix_bundle["objects"]) == 0:
                raise ValueError("Entity cannot be found or exported")
            entity_stix = [
                object
                for object in entity_stix_bundle["objects"]
                if object["id"] == entity["standard_id"]
            ][0]
            relationships = []
            # For containers, just insert everything in it
            if (
                entity_stix["type"] == "report"
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
                                "related-to", observable["id"], entity_stix_bundle["id"]
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
                        if (
                            entity_id.startswith("threat-actor")
                            or entity_id.startswith("intrusion-set")
                            or entity_id.startswith("campaign")
                        ):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "attributed-to",
                                        entity_stix["id"],
                                        entity["id"],
                                    ),
                                    relationship_type="attributed-to",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity,
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
                                        entity["id"],
                                    ),
                                    relationship_type="targets",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity,
                                    allow_custom=True,
                                )
                            )
                        # Incident uses Attack Patterns
                        elif entity_id.startswith("attack-pattern"):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses", entity_stix["id"], entity["id"]
                                    ),
                                    relationship_type="uses",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity,
                                    allow_custom=True,
                                )
                            )
            observables = observables + relationships
            observables.append(entity_stix)
        else:
            timestamp = int(time.time())
            now = datetime.utcfromtimestamp(timestamp)
            report = stix2.Report(
                id=Report.generate_id(file_name, now),
                name=file_name,
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
            print(final_objects)
            bundle = stix2.Bundle(objects=final_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(
                bundle=bundle,
                update=True,
                bypass_validation=bypass_validation,
                file_name=file_name + ".json",
                entity_id=entity["id"] if entity is not None else None,
            )

        # len() - 1 because the report update increases the count by one
        return len(bundles_sent) - 1
