import os
from typing import Dict, List, Callable

import yaml
from pycti import (
    OpenCTIConnectorHelper,
    OpenCTIStix2Utils,
    get_config_variable,
    SimpleObservable,
)
from pydantic import BaseModel
from reportimporter.constants import (
    RESULT_FORMAT_TYPE,
    RESULT_FORMAT_MATCH,
    RESULT_FORMAT_CATEGORY,
    OBSERVABLE_CLASS,
    ENTITY_CLASS,
)
from reportimporter.models import Observable, EntityConfig, Entity
from reportimporter.report_parser import ReportParser
from reportimporter.util import MyConfigParser
from stix2 import Report, Bundle


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
            "IMPORT_REPORT_CREATE_INDICATOR",
            ["import_report", "create_indicator"],
            config,
        )

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
                    getAll=True, filters=entity_config.filter
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
    ) -> (List[SimpleObservable], List[str]):
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

                    entities.append(entity["standard_id"])
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

                    entities.append(entity["standard_id"])
                else:
                    observable = SimpleObservable(
                        id=OpenCTIStix2Utils.generate_random_stix_id(
                            "x-opencti-simple-observable"
                        ),
                        key=match[RESULT_FORMAT_CATEGORY],
                        value=match[RESULT_FORMAT_MATCH],
                        x_opencti_create_indicator=self.create_indicator,
                        object_marking_refs=object_markings,
                        created_by_ref=author,
                        # labels=labels,
                        # external_references=external_references
                    )
                    observables.append(observable)

            elif match[RESULT_FORMAT_TYPE] == ENTITY_CLASS:
                entities.append(match[RESULT_FORMAT_MATCH])
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

        if entity is not None and entity["entity_type"] == "Report":
            report = Report(
                id=entity["standard_id"],
                name=entity["name"],
                description=entity["description"],
                published=self.helper.api.stix2.format_date(entity["created"]),
                report_types=entity["report_types"],
                object_refs=observables + entities,
                allow_custom=True,
            )
            observables.append(report)
        elif entity is not None:
            # TODO, relate all object to the entity
            entity_stix_bundle = self.helper.api.stix2.export_entity(
                entity["entity_type"], entity["id"]
            )
            observables = observables + entity_stix_bundle["objects"]

        bundles_sent = []
        if len(observables) > 0:
            bundle = Bundle(objects=observables, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(
                bundle=bundle,
                update=True,
                bypass_validation=bypass_validation,
                file_name=file_name,
                entity_id=entity["id"] if entity is not None else None,
            )

        # len() - 1 because the report update increases the count by one
        return len(bundles_sent) - 1
