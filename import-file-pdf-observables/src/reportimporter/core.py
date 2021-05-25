# coding: utf-8
import os
from typing import Dict, List
import yaml
from stix2 import Bundle, Report, Vulnerability
from pycti import (
    OpenCTIConnectorHelper,
    OpenCTIStix2Utils,
    get_config_variable,
    SimpleObservable,
)
from pydantic import BaseModel
from reportimporter.util import MyConfigParser
from reportimporter.models import Observable, EntityConfig, Entity
from reportimporter.report_parser import ReportParser
from reportimporter.constants import (
    RESULT_FORMAT_TYPE,
    RESULT_FORMAT_MATCH,
    RESULT_FORMAT_CATEGORY,
    OBSERVABLE_CLASS,
    ENTITY_CLASS,
)


class ReportImporter:
    def __init__(self) -> None:
        # Instantiate the connector helper from config
        base_path = os.path.dirname(os.path.abspath(__file__))
        config_file_path = base_path + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.create_indicator = get_config_variable(
            "PDF_OBSERVABLES_CREATE_INDICATOR",
            ["pdf_observables", "create_indicator"],
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
        file_name = self._download_import_file(data)
        entity_id = data.get("entity_id", None)
        if self._check_context(entity_id):
            raise ValueError(
                "No context defined, connector is get_only_contextual true"
            )

        # Retrieve entity set from OpenCTI
        entity_indicators = self._collect_stix_objects(self.entity_config)

        # Parse peport
        parser = ReportParser(self.helper, entity_indicators, self.observable_config)
        parsed = parser.run_parser(file_name, data["file_mime"])
        os.remove(file_name)

        if not parsed:
            return "No information extracted from report"

        # Process parsing results
        self.helper.log_info("Results: {}".format(parsed))
        observables, entities = self._process_parsing_results(parsed)
        report = self.helper.api.report.read(id=entity_id)
        # Send results to OpenCTI
        observable_cnt = self._process_observables(report, observables)
        entity_cnt = self._process_entities(report, entities)

        return f"Sent {observable_cnt} stix bundle(s) and {entity_cnt} entity connections for worker import"

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

    def _check_context(self, entity_id: str) -> bool:
        is_context = entity_id and len(entity_id) > 0
        return self.helper.get_only_contextual() and not is_context

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
                entity_list += entity_config.convert_to_entity(entries)
            except AttributeError:
                e = "Selected parser format is not supported: %s" % func_format
                raise NotImplementedError(e)

        return entity_list

    def _parse_config(self, config_file: str, file_class: BaseModel) -> List[BaseModel]:
        config = MyConfigParser()
        config.read(config_file)

        config_list = []
        for section, content in config.as_dict().items():
            content["name"] = section
            config_object = file_class(**content)
            config_list.append(config_object)

        return config_list

    def _process_parsing_results(
        self, parsed: List[Dict]
    ) -> (List[SimpleObservable], List[str]):
        observables = []
        entities = []
        for match in parsed:
            if match[RESULT_FORMAT_TYPE] == OBSERVABLE_CLASS:
                # Hardcoded exceptions since SimpleObservable doesn't support those types yet
                if match[RESULT_FORMAT_CATEGORY] == "Vulnerability.name":
                    observable = Vulnerability(name=match[RESULT_FORMAT_MATCH])
                else:
                    observable = SimpleObservable(
                        id=OpenCTIStix2Utils.generate_random_stix_id(
                            "x-opencti-simple-observable"
                        ),
                        key=match[RESULT_FORMAT_CATEGORY],
                        value=match[RESULT_FORMAT_MATCH],
                        x_opencti_create_indicator=self.create_indicator,
                    )

                observables.append(observable)
            elif match[RESULT_FORMAT_TYPE] == ENTITY_CLASS:
                entities.append(match[RESULT_FORMAT_MATCH])
            else:
                self.helper.log_info("Odd data received: {}".format(match))

        return observables, entities

    def _process_observables(self, report: Dict, observables: List) -> int:
        if report is not None:
            if report["entity_type"] == "Report" and len(observables) > 0:
                report = Report(
                    id=report["standard_id"],
                    name=report["name"],
                    description=report["description"],
                    published=self.helper.api.stix2.format_date(report["created"]),
                    report_types=report["report_types"],
                    object_refs=observables,
                )
                observables.append(report)

        bundles_sent = []
        if len(observables) > 0:
            bundle = Bundle(objects=observables).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)

        # -1 since report gets updated as well
        return len(bundles_sent) - 1

    def _process_entities(self, report: Dict, entities: List) -> int:
        if report:
            for stix_object in entities:
                self.helper.api.report.add_stix_object_or_stix_relationship(
                    id=report["id"], stixObjectOrStixRelationshipId=stix_object
                )

        return len(entities)
