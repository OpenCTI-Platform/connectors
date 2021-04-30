# coding: utf-8

import os
from typing import Dict

import yaml
import time

import iocp
from stix2 import Bundle, Report, Vulnerability
from pycti import (
    OpenCTIConnectorHelper,
    OpenCTIStix2Utils,
    get_config_variable,
    SimpleObservable,
)


class ImportFilePdfObservables:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
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

    def _process_message(self, data):
        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch
        file_name = os.path.basename(file_fetch)
        entity_id = data["entity_id"]
        # Get context
        is_context = entity_id is not None and len(entity_id) > 0
        if self.helper.get_only_contextual() and not is_context:
            raise ValueError(
                "No context defined, connector is get_only_contextual true"
            )
        self.helper.log_info("Importing the file " + file_uri)
        # Get the file
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)
        # Write the file
        f = open(file_name, "wb")
        f.write(file_content)
        f.close()
        # Parse
        bundle_objects = []
        entities = []
        i = 0
        custom_indicators = self._get_entities()
        parser = iocp.IOC_Parser(None, "pdf", True, "pdfminer", "json", custom_indicators=custom_indicators)
        parsed = parser.parse(file_name)
        os.remove(file_name)
        if parsed != []:
            for file in parsed:
                if file != None:
                    for page in file:
                        if page != []:
                            for match in page:
                                resolved_match = self.resolve_match(match)
                                if resolved_match:
                                    if resolved_match["type"] == "Attack-Pattern.value":
                                        entity = self.helper.api.attack_pattern.read(
                                            filters=[
                                                {
                                                    "key": "x_mitre_id",
                                                    "values": [resolved_match["value"]],
                                                }
                                            ]
                                        )
                                        if entity:
                                            entities.append(entity)
                                        else:
                                            self.helper.log_info(
                                                f"Attack pattern {resolved_match['value']} was not found in OpenCTI."
                                                + "Is the mitre connector configured and running?"
                                            )
                                    elif resolved_match["type"] == "Vulnerability.name":
                                        vulnerability = Vulnerability(name=resolved_match["value"])
                                        bundle_objects.append(vulnerability)
                                    else:
                                        observable = SimpleObservable(
                                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                                "x-opencti-simple-observable"
                                            ),
                                            key=resolved_match["type"],
                                            value=resolved_match["value"],
                                            x_opencti_create_indicator=self.create_indicator,
                                        )
                                        bundle_objects.append(observable)
                                    i += 1
        else:
            self.helper.log_error("Could not parse the report!")

        if is_context:
            entity = self.helper.api.stix_domain_object.read(id=entity_id)
            if entity is not None:
                if entity["entity_type"] == "Report" and len(bundle_objects) > 0:
                    report = Report(
                        id=entity["standard_id"],
                        name=entity["name"],
                        description=entity["description"],
                        published=self.helper.api.stix2.format_date(entity["created"]),
                        report_types=entity["report_types"],
                        object_refs=bundle_objects,
                    )
                    bundle_objects.append(report)

        bundle = Bundle(objects=bundle_objects).serialize()
        bundles_sent = self.helper.send_stix2_bundle(bundle)

        if len(entities) > 0:
            report = self.helper.api.report.read(id=container_id)
            if report:
                for entity in entities:
                    self.helper.api.report.add_stix_object_or_stix_relationship(
                        id=report["id"], stixObjectOrStixRelationshipId=entity["id"]
                    )

            # total += len(entities)

        return "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"


    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)

    def resolve_match(self, match):
        types = {
            "MD5": "File.hashes.MD5",
            "SHA1": "File.hashes.SHA-1",
            "SHA256": "File.hashes.SHA-256",
            "Filename": "File.name",
            "IP": "IPv4-Addr.value",
            "Host": "X-OpenCTI-Hostname.value",
            "Filepath": "File.path",
            "URL": "Url.value",
            "Email": "Email-Addr.value",
            "AttackPattern": "Attack-Pattern.value",
            "CVE": "Vulnerability.name",
            "Registry": "Windows-Registry-Key.key",
        }
        type = match["type"]
        value = match["match"]
        if type in types:
            resolved_type = types[type]
            if resolved_type == "IPv4-Addr.value":
                # Demilitarized IP
                if "[.]" in value:
                    value = value.replace("[.]", ".")
                type_0 = self.detect_ip_version(value)
            elif resolved_type == "Url.value":
                # Demilitarized URL
                if "hxxp://" in value:
                    value = value.replace("hxxp://", "http://")
                if "hxxps://" in value:
                    value = value.replace("hxxps://", "https://")
                if "hxxxs://" in value:
                    value = value.replace("hxxxs://", "https://")
                if "[.]" in value:
                    value = value.replace("[.]", ".")
                type_0 = resolved_type
            elif resolved_type == "X-OpenCTI-Hostname.value":
                # Demilitarized Host
                if "[.]" in value:
                    value = value.replace("[.]", ".")
                type_0 = resolved_type
            else:
                type_0 = resolved_type
            return {"type": type_0, "value": value}
        else:
            self.helper.log_info('Some odd info received: {}'.format(match))
            return False

    def detect_ip_version(self, value):
        if len(value) > 16:
            return "IPv6-Addr.value"
        else:
            return "IPv4-Addr.value"

    def _get_entities(self):
        setup = {
            'identity': {
                'filter': None,
                'fields': ['aliases', 'name'],
                'type': 'value'
            },
            'location': {
                'filter': [{"key": "entity_type", "values": ["Country"]}],
                'fields': ['aliases', 'name'],
                'type': 'value'
            },
            'intrusion_set': {
                'filter': None,
                'fields': ['aliases', 'name'],
                'type': 'value'
            },
            'malware': {
                'filter': None,
                'fields': ['aliases', 'name'],
                'type': 'value'
            },
            'tool': {
                'filter': None,
                'fields': ['aliases', 'name'],
                'type': 'value'
            }
        }

        return self.resolve_setup(setup)

    def resolve_setup(self, setup_dict: Dict):
        base_func = self.helper.api
        information_list = {}
        for entity, args in setup_dict.items():
            func_format = entity
            try:
                custom_function = getattr(base_func, func_format)
            except AttributeError:
                e = "Selected parser format is not supported: %s" % (func_format)
                raise NotImplementedError(e)

            entries = custom_function.list(getAll=True, filters=args['filter'])
            information_list[entity] = self._make_1d_list(entries, args['fields'])

        # pprint(information_list)
        return information_list


    def _make_1d_list(self, values, keys):
        items = []
        for key in keys:
            for item in values:
                elem = item.get(key, [])
                if elem:
                    if type(elem) == list:
                        items += elem
                    elif type(elem) == str:
                        items.append(elem)

        return set(items)


if __name__ == "__main__":
    try:
        connectorImportFilePdfObservables = ImportFilePdfObservables()
        connectorImportFilePdfObservables.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
