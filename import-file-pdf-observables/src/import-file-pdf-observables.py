# coding: utf-8

import os
from typing import Dict
import yaml
import time
import uuid
import magic
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

        self.types = {
            "MD5": "File.hashes.MD5",
            "SHA1": "File.hashes.SHA-1",
            "SHA256": "File.hashes.SHA-256",
            "Filename": "File.name",
            "IP": "IPv4-Addr.value",
            "DomainName": "Domain-Name.value",
            # Directory is not yet fully functional
            # "Directory": "Directory.path",
            "URL": "Url.value",
            "Email": "Email-Addr.value",
            "CVE": "Vulnerability.name",
            "Registry": "Windows-Registry-Key.key",
        }

    def _process_message(self, data):
        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch
        file_name = os.path.basename(file_fetch)
        entity_id = data.get("entity_id", None)
        self.helper.log_info(entity_id)
        # Get context
        is_context = entity_id is not None and len(entity_id) > 0
        self.helper.log_info("Context: {}".format(is_context))
        self.helper.log_info(
            "get_only_contextual: {}".format(self.helper.get_only_contextual())
        )
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
        stix_objects = set()
        i = 0
        custom_indicators = self._get_entities()
        mime_type = self._get_mime_type(file_name)
        print(mime_type)
        if mime_type is None:
            raise ValueError("Invalid file format of {}".format(file_name))

        parser = iocp.IOC_Parser(
            None,
            mime_type,
            True,
            "pdfminer",
            "json",
            custom_indicators=custom_indicators,
        )
        parsed = parser.parse(file_name)
        os.remove(file_name)
        if parsed != []:
            for file in parsed:
                if file != None:
                    for page in file:
                        if page != []:
                            for match in page:
                                resolved_match = self._resolve_match(match)
                                if resolved_match:
                                    # For the creation of relationships
                                    if resolved_match[
                                        "type"
                                    ] not in self.types.values() and self._is_uuid(
                                        resolved_match["value"]
                                    ):
                                        stix_objects.add(resolved_match["value"])
                                    # For CVEs since SimpleObservable doesn't support Vulnerabilities yet
                                    elif resolved_match["type"] == "Vulnerability.name":
                                        vulnerability = Vulnerability(
                                            name=resolved_match["value"]
                                        )
                                        bundle_objects.append(vulnerability)
                                    # Other observables
                                    elif resolved_match["type"] in self.types.values():
                                        observable = SimpleObservable(
                                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                                "x-opencti-simple-observable"
                                            ),
                                            key=resolved_match["type"],
                                            value=resolved_match["value"],
                                            x_opencti_create_indicator=self.create_indicator,
                                        )
                                        bundle_objects.append(observable)
                                    else:
                                        self.helper.log_info(
                                            "Odd data received: {}".format(
                                                resolved_match
                                            )
                                        )
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

        bundles_sent = []
        if len(bundle_objects) > 0:
            bundle = Bundle(objects=bundle_objects).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)

        if len(stix_objects) > 0 and entity_id is not None:
            report = self.helper.api.report.read(id=entity_id)
            if report:
                for stix_object in stix_objects:
                    self.helper.log_info(stix_object)
                    self.helper.api.report.add_stix_object_or_stix_relationship(
                        id=report["id"], stixObjectOrStixRelationshipId=stix_object
                    )

        return "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"

    def start(self):
        self.helper.listen(self._process_message)

    def _resolve_match(self, match):
        type = match["type"]
        value = match["match"]
        if type in self.types:
            resolved_type = self.types[type]
            if resolved_type == "IPv4-Addr.value":
                # Demilitarized IP
                if "[.]" in value:
                    value = value.replace("[.]", ".")
                type_0 = self._detect_ip_version(value)
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
            elif resolved_type == "DomainName.value":
                # Demilitarized Host
                if "[.]" in value:
                    value = value.replace("[.]", ".")
                type_0 = resolved_type
            else:
                type_0 = resolved_type
            return {"type": type_0, "value": value}
        elif self._is_uuid(value):
            return {"type": type, "value": value}
        else:
            self.helper.log_info("Some odd info received: {}".format(match))
            return False

    def _detect_ip_version(self, value):
        if len(value) > 16:
            return "IPv6-Addr.value"
        else:
            return "IPv4-Addr.value"

    def _is_uuid(self, value):
        try:
            uuid.UUID(value)
        except ValueError:
            return False
        return True

    def _get_entities(self):
        setup = {
            "attack_pattern": {
                "entity_filter": None,
                "entity_fields": ["x_mitre_id"],
                "type": "entity",
            },
            "identity": {
                "entity_filter": None,
                "entity_fields": ["aliases", "name"],
                "type": "entity",
            },
            "location": {
                "entity_filter": [{"key": "entity_type", "values": ["Country"]}],
                "entity_fields": ["aliases", "name"],
                "type": "entity",
            },
            "intrusion_set": {
                "entity_filter": None,
                "entity_fields": ["aliases", "name"],
                "type": "entity",
            },
            "malware": {
                "entity_filter": None,
                "entity_fields": ["aliases", "name"],
                "type": "entity",
            },
            "tool": {
                "entity_filter": None,
                "entity_fields": ["aliases", "name"],
                "type": "entity",
            },
        }

        return self._collect_stix_objects(setup)

    def _collect_stix_objects(self, setup_dict: Dict):
        base_func = self.helper.api
        information_list = {}
        for entity, args in setup_dict.items():
            func_format = entity
            try:
                custom_function = getattr(base_func, func_format)
                entries = custom_function.list(
                    getAll=True, filters=args["entity_filter"]
                )
                information_list[entity] = self._make_1d_list(
                    entries, args["entity_fields"]
                )
            except AttributeError:
                e = "Selected parser format is not supported: %s" % func_format
                raise NotImplementedError(e)

        return information_list

    def _make_1d_list(self, values, keys):
        items = {}
        for item in values:
            _id = item.get("id")
            sub_items = set()
            if (
                item.get("externalReferences", None) is None
                or len(item["externalReferences"]) == 0
            ):
                continue
            for key in keys:
                elem = item.get(key, [])
                if elem:
                    if type(elem) == list:
                        sub_items.update(elem)
                    elif type(elem) == str:
                        sub_items.add(elem)

            items[_id] = sub_items
        return items

    def _get_mime_type(self, file_name):
        mime = magic.Magic(mime=True)
        translation = {
            "application/pdf": "pdf",
            # 'text/html': 'html',
            # 'text/plain': 'txt'
        }
        mimetype = mime.from_file(file_name)
        return translation.get(mimetype, None)


if __name__ == "__main__":
    try:
        connectorImportFilePdfObservables = ImportFilePdfObservables()
        connectorImportFilePdfObservables.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
