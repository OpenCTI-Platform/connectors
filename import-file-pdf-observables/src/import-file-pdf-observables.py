# coding: utf-8

import os
import yaml
import time

import iocp
from stix2 import (
    Bundle,
    Report,
)
from pycti import (
    OpenCTIConnectorHelper,
    OpenCTIStix2Utils,
    get_config_variable,
    SimpleObservable,
    AttackPattern
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
        container_id = data["container_id"]
        self.helper.log_info("Importing the file " + file_uri)
        # Get the file
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)
        # Write the file
        path = "/tmp/" + file_name
        f = open(path, "wb")
        f.write(file_content)
        f.close()
        # Parse
        bundle_objects = []
        entities = []
        i = 0
        parser = iocp.IOC_Parser(None, "pdf", True, "pdfminer", "json")
        parsed = parser.parse(path)
        os.remove(path)
        if parsed != []:
            for file in parsed:
                if file != None:
                    for page in file:
                        if page != []:
                            for match in page:
                                resolved_match = self.resolve_match(match)
                                if resolved_match:
                                    if resolved_match["type"] == "AttackPattern":
                                        entity = self.helper.api.attack_pattern.read(
                                            filters=[{
                                                "key": "x_mitre_id",
                                                "values": [resolved_match['value']]
                                            }]
                                        )
                                        self.helper.log_info(entity)
                                        entities.append(entity)
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

        # Get context
        self.helper.log_info(bundle_objects)
        if len(bundle_objects) > 0:
            if container_id is not None and len(container_id) > 0:
                report = self.helper.api.report.read(id=container_id)
                if report is not None:
                    report = Report(
                        id=report["standard_id"],
                        name=report["name"],
                        description=report["description"],
                        published=self.helper.api.stix2.format_date(
                            report["published"]
                        ),
                        report_types=report["report_types"],
                        object_refs=bundle_objects,
                    )
                    bundle_objects.append(report)
            bundle = Bundle(objects=bundle_objects).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            total = len(bundles_sent)
            bundle = Bundle(objects=entities).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            total += len(bundles_sent)

            return (
                "Sent " + str(total) + " stix bundle(s) for worker import"
            )

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
            return False

    def detect_ip_version(self, value):
        if len(value) > 16:
            return "IPv6-Addr.value"
        else:
            return "IPv4-Addr.value"


if __name__ == "__main__":
    try:
        connectorImportFilePdfObservables = ImportFilePdfObservables()
        connectorImportFilePdfObservables.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
