# coding: utf-8

import os
import yaml
import time
import uuid
import json

import iocp
from pycti import OpenCTIConnectorHelper, get_config_variable

from stix2 import Bundle, Indicator, Report


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
        file_path = data["file_path"]
        file_name = os.path.basename(file_path)
        work_context = data["work_context"]
        file_uri = self.helper.opencti_url + file_path
        self.helper.log_info("Importing the file " + file_uri)
        # Get the file
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)
        # Write the file
        path = "/tmp/" + file_name
        f = open(path, "wb")
        f.write(file_content)
        f.close()
        # Parse
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "spec_version": "2.0",
            "objects": [],
        }
        observed_data = {
            "id": "observed-data--" + str(uuid.uuid4()),
            "type": "observed-data",
            "x_opencti_indicator_create": self.create_indicator,
            "objects": {},
        }
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
                                    observable = {
                                        "type": resolved_match["type"],
                                        "x_opencti_observable_type": resolved_match[
                                            "type"
                                        ],
                                        "x_opencti_observable_value": resolved_match[
                                            "value"
                                        ],
                                        "x_opencti_indicator_create": self.create_indicator,
                                    }
                                    observed_data["objects"][i] = observable
                                    i += 1
        else:
            self.helper.log_error("Could not parse the report!")

        # Get context
        if len(observed_data["objects"]) > 0:
            bundle["objects"].append(observed_data)
            if work_context is not None and len(work_context) > 0:
                report = self.helper.api.report.read(id=work_context)
                if report is not None:
                    report_stix = {
                        "type": "report",
                        "id": report["stix_id_key"],
                        "name": report["name"],
                        "description": report["description"],
                        "published": self.helper.api.stix2.format_date(
                            report["published"]
                        ),
                        "object_refs": [],
                    }
                    report_stix["object_refs"].append(observed_data["id"])
                    bundle["objects"].append(report_stix)
            bundles_sent = self.helper.send_stix2_bundle(
                json.dumps(bundle), None, False, False
            )
            return [
                "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
            ]

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)

    def resolve_match(self, match):
        types = {
            "MD5": ["File-MD5"],
            "SHA1": ["File-SHA1"],
            "SHA256": ["File-SHA256"],
            "Filename": ["File-Name"],
            "IP": ["IPv4-Addr"],
            "Host": ["Domain"],
            "Filepath": ["File-Name"],
            "URL": ["URL"],
            "Email": ["Email-Address"],
        }
        type = match["type"]
        value = match["match"]
        if type in types:
            resolved_types = types[type]
            if resolved_types[0] == "IPv4-Addr":
                type_0 = self.detect_ip_version(value)
            else:
                type_0 = resolved_types[0]
            return {"type": type_0, "value": value}
        else:
            return False

    def detect_ip_version(self, value):
        if len(value) > 16:
            return "IPv6-Addr"
        else:
            return "IPv4-Addr"


if __name__ == "__main__":
    try:
        connectorImportFilePdfObservables = ImportFilePdfObservables()
        connectorImportFilePdfObservables.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
