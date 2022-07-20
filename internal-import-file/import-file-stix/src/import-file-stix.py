import os
import sys
import time
from typing import Dict, List

import yaml
from pycti import OpenCTIConnectorHelper
from stix2 import Bundle, Report, parse
from stix2elevator import elevate
from stix2elevator.options import initialize_options


class ImportFileStix:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data: Dict) -> str:
        file_fetch = data["file_fetch"]
        bypass_validation = data["bypass_validation"]
        file_uri = self.helper.opencti_url + file_fetch
        self.helper.log_info(f"Importing the file {file_uri}")

        file_content = self.helper.api.fetch_opencti_file(file_uri)
        if data["file_mime"] == "text/xml":
            self.helper.log_debug("Stix1 file. Attempting conversion")
            initialize_options()
            file_content = elevate(file_content)

        entity_id = data.get("entity_id", None)
        if entity_id:
            self.helper.log_info("Contextual import.")

            bundle = parse(file_content, allow_custom=True)["objects"]

            if self._contains_report(bundle):
                self.helper.log_info("Bundle contains report.")
            else:
                self.helper.log_info("No Report in Stix file. Updating current report")
                bundle = self._update_report(bundle, entity_id)

            file_content = Bundle(objects=bundle, allow_custom=True).serialize()

        bundles_sent = self.helper.send_stix2_bundle(
            file_content,
            bypass_validation=bypass_validation,
            file_name=data["file_id"],
            entity_id=entity_id,
        )
        if self.helper.get_validate_before_import() and not bypass_validation:
            return "Generated bundle sent for validation"
        else:
            return str(len(bundles_sent)) + " generated bundle(s) for worker import"

    # Start the main loop
    def start(self) -> None:
        self.helper.listen(self._process_message)

    @staticmethod
    def _contains_report(bundle: List) -> bool:
        for elem in bundle:
            if type(elem) == Report:
                return True
        return False

    def _update_report(self, bundle: List, entity_id: int) -> List:
        report = self.helper.api.report.read(id=entity_id)
        # The entity_id can be any SDO
        if report:
            report = Report(
                id=report["standard_id"],
                name=report["name"],
                description=report["description"],
                published=self.helper.api.stix2.format_date(report["created"]),
                report_types=report["report_types"],
                object_refs=bundle,
                allow_custom=True,
            )
            bundle.append(report)
        return bundle


if __name__ == "__main__":
    try:
        connectorImportFileStix = ImportFileStix()
        connectorImportFileStix.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
