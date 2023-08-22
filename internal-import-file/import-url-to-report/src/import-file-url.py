import json
import os
import sys
import time
import uuid
from typing import Dict
import stix2
import datetime

import yaml
from pycti import OpenCTIConnectorHelper


class ImportUrlToReport:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.dummy = stix2.ThreatActor(name="Dummy Actor")
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data: Dict) -> str:
        file_fetch = data["file_fetch"]
        bypass_validation = data["bypass_validation"]
        file_uri = self.helper.opencti_url + file_fetch
        self.helper.log_info(f"Importing the file {file_uri}")

        file_content = self.helper.api.fetch_opencti_file(file_uri)
        if data["file_mime"] != "text/plain":
            self.helper.log_debug("Not a text file")
            return "Error: Given file not a text file"
        
        self.helper.log_debug(f"Data: {data}")
        
        url_list = file_content.split("\n")
        bundle = []
        for url in url_list:
            reference = stix2.ExternalReference(source_name="External", url=url)
            now = datetime.datetime.now()
            report = stix2.Report(name=url, published=now, external_references=[reference], object_refs=[self.dummy])
            bundle += report
            bundle += reference
        serialized_bundle = stix2.Bundle(
            objects=bundle, allow_custom=True
        ).serialize()
        bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            
        if self.helper.get_validate_before_import() and not bypass_validation:
            return "Generated bundle sent for validation"
        else:
            return str(len(bundles_sent)) + " generated bundle(s) for worker import"

    # Start the main loop
    def start(self) -> None:
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connectorImportUrlToReport = ImportUrlToReport()
        connectorImportUrlToReport.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
