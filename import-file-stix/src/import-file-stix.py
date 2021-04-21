import os
import yaml
import time

from stix2elevator import elevate
from stix2elevator.options import initialize_options
from pycti import OpenCTIConnectorHelper


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

    def _process_message(self, data):
        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch
        self.helper.log_info("Importing the file " + file_uri)
        file_content = self.helper.api.fetch_opencti_file(file_uri)
        if data["file_mime"] == "text/xml":
            initialize_options()
            file_content = elevate(file_content)
        bundles_sent = self.helper.send_stix2_bundle(file_content)
        return "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connectorImportFileStix = ImportFileStix()
        connectorImportFileStix.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
