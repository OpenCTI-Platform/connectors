import json
import os
import yaml

from connector.opencti_connector_helper import OpenCTIConnectorHelper


class StixImporter:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data):
        file_path = data['file_path']
        file_uri = self.helper.opencti_url + file_path
        self.helper.log_info('Importing the file ' + file_uri)
        file_content = self.helper.api.fetch_opencti_file(file_uri)
        bundles_sent = self.helper.send_stix2_bundle(file_content)
        return ['Sent ' + str(len(bundles_sent)) + ' stix bundle(s) for worker import']

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == '__main__':
    stix_imported = StixImporter()
    stix_imported.start()
