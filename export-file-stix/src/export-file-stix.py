# coding: utf-8

import logging
import yaml
import os
import json

from opencti_connector import OpenCTIConnector
from pycti import OpenCTIApiClient, OpenCTIConnectorHelper


class StixExporter:
    def __init__(self):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.opencti_url = os.getenv('OPENCTI_URL') or config['opencti']['url']
        self.opencti_token = os.getenv('OPENCTI_TOKEN') or config['opencti']['token']
        self.name = os.getenv('OPENCTI_NAME') or config['connector']['name']
        self.scope = (os.getenv('OPENCTI_SCOPE') or config['connector']['scope']).split(',')
        self.log_level = os.getenv('OPENCTI_LOG_LEVEL') or config['connector']['log_level']

        # Initialize Helper
        connect_id = 'f08bb060-9bb0-4de2-b002-1f8ca38b69fd'
        connect_type = 'INTERNAL_EXPORT_FILE'
        connector = OpenCTIConnector(connect_id, self.name, connect_type, self.scope)
        self.helper = OpenCTIConnectorHelper(connector, self.opencti_url, self.opencti_token, self.log_level)

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: ' + self.log_level)
        logging.basicConfig(level=numeric_level)

    def _process_message(self, data, channel, method, properties):
        bundle = self.helper.api.stix2_export_entity(data['entity_type'], data['entity_id'], 'simple')
        json_bundle = json.dumps(bundle, indent=4)
        self.helper.api.push_stix_domain_entity_export(data['entity_id'], data['export_id'], json_bundle)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == '__main__':
    stix_exporter = StixExporter()
    stix_exporter.start()
