# coding: utf-8

import os
import yaml
import logging
import time
import urllib.request

from opencti_connector import OpenCTIConnector
from pycti import OpenCTIConnectorHelper

DEFAULT_URL = 'https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json'


class OpenCTI:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.opencti_url = os.getenv('OPENCTI_URL') or config['opencti']['url']
        self.opencti_token = os.getenv('OPENCTI_TOKEN') or config['opencti']['token']
        self.name = os.getenv('OPENCTI_NAME', 'OpenCTI') or config['connector']['name']
        self.confidence_level = int(os.getenv('OPENCTI_CONFIDENCE_LEVEL', 5)) or config['connector']['confidence_level']
        self.sectors_file_url = os.getenv('OPENCTI_SECTORS_FILE_URL', DEFAULT_URL) or config['connector']['sectors_file_url']
        self.entities = os.getenv('OPENCTI_ENTITIES', 'sector,region,country,city').split(',') or config['connector']['entities'].split(',')
        self.interval = os.getenv('OPENCTI_INTERVAL', 1) or config['connector']['interval']
        self.log_level = os.getenv('OPENCTI_LOG_LEVEL', 'info') or config['connector']['log_level']

        # Initialize OpenCTI Connector
        connector_id = '89c2c3bf-de2e-4880-bbea-aeeb408b7036'
        connector_type = 'EXTERNAL_IMPORT'
        connector = OpenCTIConnector(connector_id, self.name, connector_type, [])
        self.helper = OpenCTIConnectorHelper(connector, self.opencti_url, self.opencti_token, self.log_level)

    def get_log_level(self):
        return self.log_level

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def process(self):
        logging.info('Fetching OpenCTI datasets...')
        try:
            sectors_data = urllib.request.urlopen(self.sectors_file_url).read()
            self.helper.send_stix2_bundle(sectors_data.decode('utf-8'), self.entities)
            time.sleep(self.get_interval())
        except (KeyboardInterrupt, SystemExit):
            logging.info('Connector stop')
        except Exception as e:
            logging.error(e)
            self.process()


if __name__ == '__main__':
    openCTIConnector = OpenCTI()
    openCTIConnector.process()


