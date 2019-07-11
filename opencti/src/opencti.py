# coding: utf-8

import os
import yaml
import logging
import time
import urllib.request

from pycti import OpenCTIConnectorHelper


class OpenCTI:
    def __init__(self):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        self.config = dict()
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.config_rabbitmq = config['rabbitmq']
            self.config['name'] = config['opencti']['name']
            self.config['confidence_level'] = config['opencti']['confidence_level']
            self.config['sectors_file_url'] = config['opencti']['sectors_file_url']
            self.config['entities'] = config['opencti']['entities'].split(',')
            self.config['interval'] = config['opencti']['interval']
            self.config['log_level'] = config['opencti']['log_level']
        else:
            self.config_rabbitmq = dict()
            self.config_rabbitmq['hostname'] = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.config_rabbitmq['port'] = os.getenv('RABBITMQ_PORT', 5672)
            self.config_rabbitmq['username'] = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.config_rabbitmq['password'] = os.getenv('RABBITMQ_PASSWORD', 'guest')
            self.config['name'] = os.getenv('OPENCTI_NAME', 'OpenCTI')
            self.config['confidence_level'] = int(os.getenv('OPENCTI_CONFIDENCE_LEVEL', 5))
            self.config['sectors_file_url'] = os.getenv('OPENCTI_SECTORS_FILE_URL', 'https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json')
            self.config['entities'] = os.getenv('OPENCTI_ENTITIES', 'sector,region,country,city').split(',')
            self.config['interval'] = os.getenv('OPENCTI_INTERVAL', 1)
            self.config['log_level'] = os.getenv('OPENCTI_LOG_LEVEL', 'info')

        # Initialize OpenCTI Connector
        connector_identifier = ''.join(e for e in self.config['name'] if e.isalnum())
        self.opencti_connector_helper = OpenCTIConnectorHelper(
            connector_identifier.lower(),
            self.config,
            self.config_rabbitmq,
            self.config['log_level']
        )

    def get_log_level(self):
        return self.config['log_level']

    def get_interval(self):
        return int(self.config['interval']) * 60 * 60 * 24

    def run(self):
        enterprise_data = urllib.request.urlopen(self.config['sectors_file_url']).read()
        self.opencti_connector_helper.send_stix2_bundle(enterprise_data.decode('utf-8'))


if __name__ == '__main__':
    opencti = OpenCTI()

    # Configure logger
    numeric_level = getattr(logging, opencti.get_log_level().upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: ' + opencti.get_log_level())
    logging.basicConfig(level=numeric_level)

    logging.info('Starting the OpenCTI connector...')
    while True:
        try:
            logging.info('Fetching OpenCTI datasets...')
            opencti.run()
            time.sleep(opencti.get_interval())
        except Exception as e:
            logging.error(e)
            time.sleep(30)
