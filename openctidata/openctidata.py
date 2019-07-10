# coding: utf-8

import os
import yaml
import logging
import time
import urllib.request

from pycti import OpenCTIConnectorHelper

CONNECTOR_IDENTIFIER = 'openctidata'


class OpenCTIData:
    def __init__(self):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        self.config = dict()
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.rabbitmq_hostname = config['rabbitmq']['hostname']
            self.rabbitmq_port = config['rabbitmq']['port']
            self.rabbitmq_username = config['rabbitmq']['username']
            self.rabbitmq_password = config['rabbitmq']['password']
            self.config['sectors_file_url'] = config['openctidata']['sectors_file_url']
            self.config['entities'] = config['openctidata']['entities'].split(',')
            self.config['interval'] = config['openctidata']['interval']
            self.config['log_level'] = config['openctidata']['log_level']
        else:
            self.rabbitmq_hostname = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.rabbitmq_port = os.getenv('RABBITMQ_PORT', 5672)
            self.rabbitmq_username = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.rabbitmq_password = os.getenv('RABBITMQ_PASSWORD', 'guest')
            self.config['sectors_file_url'] = os.getenv('OPENCTIDATA_SECTORS_FILE_URL', 'https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json')
            self.config['entities'] = os.getenv('OPENCTIDATA_ENTITIES', 'sector,region,country,city')
            self.config['interval'] = os.getenv('OPENCTIDATA_INTERVAL', 1)
            self.config['log_level'] = os.getenv('OPENCTIDATA_LOG_LEVEL', 'info')

        # Initialize OpenCTI Connector
        self.opencti_connector = OpenCTIConnectorHelper(
            CONNECTOR_IDENTIFIER,
            self.config,
            self.rabbitmq_hostname,
            self.rabbitmq_port,
            self.rabbitmq_username,
            self.rabbitmq_password,
            self.config['log_level']
        )

    def get_log_level(self):
        return self.config['log_level']

    def get_interval(self):
        return int(self.config['interval']) * 60 * 60 * 24

    def run(self):
        enterprise_data = urllib.request.urlopen(self.config['sectors_file_url']).read()
        self.opencti_connector.send_stix2_bundle(enterprise_data.decode('utf-8'))


if __name__ == '__main__':
    openctidata = OpenCTIData()

    # Configure logger
    numeric_level = getattr(logging, openctidata.get_log_level().upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: ' + openctidata.get_log_level())
    logging.basicConfig(level=numeric_level)

    logging.info('Starting the OpenCTIData connector...')
    while True:
        try:
            logging.info('Fetching new OpenCTIData events...')
            openctidata.run()
            time.sleep(openctidata.get_interval())
        except Exception as e:
            logging.error(e)
            time.sleep(30)
