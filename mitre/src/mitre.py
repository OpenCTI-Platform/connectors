# coding: utf-8

import os
import yaml
import logging
import time
import urllib.request

from pycti import OpenCTIConnectorHelper


class Mitre:
    def __init__(self):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        self.config = dict()
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.config_rabbitmq = config['rabbitmq']
            self.config['name'] = config['mitre']['name']
            self.config['confidence_level'] = config['mitre']['confidence_level']
            self.config['enterprise_file_url'] = config['mitre']['enterprise_file_url']
            self.config['entities'] = config['mitre']['entities'].split(',')
            self.config['interval'] = config['mitre']['interval']
            self.config['log_level'] = config['mitre']['log_level']
        else:
            self.config_rabbitmq = dict()
            self.config_rabbitmq['hostname'] = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.config_rabbitmq['port'] = os.getenv('RABBITMQ_PORT', 5672)
            self.config_rabbitmq['username'] = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.config_rabbitmq['password'] = os.getenv('RABBITMQ_PASSWORD', 'guest')
            self.config['name'] = os.getenv('MITRE_NAME', 'MITRE ATT&CK')
            self.config['confidence_level'] = int(os.getenv('MITRE_CONFIDENCE_LEVEL', 3))
            self.config['enterprise_file_url'] = os.getenv('MITRE_ENTERPRISE_FILE_URL', 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')
            self.config['entities'] = os.getenv('MITRE_ENTITIES', 'attack-pattern,course-of-action,intrusion-set,malware,tool').split(',')
            self.config['interval'] = os.getenv('MITRE_INTERVAL', 5)
            self.config['log_level'] = os.getenv('MITRE_LOG_LEVEL', 'info')

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
        enterprise_data = urllib.request.urlopen(self.config['enterprise_file_url']).read()
        self.opencti_connector_helper.send_stix2_bundle(enterprise_data.decode('utf-8'))


if __name__ == '__main__':
    mitre = Mitre()

    # Configure logger
    numeric_level = getattr(logging, mitre.get_log_level().upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: ' + mitre.get_log_level())
    logging.basicConfig(level=numeric_level)

    logging.info('Starting the MITRE connector...')
    while True:
        try:
            logging.info('Fetching the MITRE knowledge...')
            mitre.run()
            time.sleep(mitre.get_interval())
        except Exception as e:
            logging.error(e)
            time.sleep(30)
