# coding: utf-8

import datetime
import dateutil
import json
import logging
import os
import sys
import time
import urllib.request
import yaml

from pycti import OpenCTIConnectorHelper


class Mitre:
    def __init__(self):
        # Get configuration
        self.config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        self.config = dict()
        self.last_check = None

        if os.path.isfile(self.config_file_path):
            self.yaml_config = yaml.load(open(self.config_file_path), Loader=yaml.FullLoader)
            self.config_rabbitmq = self.yaml_config['rabbitmq']
            self.config['name'] = self.yaml_config['mitre']['name']
            self.config['confidence_level'] = self.yaml_config['mitre']['confidence_level']
            self.config['enterprise_file_url'] = self.yaml_config['mitre']['enterprise_file_url']
            self.config['entities'] = self.yaml_config['mitre']['entities'].split(',')
            self.config['interval'] = self.yaml_config['mitre']['interval']
            self.config['log_level'] = self.yaml_config['mitre']['log_level']

            if 'last_check' in self.yaml_config['mitre']:
                # add the timezone back to allow comparison later
                self.last_check = dateutil.parser.parse(
                    self.yaml_config['mitre']['last_check']
                ).replace(tzinfo=dateutil.tz.tzutc())
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
        if self.last_check is None:
            self.opencti_connector_helper.send_stix2_bundle(enterprise_data.decode('utf-8'), self.config['entities'])
        else:
            bundle = json.loads(enterprise_data)

            new_bundle = {
                'type': bundle['type'],
                'id': bundle['id'],
                'spec_version': bundle['spec_version'],
                'objects': []
            }

            new_object_count = 0
            for object in bundle['objects']:
                if 'modified' in object:
                    mod = dateutil.parser.parse(object['modified'])
                    if mod > self.last_check:
                        new_bundle['objects'].append(object)
                        new_object_count += 1
                else:
                    new_bundle['objects'].append(object)

            logging.info(f"{new_object_count} objects to add")
            if new_object_count:
                self.opencti_connector_helper.send_stix2_bundle(json.dumps(new_bundle), self.config['entities'])

        # write the new date back to the config file
        if os.path.isfile(self.config_file_path):
            self.yaml_config['mitre']['last_check'] = datetime.datetime.utcnow().isoformat()
            with open(self.config_file_path, 'w') as f:
                yaml.dump(self.yaml_config, f)


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

