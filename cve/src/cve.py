# coding: utf-8

import os
import yaml
import logging
import time
import urllib.request
import gzip
import shutil

from pycti import OpenCTIConnectorHelper
from cvetostix2 import convert


class Cve:
    def __init__(self):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        self.config = dict()
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.config_rabbitmq = config['rabbitmq']
            self.config['name'] = config['cve']['name']
            self.config['confidence_level'] = config['cve']['confidence_level']
            self.config['nvd_data_feed'] = config['cve']['nvd_data_feed']
            self.config['entities'] = config['cve']['entities'].split(',')
            self.config['interval'] = config['cve']['interval']
            self.config['log_level'] = config['cve']['log_level']
        else:
            self.config_rabbitmq = dict()
            self.config_rabbitmq['hostname'] = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.config_rabbitmq['port'] = os.getenv('RABBITMQ_PORT', 5672)
            self.config_rabbitmq['username'] = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.config_rabbitmq['password'] = os.getenv('RABBITMQ_PASSWORD', 'guest')
            self.config['name'] = os.getenv('CVE_NAME', 'Common Vulnerabilities and Exposures')
            self.config['confidence_level'] = int(os.getenv('CVE_CONFIDENCE_LEVEL', 3))
            self.config['nvd_data_feed'] = os.getenv('CVE_DATA_FEED', 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz')
            self.config['entities'] = os.getenv('CVE_ENTITIES', 'vulnerability').split(',')
            self.config['interval'] = os.getenv('CVE_INTERVAL', 5)
            self.config['log_level'] = os.getenv('CVE_LOG_LEVEL', 'info')

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
        # Downloading json.gz file
        logging.info('Requesting the file')
        urllib.request.urlretrieve(self.config['nvd_data_feed'],os.path.dirname(os.path.abspath(__file__)) + '/data.json.gz')
        # Unzipping the file
        logging.info('Unzipping the file')
        with gzip.open('data.json.gz', 'rb') as f_in:
            with open('data.json', 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        # Converting the file to stix2
        logging.info('Converting the file')
        convert('data.json', 'data-stix2.json')
        with open('data-stix2.json') as stixjson:
            contents = stixjson.read()
            self.opencti_connector_helper.send_stix2_bundle(contents, self.config['entities'])
        
        # Remove files
        os.remove('data.json')
        os.remove('data.json.gz')
        os.remove('data-stix2.json')


if __name__ == '__main__':
    cve = Cve()

    # Configure logger
    numeric_level = getattr(logging, cve.get_log_level().upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: ' + cve.get_log_level())
    logging.basicConfig(level=numeric_level)

    logging.info('Starting the CVE connector...')
    while True:
        try:
            logging.info('Fetching the CVE knowledge...')
            cve.run()
            time.sleep(cve.get_interval())
        except Exception as e:
            logging.error(e)
            time.sleep(30)
