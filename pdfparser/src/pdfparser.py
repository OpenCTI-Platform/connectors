# coding: utf-8

import os
import yaml
import time
import logging
import argparse

from datetime import datetime
from dateutil.parser import parse
import iocp
from pycti import OpenCTIConnectorHelper
from stix2 import Bundle, Identity, ThreatActor, IntrusionSet, Malware, Tool, Report, Indicator, Relationship, \
    ExternalReference, TLP_WHITE, TLP_GREEN, \
    TLP_AMBER, TLP_RED


class PDFParser:
    def __init__(self, path):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        self.config = dict()
        self.path = path
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.config_rabbitmq = config['rabbitmq']
            self.config['name'] = config['pdfparser']['name']
            self.config['confidence_level'] = config['pdfparser']['confidence_level']
            self.config['interval'] = config['pdfparser']['interval']
            self.config['log_level'] = config['pdfparser']['log_level']
        else:
            self.config_rabbitmq = dict()
            self.config_rabbitmq['hostname'] = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.config_rabbitmq['port'] = os.getenv('RABBITMQ_PORT', 5672)
            self.config_rabbitmq['username'] = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.config_rabbitmq['password'] = os.getenv('RABBITMQ_PASSWORD', 'guest')
            self.config['name'] = 'pdfparser'
            self.config['confidence_level'] = 3
            self.config['interval'] = 7
            self.config['log_level'] = 'info'

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
        parser = iocp.IOC_Parser(None, "pdf", True, "pypdf2", "json")
        parsed = parser.parse(self.path)
        author = Identity(name='me', identity_class='organization')
        indicators = []
        bundle_objects = [author]

        if (parsed != []):
            for file in parsed:
                if (file != None):
                    for page in file:
                        if page != []:
                            for match in page:
                                resolved_match = self.resolve_match(match)
                                if resolved_match != 0:
                                    indicator = Indicator(
                                        name='Indicator',
                                        description='Parsed from PDF report',
                                        pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                                        labels=['malicious-activity','parsed_import'],
                                        created_by_ref=author,
                                        custom_properties={
                                            'x_opencti_observable_type': resolved_match['type'],
                                            'x_opencti_observable_value': resolved_match['value'],
                                        }
                                    ) 
                                    indicators.append(indicator)
                                    bundle_objects.append(indicator)
        else:
            print("Could not parse given reports")

        bundle = Bundle(objects=bundle_objects).serialize()
        self.opencti_connector_helper.send_stix2_bundle(bundle)

    def resolve_match(self, match):
        types = {
            'MD5': ['File-MD5'],
            'SHA1': ['File-SHA1'],
            'SHA256': ['File-SHA256'],
            'Filename': ['File-Name'],
            'IP': ['IPv4-Addr'],
            'Host': ['Domain'],
            'Filepath': ['File-Name'],
            'URL': ['URL'],
            'Email': ['Email-Address']
        }
        type = match['type']
        value = match['match']
        if type in types:
            resolved_types = types[type]
            if resolved_types[0] == 'IPv4-Addr':
                type_0 = self.detect_ip_version(value)
            else:
                type_0 = resolved_types[0]
            return {'type': type_0, 'value': value}
        else:
            return 0

    def detect_ip_version(self, value):
        if len(value) > 16:
            return 'IPv6-Addr'
        else:
            return 'IPv4-Addr'

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('PATH', action='store', help='File/directory to report(s)')
    args = argparser.parse_args()
    parser = PDFParser(args.PATH)

    # Configure logger
    numeric_level = getattr(logging, parser.get_log_level().upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: ' + parser.get_log_level())
    logging.basicConfig(level=numeric_level)

    logging.info('Starting the parser connector...')
    while True:
        try:
            logging.info('Fetching observables from pdf reports...')
            parser.run()
            time.sleep(parser.get_interval())
        except Exception as e:
            logging.error(e)
            time.sleep(30)
