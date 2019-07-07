# coding: utf-8

import os
import urllib.request
from pycti import OpenCTI


class Mitre:
    def __init__(self, config, scheduler):
        # Initialize config
        self.config = config
        self.scheduler = scheduler

        # Initialize OpenCTI client
        self.opencti = OpenCTI(
            self.config['opencti']['api_url'],
            self.config['opencti']['api_key'],
            os.path.dirname(os.path.abspath(__file__)) + '/mitre.log',
            True
        )

    def set_config(self, config):
        self.config = config

    def get_config(self):
        return self.config['mitre']

    def run(self):
        enterprise_data = urllib.request.urlopen(self.config['mitre']['enterprise_file_url']).read()
        self.scheduler.send_stix2_bundle(enterprise_data.decode('utf-8'))
