# coding: utf-8

import os
import shutil
import urllib3
from pycti import OpenCTI

URL_ENTERPRISE_ATTACK = 'https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json?raw=true'


class Mitre:
    def __init__(self, config):
        # Initialize config
        self.config = config

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
        http = urllib3.PoolManager()
        with http.request('GET', URL_ENTERPRISE_ATTACK, preload_content=False) as r, open('./enterprise.json', 'wb') as out_file:
            shutil.copyfileobj(r, out_file)

        self.opencti.stix2_import_bundle_from_file('./enterprise.json', False, self.config['mitre']['entities'])
        os.remove('./enterprise.json')
