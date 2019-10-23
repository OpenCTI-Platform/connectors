# coding: utf-8

import os
import yaml
import time
import urllib.request
import gzip
import shutil

from pycti import OpenCTIConnectorHelper
from cvetostix2 import convert


class Cve:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.cve_nvd_data_feed = os.getenv('CVE_NVD_DATA_FEED') or config['cve']['nvd_data_feed']
        self.cve_interval = os.getenv('CVE_INTERVAL') or config['cve']['interval']

    def get_interval(self):
        return int(self.cve_interval) * 60 * 60 * 24

    def run(self):
        self.helper.log_info('Fetching CVE knowledge...')
        while True:
            try:
                # Downloading json.gz file
                self.helper.log_info('Requesting the file')
                urllib.request.urlretrieve(self.cve_nvd_data_feed, os.path.dirname(os.path.abspath(__file__)) + '/data.json.gz')
                # Unzipping the file
                self.helper.log_info('Unzipping the file')
                with gzip.open('data.json.gz', 'rb') as f_in:
                    with open('data.json', 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                # Converting the file to stix2
                self.helper.log_info('Converting the file')
                convert('data.json', 'data-stix2.json')
                with open('data-stix2.json') as stix_json:
                    contents = stix_json.read()
                    self.helper.send_stix2_bundle(contents, self.helper.connect_scope)

                # Remove files
                os.remove('data.json')
                os.remove('data.json.gz')
                os.remove('data-stix2.json')
                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info('Connector stop')
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(self.get_interval())


if __name__ == '__main__':
    cveConnector = Cve()
    cveConnector.run()
