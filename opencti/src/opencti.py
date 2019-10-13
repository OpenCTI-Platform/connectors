# coding: utf-8

import os
import yaml
import time
import urllib.request

from connector.opencti_connector_helper import OpenCTIConnectorHelper


class OpenCTI:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.opencti_sectors_file_url = os.getenv('OPENCTI_SECTORS_FILE_URL') or config['config']['sectors_file_url']
        self.opencti_interval = os.getenv('OPENCTI_INTERVAL') or config['config']['interval']

    def get_interval(self):
        return int(self.opencti_interval) * 60 * 60 * 24

    def process(self):
        self.helper.log_info('Fetching OpenCTI datasets...')
        try:
            sectors_data = urllib.request.urlopen(self.opencti_sectors_file_url).read()
            self.helper.send_stix2_bundle(sectors_data.decode('utf-8'), self.helper.connect_scope)
            time.sleep(self.get_interval())
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info('Connector stop')
        except Exception as e:
            self.helper.log_error(str(e))
            self.process()


if __name__ == '__main__':
    openCTIConnector = OpenCTI()
    openCTIConnector.process()


