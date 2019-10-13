import os
import yaml
import time
import urllib.request

from connector.opencti_connector_helper import OpenCTIConnectorHelper


class Mitre:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.mitre_file_url = os.getenv('MITRE_ENTERPRISE_FILE_URL') or config['mitre']['enterprise_file_url']
        self.mitre_interval = os.getenv('MITRE_INTERVAL') or config['mitre']['interval']

    def get_interval(self):
        return int(self.mitre_interval) * 60 * 60 * 24

    def run(self):
        enterprise_data = urllib.request.urlopen(self.mitre_file_url).read()
        self.helper.send_stix2_bundle(enterprise_data.decode('utf-8'), self.helper.connect_scope)


if __name__ == '__main__':
    mitre = Mitre()
    mitre.helper.log_info('Starting the MITRE connector...')
    while True:
        try:
            mitre.helper.log_info('Fetching the MITRE knowledge...')
            mitre.run()
            time.sleep(mitre.get_interval())
        except Exception as e:
            mitre.helper.log_error(str(e))
            time.sleep(30)
