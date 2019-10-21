import os
import yaml
import time
import urllib.request

from pycti import OpenCTIConnectorHelper


class Mitre:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.mitre_enterprise_file_url = os.getenv('MITRE_ENTERPRISE_FILE_URL') or config['mitre']['enterprise_file_url']
        self.mitre_pre_attack_file_url = os.getenv('MITRE_PRE_ATTACK_FILE_URL') or config['mitre']['pre_attack_file_url']
        self.mitre_interval = os.getenv('MITRE_INTERVAL') or config['mitre']['interval']

    def get_interval(self):
        return int(self.mitre_interval) * 60 * 60 * 24

    def run(self):
        self.helper.log_info('Fetching MITRE datasets...')
        while True:
            try:
                enterprise_data = urllib.request.urlopen(self.mitre_enterprise_file_url).read()
                self.helper.send_stix2_bundle(enterprise_data.decode('utf-8'), self.helper.connect_scope)
                pre_attack_data = urllib.request.urlopen(self.mitre_pre_attack_file_url).read()
                self.helper.send_stix2_bundle(pre_attack_data.decode('utf-8'), self.helper.connect_scope)
                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info('Connector stop')
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(10)


if __name__ == '__main__':
    mitreConnector = Mitre()
    mitreConnector.run()
