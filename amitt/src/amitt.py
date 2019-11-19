import os
import yaml
import time
import urllib.request

from datetime import datetime
from pycti import OpenCTIConnectorHelper


class Amitt:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.amitt_attack_file_url = os.getenv('AMITT_FILE_URL') or config['amitt'][
            'enterprise_file_url']
        self.amitt_pre_attack_file_url = os.getenv('AMITT_PRE_ATTACK_FILE_URL') or config['amitt'][
            'pre_attack_file_url']
        self.amitt_interval = os.getenv('AMITT_INTERVAL') or config['amitt']['interval']

    def get_interval(self):
        return int(self.amitt_interval) * 60 * 60 * 24

    def run(self):
        self.helper.log_info('Fetching AMITT datasets...')
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and 'last_run' in current_state:
                    last_run = current_state['last_run']
                    self.helper.log_info(
                        'Connector last run: ' + datetime.utcfromtimestamp(last_run).strftime('%Y-%m-%d %H:%M:%S'))
                else:
                    last_run = None
                    self.helper.log_info('Connector has never run')
                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) > ((int(self.amitt_interval) - 1) * 60 * 60 * 24)):
                    self.helper.log_info('Connector will run!')
                    enterprise_data = urllib.request.urlopen(self.amitt_attack_file_url).read().decode('utf-8')
                    self.helper.send_stix2_bundle(enterprise_data, self.helper.connect_scope)
                    pre_attack_data = urllib.request.urlopen(self.amitt_pre_attack_file_url).read()
                    self.helper.send_stix2_bundle(pre_attack_data.decode('utf-8'), self.helper.connect_scope)
                    # Store the current timestamp as a last run
                    self.helper.log_info('Connector successfully run, storing last_run as ' + str(timestamp))
                    self.helper.set_state({'last_run': timestamp})
                    # Sleep all interval
                    self.helper.log_info(
                        'Last_run stored, sleeping for: ' + str(round(self.get_interval() / 60 / 60 / 24, 2)) + ' days')
                    time.sleep(self.get_interval())
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        'Connector will not run, sleeping for: ' + str(round(new_interval / 60 / 60 / 24, 2)) + ' days')
                    # Sleep only remaining time
                    time.sleep(new_interval)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info('Connector stop')
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(self.get_interval())


if __name__ == '__main__':
    amittConnector = Amitt()
    amittConnector.run()
