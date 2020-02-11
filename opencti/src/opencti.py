import os
import yaml
import time
import urllib.request

from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable


class OpenCTI:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.opencti_sectors_file_url = get_config_variable(
            'CONFIG_SECTORS_FILE_URL',
            ['config', 'sectors_file_url'],
            config
        )
        self.opencti_geography_file_url = get_config_variable(
            'CONFIG_GEOGRAPHY_FILE_URL',
            ['config', 'geography_file_url'],
            config
        )
        self.opencti_interval = get_config_variable('CONFIG_INTERVAL', ['config', 'interval'], config, True)
        self.update_existing_data = get_config_variable(
            'CONNECTOR_UPDATE_EXISTING_DATA',
            ['connector', 'update_existing_data'],
            config
        )

    def get_interval(self):
        return int(self.opencti_interval) * 60 * 60 * 24

    def run(self):
        self.helper.log_info('Fetching OpenCTI datasets...')
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and 'last_run' in current_state:
                    last_run = current_state['last_run']
                    self.helper.log_info(
                        'Connector last run: ' + datetime.utcfromtimestamp(last_run).strftime('%Y-%m-%d %H:%M:%S')
                    )
                else:
                    last_run = None
                    self.helper.log_info('Connector has never run')
                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) > ((int(self.opencti_interval) - 1) * 60 * 60 * 24)):
                    sectors_data = urllib.request.urlopen(self.opencti_sectors_file_url).read()
                    self.helper.send_stix2_bundle(
                        sectors_data.decode('utf-8'),
                        self.helper.connect_scope,
                        self.update_existing_data
                    )
                    geography_data = urllib.request.urlopen(self.opencti_geography_file_url).read()
                    self.helper.send_stix2_bundle(
                        geography_data.decode('utf-8'),
                        self.helper.connect_scope,
                        self.update_existing_data
                    )
                    # Store the current timestamp as a last run
                    self.helper.log_info('Connector successfully run, storing last_run as ' + str(timestamp))
                    self.helper.set_state({'last_run': timestamp})
                    self.helper.log_info(
                        'Last_run stored, next run in: ' + str(round(self.get_interval() / 60 / 60 / 24, 2)) + ' days'
                    )
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        'Connector will not run, next run in: ' + str(round(new_interval / 60 / 60 / 24, 2)) + ' days'
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info('Connector stop')
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == '__main__':
    try:
        openCTIConnector = OpenCTI()
        openCTIConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
