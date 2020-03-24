import os
import yaml
import time
import requests
import json
from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable

IDR_API =  'https://malpedia.caad.fkie.fraunhofer.de/api/'
AUTH_KEY = '9024365e2058c49d4683fe600d44e5a7b1f5079b'
api_call = {
            'API_CHECK_APIKEY': 'check/apikey', 
            'API_GET_VERSION':'get/version', 
            'API_GET_FAMILIES':'get/families', 
            'API_LIST_ACTORS':'list/actors', 
            'API_GET_FAMILY':'get/family/'}

class Malpedia:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path))
            if os.path.isfile(config_file_path)
            else {}
        )
        self.interval = 1 #1 Day interval between each scraping
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
        )
        self.data = {}

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching Malpedia datasets...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run)
                    > ((int(self.interval) -1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    
                    ## CORE ##
                    # API Key check
                    r = requests.get(IDR_API + api_call['API_CHECK_APIKEY'], 
                                headers={'Authorization': 'apitoken ' + AUTH_KEY})
                    response_json = r.json ()
                    if "Valid token" in response_json["detail"]:
                        print ("--- Authentication successful.")
                    else:
                        print ("--- Authentication failed.")
                    # API Version check
                    r = requests.get(IDR_API + api_call['API_GET_VERSION'], 
                                headers={'Authorization': 'apitoken ' + AUTH_KEY})
                    response_json = r.json ()
                    print ("--- Malpedia version: "+ str(response_json["version"]) +" (" + response_json["date"] + ")")

#get list families
                    r = requests.get(IDR_API + api_call['API_GET_FAMILIES'] , 
                                headers={'Authorization': 'apitoken ' + AUTH_KEY})
                    response_json = r.json ()
#for family in families:
#    get family content
#    if update_date == update_date dans opencti:
#        on fait rien
#    else:
#        on cree l'entité dans opencti

                    r = requests.get(IDR_API + api_call['API_GET_FAMILY'] + 'win.nemty', 
                                headers={'Authorization': 'apitoken ' + AUTH_KEY})
                    response_json = r.json ()

                    
                    malware = self.helper.api.malware.create(
                            name=response_json["common_name"],
                            description=response_json["description"],
                    ) 
                    
                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        MalpediaConnector = Malpedia()
        MalpediaConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
