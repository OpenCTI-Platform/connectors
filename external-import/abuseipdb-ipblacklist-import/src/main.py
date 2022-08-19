import os
import time
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable, Identity
from stix2 import IPv4Address, TLP_WHITE, Indicator, ExternalReference, Bundle
from datetime import datetime
import certifi
import ssl
import urllib
from urllib import parse
import json
import re

class abuseipdbipblacklistimport:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_url = get_config_variable(
            "ABUSEIPDB_URL", ["abuseipdbipblacklistimport", "api_url"], config
        )
        self.api_key = get_config_variable(
            "ABUSEIPDB_API_KEY", ["abuseipdbipblacklistimport", "api_key"], config
        )
        self.score = get_config_variable(
            "ABUSEIPDB_SCORE", ["abuseipdbipblacklistimport", "score"], config, True
        )
        self.limit = get_config_variable(
            "ABUSEIPDB_LIMIT", ["abuseipdbipblacklistimport", "limit"], config, True
        )
        self.interval = get_config_variable(
            "ABUSEIPDB_INTERVAL", ["abuseipdbipblacklistimport", "interval"], config, True
        )
        self.create_indicators = get_config_variable(
            "ABUSEIPDB_CREATE_INDICATORS",
            ["abuseipdb", "create_indicators"],
            config,
            False,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="AbuseIPDB",
            description="AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet",
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("abuseIPDB dataset...")
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
                    > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    # Initiate the run
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "AbuseIPDB connector run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        # Requesting data over AbuseIPDB
                        req = urllib.request.Request(self.api_url)
                        req.add_header('Key', self.api_key)
                        req.add_header('Accept', "application/json")
                        req.method = 'GET'
                        body= parse.urlencode({"confidenceMinimum":str(self.score),"limit":str(self.limit)}).encode()

                        response = urllib.request.urlopen(
                            req,
                            context=ssl.create_default_context(cafile=certifi.where()),
                            data=body
                        )
                        image = response.read()
                        data_json = json.loads(image)

                        # preparing the bundle to be sent to OpenCTI worker
                        external_reference = ExternalReference(
                            source_name="AbuseIPDB database",
                            url="https://www.abuseipdb.com/",
                            description="AbuseIPDB database URL",
                        )
                        bundle_objects = []

                        # Filling the bundle
                        ipv4validator = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
                        for d in data_json["data"]:
                            if(ipv4validator.match(d["ipAddress"])):
                                typeaddr="ipv4-addr"
                            else:
                                typeaddr= "ipv6-addr"
                            #print(d) # {'ipAddress': '1.2.3.4', 'countryCode': 'FR', 'abuseConfidenceScore': 100, 'lastReportedAt': '2022-08-17T11:50:02+00:00'}"
                            stix_observable = IPv4Address(
                                type="ipv4-addr",
                                spec_version= "2.1",
                                value = d["ipAddress"],
                                object_marking_refs=[TLP_WHITE],
                                custom_properties={
                                        "description": "Agressive IP known malicious on AbuseIPDB"
                                        + " - countryCode: "
                                        + str(d["countryCode"])
                                        + " - abuseConfidenceScore: "
                                        + str(d["abuseConfidenceScore"])
                                        + " - lastReportedAt: "
                                        + str(d["lastReportedAt"]),
                                        "x_opencti_score": d["abuseConfidenceScore"],
                                        "created_by_ref": self.identity["standard_id"],
                                        "x_opencti_create_indicator": self.create_indicators,
                                        "external_references": [external_reference],
                                    })
                            # Adding the IP to the list
                            bundle_objects.append(stix_observable)
                        # Creating the bundle from the list
                        bundle = Bundle(bundle_objects, allow_custom=True)
                        bundle_json = bundle.serialize()
                        # Sending the bundle
                        self.helper.send_stix2_bundle(
                            bundle_json,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))
                    # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(timestamp)
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
                else:
                    #wait for next run
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
        connector = abuseipdbipblacklistimport()
        connector.run()
    except Exception as e:
        time.sleep(10)
        exit(0)
