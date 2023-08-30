import os.path

import yaml
import json
import time
import sys
import requests

from pycti import OpenCTIConnectorHelper, get_config_variable
import logging


class HarfangLabConnector:
    def __init__(self):
        # Initialize parameters and OpenCTI helper
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Initialiaze the Harfang Lab API
        self.harfanglab_url = get_config_variable("HARFANGLAB_URL", ["harfanglab", "url"], config)

        # TODO is basic auth needed/used?
        self.harfanglab_ssl_verify = get_config_variable(
            "HARFLANGLAB_SSL_VERIFY", ["harfanglab", "ssl_verify"], config, False, True
        )
        self.harfanglab_token = get_config_variable(
            "HARFLANGLAB_TOKEN", ["harfanglab", "token"], config
        )
        self.harfanglab_login = get_config_variable(
            "HARFLANGLAB_LOGIN", ["harfanglab", "login"], config
        )
        self.harfanglab_password = get_config_variable(
            "HARFLANGLAB_PASSWORD", ["harfanglab", "password"], config
        )
        self.indicators_scope = get_config_variable(
            "HARFLANGLAB_INDICATORS_SCOPE", ["harfanglab", "indicators_scope"], config
        ).split(',')

    def _process_message(self, msg):
        # _process_message
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message")
        # Handle creation
        self.helper.log_info(f'Processing the object {data["id"]}')
        url = (
            self.harfanglab_url
            + "/api/data/threat_intelligence"
        )
        # https://4cc1e4989b9de1af.hurukai.io:8443/api/data/threat_intelligence/YaraFile/
        headers = {
            "Accept": "application/json",
            "Authorization": "Token " + self.harfanglab_token
        }
        if msg.event == "create":
            # TODO YARA, Sigma and IoC
            # TODO Only revoked=false
            # TODO Handle creation source list
            if data["type"] == "indicator" and data["pattern_type"] in self.indicators_scope:
                if data["pattern_type"] == "sigma":
                    self.helper.log_info(
                        "[CREATE] Processing indicator {"
                        + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                        + "}"
                    )
                    indicator = {
                        "content": data["pattern"],
                        "enabled": True,
                        "hl_local_testing_status": "in_progress",
                        "hl_status": "stable",
                        "name": data["name"],
                        "source_id": "92e3513d-8639-44a6-b322-e839ad456295"
                    }
                    response = requests.post(
                        url + '/SigmaRule/',
                        headers=headers,
                        json=indicator
                    )
                    self.helper.log_info(f'Indicator created = {response}')
                elif data["pattern_type"] == "yara":
                    self.helper.log_info(
                        "[CREATE] Processing indicator {"
                        + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                        + "}"
                    )
                    indicator = {
                        "content": data["pattern"],
                        "enabled": True,
                        "hl_local_testing_status": "in_progress",
                        "hl_status": "stable",
                        "name": data["name"],
                        "source_id": "92e3513d-8639-44a6-b322-e839ad456295"
                    }
                    response = requests.post(
                        url + '/YaraFile/',
                        headers=headers,
                        json=indicator
                    )
                    self.helper.log_info(f'Indicator created = {response}')
                elif data["pattern_type"] == "stix":
                    # TODO check if it's the right name to get the type?
                    if data["x_opencti_main_observable_type"] in ["StixFile", "Domain-Name", "IPv4-Addr", "IPv6-Addr", "Url"]:
                        # TODO Exctract data from pattern
                        data["pattern"]



            return
        # Handle update
        if msg.event == "update":
            return
        if msg.event == "delete":
            return




    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    try:
        HarfangLabInstance = HarfangLabConnector()
        HarfangLabInstance.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
