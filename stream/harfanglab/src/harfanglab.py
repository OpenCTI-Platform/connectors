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
        self.api_url = (
                self.harfanglab_url
                + "/api/data/threat_intelligence"
        )
        self.headers = {
            "Accept": "application/json",
            "Authorization": "Token " + self.harfanglab_token
        }
        self.harfanglab_yara_list_name = get_config_variable(
            "HARFLANGLAB_YARA_LIST_NAME", ["harfanglab", "yara_list_name"], config
        )

        response = requests.get(
            self.api_url + '/YaraSource/',
            headers=self.headers,
            params={'search': self.harfanglab_yara_list_name}
        )
        list_of_yara_sources = json.loads(response.content)['results']

        element = next((x for x in list_of_yara_sources if x["name"] == self.harfanglab_yara_list_name), None)
        if element is None:
            # create list
            yara_list = {
                "name": self.harfanglab_yara_list_name,
                "enabled": True,
            }
            response = requests.post(
                self.api_url + '/YaraSource/',
                headers=self.headers,
                json=yara_list
            )
            self.harfanglab_yara_list_id = json.loads(response.content)['id']
        else:
            self.harfanglab_yara_list_id = element['id']

    def _process_message(self, msg):
        # _process_message
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message")
        # Handle creation
        self.helper.log_info(f'Processing the object {data["id"]}')

        if msg.event == "create":
            # TODO YARA, Sigma and IoC
            # TODO Only revoked=false
            if data["type"] == "indicator":
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
                        self.api_url + '/SigmaRule/',
                        headers=self.headers,
                        json=indicator
                    )
                    self.helper.log_info(f'Indicator created = {response}')
                elif data["pattern_type"] == "yara" and data["revoked"] is False and OpenCTIConnectorHelper.get_attribute_in_extension("detection", data) is True:
                    self.helper.log_info(
                        "[CREATE] Processing indicator {"
                        + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                        + "}"
                    )
                    yara_indicator = {
                        "content": data["pattern"],
                        "enabled": OpenCTIConnectorHelper.get_attribute_in_extension("detection", data),
                        "hl_local_testing_status": "in_progress",
                        "hl_status": "stable",
                        "name": data["name"],
                        "source_id": self.harfanglab_yara_list_id
                    }
                    response = requests.post(
                        self.api_url + '/YaraFile/',
                        headers=self.headers,
                        json=yara_indicator
                    )
                    self.helper.log_info(f'Indicator created = {response}')
                # elif data["pattern_type"] == "stix":
                #     # TODO check if it's the right name to get the type?
                #     if data["x_opencti_main_observable_type"] in ["StixFile", "Domain-Name", "IPv4-Addr", "IPv6-Addr", "Url"]:
                #         # TODO Exctract data from pattern
                #         data["pattern"]



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
