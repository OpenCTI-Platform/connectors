import os
import yaml
import json
import requests

from pycti import OpenCTIConnectorHelper, get_config_variable


class TaniumConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.tanium_url = get_config_variable("TANIUM_URL", ["tanium", "url"], config)
        self.tanium_login = get_config_variable(
            "TANIUM_LOGIN", ["tanium", "login"], config
        )
        self.tanium_password = get_config_variable(
            "TANIUM_PASSWORD", ["tanium", "password"], config
        )
        self.tanium_indicator_types = get_config_variable(
            "TANIUM_INDICATOR_TYPES", ["tanium", "indicator_types"], config
        ).split(",")
        self.tanium_observable_types = get_config_variable(
            "TANIUM_OBSERVABLE_TYPES", ["tanium", "observable_types"], config
        ).split(",")
        self.tanium_import_label = get_config_variable(
            "TANIUM_IMPORT_LABEL",
            ["tanium", "import_label"],
            config,
        )

        # Variables
        self.session = None

        # Open a session
        self._get_session()

    def _get_session(self):
        payload = {
            "username": self.tanium_login,
            "password": self.tanium_password,
        }
        r = requests.post(self.tanium_url + "/api/v2/session/login", json=payload)
        if r.status_code == 200:
            result = r.json()
            self.session = result["data"]["session"]
        else:
            raise ValueError("Cannot login to the Tanium API")

    def _query(self, method, uri, payload, retry=False):
        headers = {"session": self.session}
        if method == "get":
            r = requests.get(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "post":
            r = requests.post(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "put":
            r = requests.put(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "patch":
            r = requests.patch(self.tanium_url + uri, headers=headers, json=payload)
        else:
            raise ValueError("Unspported method")
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 401 and not retry:
            self._get_session()
            self._query(method, uri, payload, True)
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")

    def _add_observable(self, observable_type, observable_value):


    def _process_message(self, msg):
        data = json.loads(msg.data)
        entity_type = data["data"]["type"]

        if entity_type.lower() not in self.tanium_indicator_types and entity_type.lower() not in self.tanium_observable_types:
            return

        # Handle creation
        if msg.event == "create":
            if self.tanium_import_label not in data["data"]["labels"]:
                return
            if entity_type.lower() == "ipv4-addr":


    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    TaniumInstance = TaniumConnector()
    TaniumInstance.start()
