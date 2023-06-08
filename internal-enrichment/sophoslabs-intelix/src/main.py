import base64
import os
import time

import requests
import yaml

from intelix import intelixlookup
from pycti import OpenCTIConnectorHelper, get_config_variable


class ConnectorStart:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.client_id = get_config_variable(
            "INTELIX_CLIENT_ID", ["intelix", "intelix_client_id"], config
        )
        self.client_secret = get_config_variable(
            "INTELIX_CLIENT_SECRET", ["intelix", "intelix_client_secret"], config
        )
        self.intelix_region_uri = get_config_variable(
            "INTELIX_REGION_URI", ["intelix", "intelix_region_uri"], config
        )
        self.token = self._get_token()

    def _get_token(self):
        creds = f"{self.client_id}:{self.client_secret}"
        t = base64.b64encode(creds.encode("UTF-8")).decode("ascii")
        d = {"grant_type": "client_credentials"}
        h = {
            "Authorization": f"Basic {t}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        r = requests.post("https://api.labs.sophos.com/oauth2/token", headers=h, data=d)
        if r.ok:
            r = r.json()
            return r["access_token"]
        else:
            raise ValueError("Unable to authenticate with Intelix")

    def _process_message(self, data) -> str:
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        observable_id = observable["id"]
        observable_value = observable["observable_value"]
        observable_type = observable["entity_type"]
        self.helper.log_info(observable)
        analysis = intelixlookup(
            self.token, observable_value, self.intelix_region_uri, observable_type
        )
        self.helper.log_info(analysis)
        return self._send_knowledge(observable_id, analysis, observable_value)

    def _send_knowledge(self, observable_id, analysis, observable_value):
        # Create external reference
        external_reference = self.helper.api.external_reference.create(
            source_name=f"SophosLabs Intelix {observable_value}",
            url=analysis["url"],
            description=f"SophosLabs Intelix Results: \
                        \nDescription:  {analysis['description']} \
                        \nCategory:     {analysis['category'].title()}",
        )

        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable_id,
            external_reference_id=external_reference["id"],
        )

        label = self.helper.api.label.create(
            value=analysis["category"], color=analysis["labelcolor"]
        )

        self.helper.api.stix_cyber_observable.add_label(
            id=observable_id, label_id=label["id"]
        )

        return f"Processing {observable_value} with SophosLabs Intelix"

    # Start the main loop
    def start(self) -> None:
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        openctitest = ConnectorStart()
        openctitest.start()
    except Exception as e:
        time.sleep(10)
        exit(0)
