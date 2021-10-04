# coding: utf-8

import os
import yaml
import requests
import time
import json

from pycti import OpenCTIConnectorHelper, get_config_variable


class LastInfoSecEnrichment:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_url = "https://api.client.lastinfosec.com/v2"
        self.lastinfosec_apikey = get_config_variable(
            "CONFIG_LIS_APIKEY_CTI", ["lastinfosec", "api_key_cti"], config
        )
        self.proxy_http = get_config_variable(
            "PROXY_HTTP", ["opencti", "proxy_http"], config
        )
        self.proxy_https = get_config_variable(
            "PROXY_HTTPS", ["opencti", "proxy_https"], config
        )

    def _send_knowledge(self, observable, report, value):
        # Create external reference
        external_reference = self.helper.api.external_reference.create(
            source_name="Last Info Sec",
            url="{}/stix21/search_hash/{}".format(self.api_url, value),
            description="Last Info Sec Threat Feed",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"],
            external_reference_id=external_reference["id"],
        )
        # Send bundle
        bundle = json.dumps(
            report
        )  # Python uses single quotes and STIX2.1 needs double quotes
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found "
                "(may be linked to data seggregation, check your group and permissions)"
            )

        value = observable["observable_value"]
        proxy_dic = {}
        if self.proxy_http is not None:
            proxy_dic["http"] = self.proxy_http
        if self.proxy_https is not None:
            proxy_dic["https"] = self.proxy_https

        if observable["entity_type"] == "StixFile":
            url = "{}/stix21/search_hash/{}?api_key={}&platform=opencti".format(
                self.api_url, value, self.lastinfosec_apikey
            )
        if observable["entity_type"] == "Domain-Name":
            url = "{}/stix21/search_host/{}?api_key={}&platform=opencti".format(
                self.api_url, value, self.lastinfosec_apikey
            )
        response = requests.get(url, proxies=proxy_dic)

        if response.status_code == 422:
            return "{} not found...".format(value)
        else:
            response.raise_for_status()

        json_resp = response.json()
        return self._send_knowledge(observable, json_resp["message"][0], value)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        lis_enrichment = LastInfoSecEnrichment()
        lis_enrichment.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
