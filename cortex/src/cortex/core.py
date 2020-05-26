# -*- coding: utf-8 -*-
"""OpenCTI Cortex client module."""

import yaml
import os

from pycti import OpenCTIConnectorHelper, get_config_variable

from .client import CortexClient


class Cortex:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        # Extra config
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL", ["connector", "confidence_level"], config,
        )
        self.URL = get_config_variable("CORTEX_BASE_URL", ["cortex", "url"], config)
        self.API_KEY = get_config_variable(
            "CORTEX_API_KEY", ["cortex", "auth_key"], config
        )
        self.VERIFY_SSL = get_config_variable(
            "CORTEX_VERIFY_SSL", ["cortex", "verify_ssl"], config
        )

        self.helper = OpenCTIConnectorHelper(config)
        self.helper.log_info(f"loaded cortex config: {config}")

        self.cortex_client = CortexClient(
            api_url=self.URL, api_key=self.API_KEY, verify_ssl=self.VERIFY_SSL
        )

    def run(self):
        self.helper.listen(self._process_message)

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_observable.read(id=entity_id)
        self._process_observable(observable)

    def _process_observable(self, observable):
        o_type = observable["entity_type"].lower()

        if o_type == "ipv4-addr" or o_type == "ipv6-addr":
            for ana in self.cortex_client.IP_ANALYZERS:
                self.cortex_client.launch_job(ana, "ip", observable["observable_value"])

        if o_type == "domain":
            for ana in self.cortex_client.DOMAIN_ANALYZERS:
                self.cortex_client.launch_job(
                    ana, "domain", observable["observable_value"]
                )
