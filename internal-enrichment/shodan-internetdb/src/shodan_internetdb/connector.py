"""Shodan InternetDB connector"""

from __future__ import annotations

import logging
from typing import Any

import stix2
import validators
from pycti import (
    OpenCTIConnectorHelper,
)
from requests.exceptions import RequestException
from shodan_internetdb.client import ShodanInternetDbClient
from shodan_internetdb.config import ConfigConnector
from shodan_internetdb.converter_to_stix import ConverterToStix

__all__ = [
    "ShodanInternetDBConnector",
]


log = logging.getLogger(__name__)


class ShodanInternetDBConnector:
    """Shodan InternetDB connector"""

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigConnector) -> None:
        """Constructor"""
        self.config = config
        self.helper = helper
        self._client = ShodanInternetDbClient(verify=self.config.shodan_ssl_verify)
        self.converter = ConverterToStix(self.helper)

    def extract_and_check_markings(self, observable: dict[str, Any]) -> None:
        max_tlp_name = self.config.shodan_max_tlp
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP" and not (
                OpenCTIConnectorHelper.check_max_tlp(
                    tlp=marking_definition["definition"], max_tlp=max_tlp_name
                )
            ):
                raise ValueError(
                    "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                    "the connector does not has access to this observable, please check the group of the connector user"
                )

    def _process_message(self, data: dict[str, Any]) -> str:
        """
        Process the data message
        :param data: Entity data
        :return: None
        """
        # Fetch the observable being processed
        observable = data["enrichment_entity"]
        stix_observable = data["stix_entity"]

        self.extract_and_check_markings(observable)

        # Process the observable value
        value = stix_observable["value"]
        if not validators.ipv4(value):
            log.error("Observable value is not an IPv4 address")
            return "Skipping observable (ipv4 validation)"

        try:
            result = self._client.query(value)
        except RequestException:
            log.exception("Shodan API error")
            return "Skipping observable (Shodan API error)"

        if result is None:
            log.debug("No information available on %s", value)
            return "Skipping observable (Shodan 404)"

        # Process the result
        log.debug("Processing %s", value)

        stix_objects = self.converter.create_stix_objects(stix_observable, result)

        bundle = stix2.Bundle(objects=stix_objects, allow_custom=True).serialize()
        self.helper.log_info("Sending event STIX2 bundle")
        bundle_sent = self.helper.send_stix2_bundle(bundle)
        return f"Sent {len(bundle_sent)} stix bundle(s) for worker import"

    def run(self) -> None:
        """
        Start the connector
        :return: None
        """
        self.helper.listen(message_callback=self._process_message)
