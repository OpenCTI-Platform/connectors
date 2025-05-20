from typing import Any

import validators
from pycti import OpenCTIConnectorHelper
from shodan_internetdb.client import ShodanInternetDbClient
from shodan_internetdb.config import ConfigConnector
from shodan_internetdb.converter_to_stix import ConverterToStix
from shodan_internetdb.exceptions import (
    ShodanInternetDbApiError,
    ShodanInternetDbEntityNotInScopeError,
    ShodanInternetDbExtractAndCheckMarkingsError,
    ShodanInternetDbInvalidIPv4AddressError,
    ShodanInternetDbInvalidTlpLevelError,
    ShodanInternetDbNotFoundError,
)

__all__ = [
    "ShodanInternetDBConnector",
]


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
                raise ShodanInternetDbExtractAndCheckMarkingsError(
                    "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                    "the connector does not has access to this observable, please check the group of the connector user"
                )

    def _send_bundle(self, stix_objects: list[Any]) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)
        return f"Sending {len(bundles_sent)} stix bundle(s) for worker import"

    def _is_entity_in_scope(self, entity_type: str) -> bool:
        return self.helper.connect_scope.lower() == entity_type.lower()

    def _process_message(self, data: dict[str, Any]) -> str:
        """
        Process the data message
        :param data: Entity data
        :return: None
        """
        # Fetch the observable being processed
        observable = data["enrichment_entity"]
        stix_observable = data["stix_entity"]
        stix_objects = data["stix_objects"]

        self.extract_and_check_markings(observable)

        if not self._is_entity_in_scope(observable["entity_type"]):
            if data.get("event_type"):
                raise ShodanInternetDbEntityNotInScopeError(
                    f"[CONNECTOR] Failed to process observable, {observable['entity_type']} is not a supported entity type"
                )
            # If it is not in scope AND entity bundle passed through playbook,
            # we should return the original bundle unchanged
            return self._send_bundle(stix_objects)

        # Process the observable value
        value = stix_observable["value"]

        if not validators.ipv4(value):
            raise ShodanInternetDbInvalidIPv4AddressError(
                "[CONNECTOR] Observable value is not an IPv4 address"
            )

        result = self._client.query(value)

        # Process the result
        self.helper.connector_logger.debug("Processing %s", value)

        return self._send_bundle(
            stix_objects + self.converter.create_stix_objects(stix_observable, result)
        )

    def process_message(self, data: dict[str, Any]) -> str:
        try:
            return self._process_message(data)
        except (
            ShodanInternetDbInvalidIPv4AddressError,
            ShodanInternetDbEntityNotInScopeError,
            ShodanInternetDbApiError,
            ShodanInternetDbNotFoundError,
            ShodanInternetDbExtractAndCheckMarkingsError,
            ShodanInternetDbInvalidTlpLevelError,
        ) as e:
            self.helper.connector_logger.warning(e)
            return str(e)

    def run(self) -> None:
        """
        Start the connector
        :return: None
        """
        self.helper.listen(message_callback=self._process_message)
