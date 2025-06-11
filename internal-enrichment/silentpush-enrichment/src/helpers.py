import copy

import requests
from pycti import OpenCTIConnectorHelper
from settings import API_KEY, API_URI, API_VERIFY_CERT, config
from silentpush.domain_enricher import DomainEnricher
from silentpush.indicator_enricher import IndicatorEnricher
from silentpush.ipv4_enricher import IPv4Enricher
from silentpush.ipv6_enricher import IPv6Enricher
from silentpush.url_enricher import URLEnricher


class SilentPushConnectorHelper:
    """
    The main class trigger for the Silent Push connector
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper(config)
        # self.custom_attribute = get_config_variable(
        #     "TEMPLATE_ATTRIBUTE", ["template", "attribute"], config
        # )

    def _process_message(self, data: dict) -> str:
        """
        Process IPv4, IPv6, Domain, URL or Indicator stix entities

        :param data: The data to be enriched
        :raises ValueError: if stix entity type not supported
        :return: Enriched status or Error
        """

        self.helper.log_debug(f"data: {data}")
        opencti_entity = data["enrichment_entity"]
        self.stix_entity = copy.copy(data["stix_entity"])
        self.helper.log_debug(f"self._stix_entity: {self.stix_entity}")
        match opencti_entity["entity_type"]:
            case "IPv4-Addr":
                _stix_objects = IPv4Enricher(self.helper, self.stix_entity).process()
            case "IPv6-Addr":
                _stix_objects = IPv6Enricher(self.helper, self.stix_entity).process()
            case "Domain-Name" | "Hostname":
                _stix_objects = DomainEnricher(self.helper, self.stix_entity).process()
            case "Url":
                _stix_objects = URLEnricher(self.helper, self.stix_entity).process()
            case "Indicator":
                _stix_objects = IndicatorEnricher(
                    self.helper, self.stix_entity
                ).process()
            case _:
                raise ValueError(
                    f'{opencti_entity["entity_type"]} is not a supported entity type.'
                )
        serialized_bundle = self.helper.stix2_create_bundle(_stix_objects)
        self.helper.log_debug(f"stix_objects serialized: {serialized_bundle}")
        self.helper.send_stix2_bundle(serialized_bundle, allow_custom=True)
        return "Data enriched by Silent Push"

    def ping(self):
        response = requests.get(
            API_URI + "me", headers={"x-api-key": API_KEY}, verify=API_VERIFY_CERT
        )
        self.helper.log_debug(f"ping response {API_URI}, {API_KEY}: {response}")
        if not response.status_code == 200:
            raise PermissionError("Check your API key")

    def run(self) -> None:
        self.ping()
        self.helper.listen(self._process_message)
