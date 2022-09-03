"""Shodan InternetDB connector"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict

import validators
import yaml
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from requests.exceptions import RequestException

from .client import ShodanInternetDbClient, ShodanResult
from .config import RootConfig

__all__ = [
    "ShodanInternetDBConnector",
]

log = logging.getLogger(__name__)


class ShodanInternetDBConnector:
    """Shodan InternetDB connector"""

    def __init__(self):
        """Constructor"""
        config_path = Path(__file__).parent.parent.joinpath("config.yml")
        config = (
            yaml.load(config_path.open(), Loader=yaml.SafeLoader)
            if config_path.is_file()
            else {}
        )

        self._config = RootConfig.parse_obj(config)
        self._helper = OpenCTIConnectorHelper(config)

        self._identity = self._helper.api.identity.create(
            type="Organization",
            name="Shodan",
            description="Shodan is a search engine for Internet-connected devices.",
        )
        self._identity_id = self._identity["standard_id"]

        self._client = ShodanInternetDbClient(verify=self._config.shodan.ssl_verify)

    def start(self) -> None:
        """
        Start the connector
        :return: None
        """
        self._helper.listen(self._process_message)

    def _process_message(self, data: Dict[str, Any]) -> str:
        """
        Process the data message
        :param data: Entity data
        :return: None
        """
        # Fetch the observable being processed
        entity_id = data["entity_id"]
        observable = self._helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            log.error("Observable not found with entity_id %s", entity_id)
            return "Observable not found"

        # Check TLP markings, do not submit higher than the max allowed
        tlps = ["TLP:CLEAR"]
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlps.append(marking_definition["definition"])

        for tlp in tlps:
            max_tlp_name = self._config.shodan.max_tlp.name
            if max_tlp_name == 'TLP:WHITE':
                max_tlp_name = 'TLP:CLEAR'

            if not OpenCTIConnectorHelper.check_max_tlp(tlp, max_tlp_name):
                log.debug("Skipping observable, TLP is greater than the MAX TLP")
                return "Skipping observable (TLP)"

        # Process the observable value
        value = observable["value"]
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
        self._process_description(observable, result)
        self._process_domains(observable, result)
        self._process_tags(observable, result)
        self._process_vulns(observable, result)
        self._process_indicator(observable, result)

        return "Success"

    def _process_description(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> None:
        """
        Update the observable description
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        description = observable.get("x_opencti_description") or ""
        description = description.rstrip()

        if description:
            description += "\n\n"

        description += "```"
        description += "\nShodan InternetDB:"
        description += "\n------------------"
        description += "\nHostnames:"
        description += "".join(f"\n- {name}" for name in result.hostnames) or " n/a"
        description += "\n------------------"
        description += "\nSoftware:"
        description += "".join(f"\n- {name}" for name in result.cpes) or " n/a"
        description += "\n------------------"
        description += "\nVulnerabilities:"
        description += "".join(f"\n- {name}" for name in result.vulns) or " n/a"
        description += "\n------------------"
        description += "\nPorts:"
        description += "".join(f"\n- {name}" for name in result.ports) or " n/a"
        description += "\n------------------"
        description += "\n```"
        description += "\n"

        # Update the observable so the domain/indicator can use it
        observable["x_opencti_description"] = description
        log.debug(f"Updating description:\n{description}")
        self._helper.api.stix_cyber_observable.update_field(
            id=observable["id"],
            input={
                "key": "x_opencti_description",
                "value": description,
            },
        )

    def _process_domains(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> None:
        """
        Add additional domains to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        markings = observable["objectMarkingIds"]

        for name in result.hostnames:
            log.debug("Adding domain %s", name)
            domain = self._helper.api.stix_cyber_observable.create(
                observableData=dict(
                    type="Domain-Name",
                    value=name,
                ),
                objectMarking=markings,
                createdBy=self._identity_id,
                update=True,
            )

            log.debug("Creating domain relationship")
            self._helper.api.stix_cyber_observable_relationship.create(
                fromId=domain["id"],
                toId=observable["id"],
                relationship_type="resolves-to",
                createdBy=self._identity_id,
                objectMarking=markings,
                confidence=self._helper.connect_confidence_level,
                update=True,
            )

    def _process_tags(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> None:
        """
        Add additional tags to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        for name in result.tags:
            log.debug("Creating label %s", name)
            label = self._helper.api.label.create(value=name)

            log.debug("Adding to observable")
            self._helper.api.stix_cyber_observable.add_label(
                id=observable["id"],
                label_id=label["id"],
            )

    def _process_vulns(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> None:
        """
        Add additional vulnerabilities to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        now = datetime.now()
        vuln_eol = now + timedelta(days=60)

        for name in result.vulns:
            log.debug("Creating vulnerability %s", name)
            vuln = self._helper.api.vulnerability.create(
                name=name,
                createdBy=self._identity_id,
            )

            log.debug("Creating vulnerability relationship")
            self._helper.api.stix_core_relationship.create(
                fromId=observable["id"],
                toId=vuln["id"],
                relationship_type="related-to",
                createdBy=self._identity_id,
                start_time=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                stop_time=vuln_eol.strftime("%Y-%m-%dT%H:%M:%SZ"),
                confidence=self._helper.connect_confidence_level,
                update=True,
            )

    def _process_indicator(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> None:
        """
        Create an indicator and link it back
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        if not self._config.shodan.create_indicators:
            return

        value = observable["value"]
        description = observable["x_opencti_description"]

        log.debug("Creating indicator %s", value)
        indicator = self._helper.api.indicator.create(
            name=value,
            description=description,
            pattern_type="stix",
            pattern=f"[ipv4-addr:value = '{value}']",
            x_opencti_main_observable_type="IPv4-Addr",
            objectLabel=result.tags,
            createdBy=self._identity_id,
            confidence=self._helper.connect_confidence_level,
            x_opencti_detection=True,
            update=True,
        )

        log.debug("Creating indicator relationship")
        self._helper.api.stix_core_relationship.create(
            fromId=indicator["id"],
            toId=observable["id"],
            relationship_type="based-on",
            createdBy=self._identity_id,
            confidence=self._helper.connect_confidence_level,
            update=True,
        )
