"""Shodan InternetDB connector"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Union

import pycti
import stix2
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
        self._object_marking_id = stix2.TLP_WHITE["id"]

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
        self._process_domains(observable, result)
        self._process_tags(observable, result)
        self._process_vulns(observable, result)
        self._process_note(observable, result)

        return "Success"

    def _process_note(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> None:
        """
        Add an enrichment note to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """

        def format_list(alist: List[Union[str, int]]) -> str:
            """Format a list of primitives into a Markdown list"""
            return "".join(f"\n- {name}" for name in alist) or "n/a"

        value = observable["value"]
        abstract = f"Shodan InternetDB enrichment of {value}"
        content = f"""```
Shodan InternetDB:
------------------
Hostnames: {format_list(result.hostnames)}
------------------
Software: {format_list(result.cpes)}
------------------
Vulnerabilities: {format_list(result.vulns)}
------------------
Ports: {format_list(result.ports)}
------------------
```
"""

        self._helper.api.note.create(
            stix_id=pycti.Note.generate_id(),
            createdBy=self._identity_id,
            objectMarking=[self._object_marking_id],
            confidence=self._helper.connect_confidence_level,
            objects=[observable["id"]],
            authors=[self._identity_id],
            abstract=abstract,
            content=content,
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
        now = datetime.utcnow()
        vuln_eol = now + timedelta(days=60)

        for name in result.vulns:
            log.debug("Creating vulnerability %s", name)
            vuln = self._helper.api.vulnerability.create(
                stix_id=pycti.Vulnerability.generate_id(name),
                name=name,
                createdBy=self._identity_id,
                objectMarking=[self._object_marking_id],
                confidence=self._helper.connect_confidence_level,
                update=True,
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
                objectMarking=[self._object_marking_id],
                update=True,
            )
