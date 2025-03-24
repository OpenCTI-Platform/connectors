"""Shodan InternetDB connector"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Union

import stix2
import validators
from pycti import (
    STIX_EXT_OCTI_SCO,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
    Vulnerability,
)
from requests.exceptions import RequestException
from shodan_internetdb.client import ShodanInternetDbClient, ShodanResult
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

    def _process_message(self, data: Dict) -> str:
        """
        Process the data message
        :param data: Entity data
        :return: None
        """
        # Fetch the observable being processed
        observable = data["enrichment_entity"]
        stix_observable = data["stix_entity"]

        # Check TLP markings, do not submit higher than the max allowed
        tlps = ["TLP:CLEAR"]
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlps.append(marking_definition["definition"])

        for tlp in tlps:
            max_tlp_name = self.config.shodan_max_tlp
            if not OpenCTIConnectorHelper.check_max_tlp(tlp, max_tlp_name):
                log.debug("Skipping observable, TLP is greater than the MAX TLP")
                return "Skipping observable (TLP)"

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
        stix_objects = []
        log.debug("Processing %s", value)
        stix_objects.extend(self._process_domains(stix_observable, result))
        stix_objects.extend(self._process_vulns(stix_observable, result))
        stix_objects.append(self._process_note(stix_observable, result))
        stix_objects.append(self._process_tags(stix_observable, result))

        bundle = stix2.Bundle(objects=stix_objects, allow_custom=True).serialize()
        self.helper.log_info("Sending event STIX2 bundle")
        bundle_sent = self.helper.send_stix2_bundle(bundle)
        return f"Sent {len(bundle_sent)} stix bundle(s) for worker import"

    def _process_note(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> Note:
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
        note = stix2.Note(
            id=Note.generate_id(datetime.now().isoformat(), content),
            created_by_ref=self.converter.author.id,
            object_marking_refs=[self.converter.tlp_marking.id],
            abstract=abstract,
            content=content,
            object_refs=[observable["id"]],
            allow_custom=True,
        )
        return note

    def _process_domains(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> list:
        """
        Add additional domains to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        stix_objects = []
        for name in result.hostnames:
            log.debug("Adding domain %s", name)
            stix_domain = stix2.DomainName(
                value=name,
                object_marking_refs=[self.converter.tlp_marking.id],
                resolves_to_refs=[observable["id"]],
                custom_properties={"created_by_ref": self.converter.author.id},
            )
            stix_objects.append(stix_domain)
        return stix_objects

    def _process_tags(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> Dict:
        """
        Add additional tags to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        for name in result.tags:
            OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "labels", name, True
            )
        return observable

    def _process_vulns(
        self,
        observable: Dict[str, Any],
        result: ShodanResult,
    ) -> list:
        """
        Add additional vulnerabilities to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        stix_objects = []
        now = datetime.utcnow()
        vuln_eol = now + timedelta(days=60)

        for name in result.vulns:
            log.debug("Creating vulnerability %s", name)
            stix_vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(name),
                name=f"{name}",
                created_by_ref=self.converter.author.id,
                object_marking_refs=[self.converter.tlp_marking.id],
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", observable["id"], stix_vuln.id
                ),
                relationship_type="related-to",
                created_by_ref=self.converter.author.id,
                source_ref=observable["id"],
                target_ref=stix_vuln.id,
                object_marking_refs=[self.converter.tlp_marking.id],
                allow_custom=True,
                start_time=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                stop_time=vuln_eol.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            stix_objects.append(stix_vuln)
            stix_objects.append(relationship)
        return stix_objects

    def run(self) -> None:
        """
        Start the connector
        :return: None
        """
        self.helper.listen(message_callback=self._process_message)
