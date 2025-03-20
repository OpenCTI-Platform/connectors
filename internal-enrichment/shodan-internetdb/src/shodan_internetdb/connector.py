"""Shodan InternetDB connector"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import stix2
import validators
import yaml
from pycti import (
    STIX_EXT_OCTI_SCO,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
    Vulnerability,
)
from requests.exceptions import RequestException

from .client import ShodanInternetDbClient, ShodanResult
from .config import RootConfig

__all__ = [
    "ShodanInternetDBConnector",
]


class ShodanInternetDBConnector:
    """Shodan InternetDB connector"""

    def __init__(self) -> None:
        """Constructor"""
        config_path = Path(__file__).parent.parent.joinpath("config.yml")
        config = (
            yaml.load(config_path.open(), Loader=yaml.SafeLoader)
            if config_path.is_file()
            else {}
        )

        self._config = RootConfig.parse_obj(config)
        self._helper = OpenCTIConnectorHelper(config, True)

        self._identity = self._helper.api.identity.create(
            type="Organization",
            name="Shodan",
            description="Shodan is a search engine for Internet-connected devices.",
        )
        self._identity_id = self._identity["standard_id"]
        self._object_marking_id = stix2.TLP_WHITE["id"]

        self._client = ShodanInternetDbClient(verify=self._config.shodan.ssl_verify)

    def extract_and_check_markings(self, opencti_entity: dict[str, Any]) -> None:
        tlps = ["TLP:CLEAR"]
        tlps.extend(
            marking_definition["definition"]
            for marking_definition in opencti_entity.get("objectMarking", [])
            if marking_definition["definition_type"] == "TLP"
        )
        for tlp in tlps:
            max_tlp_name = self._config.shodan.max_tlp.name
            if not OpenCTIConnectorHelper.check_max_tlp(tlp, max_tlp_name):
                self._helper.connector_logger.debug(
                    "Skipping observable, TLP is greater than the MAX TLP"
                )
                raise ValueError(
                    "[CONNECTOR] Enrichment of the entity was unsuccessful, the entity's TLP is greater than the "
                    "MAX TLP allowed in the connector's configuration, so it does not have the necessary authorisation "
                    "to enrich this entity."
                )

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self._helper.stix2_create_bundle(stix_objects)
        bundles_sent = self._helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = (
            "Sending " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
        )
        return info_msg

    def process_message(self, data: dict[str, Any]) -> str:
        """
        Get the observable created/modified in OpenCTI and check which type to send for process
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """

        self.extract_and_check_markings(opencti_entity=data["enrichment_entity"])

        stix_observable = data["stix_entity"]

        # Process the observable value
        value = stix_observable["value"]
        if not validators.ipv4(value):
            self._helper.connector_logger.error(
                "Observable value is not an IPv4 address"
            )
            return "Skipping observable (ipv4 validation)"

        try:
            result = self._client.query(value)
        except RequestException:
            self._helper.connector_logger.error("Shodan API error")
            return "Skipping observable (Shodan API error)"

        if result is None:
            self._helper.connector_logger.debug("No information available on %s", value)
            return "Skipping observable (Shodan 404)"

        # Process the result
        self._helper.connector_logger.debug("Processing %s", value)
        stix_objects = data.get("stix_objects", [])
        stix_objects.extend(self._process_domains(stix_observable, result))
        stix_objects.extend(self._process_vulns(stix_observable, result))
        stix_objects.append(self._process_note(stix_observable, result))
        stix_objects.append(self._process_tags(stix_observable, result))
        stix_objects.append(self._identity)

        return self._send_bundle(stix_objects)

    def _process_note(
        self,
        observable: dict[str, Any],
        result: ShodanResult,
    ) -> Note:
        """
        Add an enrichment note to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """

        def format_list(alist: list[str] | list[int]) -> str:
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
            created_by_ref=self._identity_id,
            object_marking_refs=[self._object_marking_id],
            abstract=abstract,
            content=content,
            object_refs=[observable["id"]],
            allow_custom=True,
        )
        return note

    def _process_domains(
        self,
        observable: dict[str, Any],
        result: ShodanResult,
    ) -> list[stix2.DomainName]:
        """
        Add additional domains to the observable
        :param observable: Observable data
        :param result: Shodan data
        :return: None
        """
        stix_objects = []
        for name in result.hostnames:
            self._helper.connector_logger.debug("Adding domain %s", name)
            stix_domain = stix2.DomainName(
                value=name,
                object_marking_refs=[self._object_marking_id],
                resolves_to_refs=[observable["id"]],
                custom_properties={"created_by_ref": self._identity_id},
            )
            stix_objects.append(stix_domain)
        return stix_objects

    def _process_tags(
        self,
        observable: dict[str, Any],
        result: ShodanResult,
    ) -> dict[str, Any]:
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
        observable: dict[str, Any],
        result: ShodanResult,
    ) -> list[stix2.Vulnerability | stix2.Relationship]:
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
            self._helper.connector_logger.debug("Creating vulnerability %s", name)
            stix_vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(name),
                name=f"{name}",
                created_by_ref=self._identity_id,
                object_marking_refs=[self._object_marking_id],
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", observable["id"], stix_vuln.id
                ),
                relationship_type="related-to",
                created_by_ref=self._identity_id,
                source_ref=observable["id"],
                target_ref=stix_vuln.id,
                object_marking_refs=[self._object_marking_id],
                allow_custom=True,
                start_time=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                stop_time=vuln_eol.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            stix_objects.append(stix_vuln)
            stix_objects.append(relationship)
        return stix_objects

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self._helper.listen(message_callback=self.process_message)
