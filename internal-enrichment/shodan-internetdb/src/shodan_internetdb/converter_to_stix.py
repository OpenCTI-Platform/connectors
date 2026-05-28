import datetime
from typing import Any, Literal

import pycti
import stix2
from shodan_internetdb.client import ShodanResult
from shodan_internetdb.exceptions import ShodanInternetDbInvalidTlpLevelError


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper: pycti.OpenCTIConnectorHelper):
        self.helper = helper
        self.author = self._create_author()
        self.tlp_marking = self._create_tlp_marking("white")

    def _create_author(
        self,
    ) -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        return stix2.Identity(
            id=pycti.Identity.generate_id(name="Shodan", identity_class="organization"),
            name="Shodan",
            identity_class="organization",
            description="Shodan is a search engine for Internet-connected devices.",
        )

    @staticmethod
    def _create_tlp_marking(
        level: Literal["white", "clear", "green", "amber", "amber+strict", "red"],
    ) -> stix2.MarkingDefinition:
        match level:
            case "white" | "clear":
                return stix2.TLP_WHITE
            case "green":
                return stix2.TLP_GREEN
            case "amber":
                return stix2.TLP_AMBER
            case "amber+strict":
                return stix2.MarkingDefinition(
                    id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                    definition_type="statement",
                    definition={"statement": "custom"},
                    custom_properties={
                        "x_opencti_definition_type": "TLP",
                        "x_opencti_definition": "TLP:AMBER+STRICT",
                    },
                )
            case "red":
                return stix2.TLP_RED
            case _:  # default
                raise ShodanInternetDbInvalidTlpLevelError(
                    f"Invalid TLP level: {level}"
                )

    def _create_domain_names(
        self,
        observable_id: str,
        hostnames: list[str],
    ) -> list[stix2.DomainName]:
        return [
            stix2.DomainName(
                value=hostname,
                object_marking_refs=[self.tlp_marking.id],
                resolves_to_refs=[observable_id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author.id,
                },
            )
            for hostname in hostnames
        ]

    def _create_vulnerabilities_and_relationships(
        self,
        observable_id: str,
        vulnerability_names: list[str],
    ) -> list[stix2.Vulnerability | stix2.Relationship]:
        stix_objects = []
        now = datetime.datetime.now(tz=datetime.UTC)
        vuln_eol = now + datetime.timedelta(days=60)

        for name in vulnerability_names:
            self.helper.connector_logger.debug("Creating vulnerability %s", name)
            stix_vuln = stix2.Vulnerability(
                id=pycti.Vulnerability.generate_id(name),
                name=f"{name}",
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            relationship = stix2.Relationship(
                id=pycti.StixCoreRelationship.generate_id(
                    "related-to", observable_id, stix_vuln.id
                ),
                relationship_type="related-to",
                created_by_ref=self.author.id,
                source_ref=observable_id,
                target_ref=stix_vuln.id,
                object_marking_refs=[self.tlp_marking.id],
                allow_custom=True,
                start_time=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                stop_time=vuln_eol.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            stix_objects.extend([stix_vuln, relationship])
        return stix_objects

    def _create_note(
        self,
        observable_id: str,
        observable_value: str,
        hostnames: list[str],
        cpes: list[str],
        vulns: list[str],
        ports: list[int],
    ) -> stix2.Note:

        def format_list(alist: list[str] | list[int]) -> str:
            """Format a list of primitives into a Markdown list"""
            return "".join(f"\n- {name}" for name in alist) or "n/a"

        abstract = f"Shodan InternetDB enrichment of {observable_value}"
        content = (
            "```\n"
            "Shodan InternetDB:\n"
            "------------------\n"
            f"Hostnames: {format_list(hostnames)}\n"
            "------------------\n"
            f"Software: {format_list(cpes)}\n"
            "------------------\n"
            f"Vulnerabilities: {format_list(vulns)}\n"
            "------------------\n"
            f"Ports: {format_list(ports)}\n"
            "------------------\n"
            "```\n"
        )
        note = stix2.Note(
            id=pycti.Note.generate_id(
                datetime.datetime.now(tz=datetime.UTC).isoformat(), content
            ),
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            abstract=abstract,
            content=content,
            object_refs=[observable_id],
            allow_custom=True,
        )
        return note

    def _create_tags(
        self, observable: dict[str, Any], tag_names: list[str]
    ) -> list[dict[str, Any]]:
        return [
            pycti.OpenCTIStix2.put_attribute_in_extension(
                observable, pycti.STIX_EXT_OCTI_SCO, "labels", name, True
            )
            for name in tag_names
        ]

    def create_stix_objects(
        self, stix_observable: dict[str, Any], result: ShodanResult
    ) -> list[
        stix2.DomainName
        | stix2.Vulnerability
        | stix2.Relationship
        | stix2.Note
        | stix2.Identity
        | stix2.MarkingDefinition
        | dict[str, Any]
    ]:
        return (
            self._create_domain_names(
                observable_id=stix_observable["id"],
                hostnames=result.hostnames,
            )
            + self._create_vulnerabilities_and_relationships(
                observable_id=stix_observable["id"],
                vulnerability_names=result.vulns,
            )
            + self._create_tags(stix_observable, result.tags)
            + [
                self._create_note(
                    observable_id=stix_observable["id"],
                    observable_value=stix_observable["value"],
                    hostnames=result.hostnames,
                    cpes=result.cpes,
                    vulns=result.vulns,
                    ports=result.ports,
                ),
                self.author,
                self.tlp_marking,
            ]
        )
