import ipaddress

import stix2
from connectors_sdk.models.enums import TLPLevel
from pycti import (
    CaseIncident,
    CustomObjectCaseIncident,
    Identity,
    Incident,
    Indicator,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
        - `generate_id()` methods from `pycti` library MUST be used to generate the `id` of each entity (except observables),
        e.g. `pycti.Identity.generate_id(name="Source Name", identity_class="organization")` for a STIX Identity.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: TLPLevel,
    ):
        """
        Initialize the converter with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `tlp_level`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (TLPLevel): The TLP level to add to the created STIX entities.
        """
        self.helper = helper

        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.value)

    @staticmethod
    def create_author() -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="Sublime", identity_class="organization"),
            name="Sublime",
            identity_class="organization",
            description="Email Security Platform",
            custom_properties={"x_opencti_type": "Organization"},
            allow_custom=True,
        )
        return author

    def create_case_incident(
        self,
        name: str,
        created: str,
        description: str = None,
        object_refs: list = None,
        external_references: list = None,
        severity: str = None,
        priority: str = None,
    ):
        """Create Custom Case Incident STIX object with deterministic ID.

        Args:
            name: Case incident name.
            created: ISO 8601 timestamp used for deterministic ID generation.
            description: Case description.
            object_refs: List of STIX object IDs to include in the case.
            external_references: List of external reference dicts.
            severity: Severity level (e.g. "high", "medium", "low").
            priority: Priority level (e.g. "P1", "P2", "P3", "P4").

        Returns:
            CustomObjectCaseIncident: STIX case-incident object.
        """
        case_data = {
            "id": CaseIncident.generate_id(name=name, created=created),
            "name": name,
            "created": created,
            "created_by_ref": self.author["id"],
            "object_marking_refs": [self.tlp_marking.id],
        }
        if description:
            case_data["description"] = description
        if object_refs:
            case_data["object_refs"] = object_refs
        if external_references:
            case_data["external_references"] = external_references
        if severity:
            case_data["severity"] = severity
        if priority:
            case_data["priority"] = priority

        return CustomObjectCaseIncident(**case_data)

    def create_domain_name(self, value: str):
        """Create DomainName object"""
        return stix2.DomainName(
            value=value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
        )

    def create_email_address(self, value: str):
        """Create EmailAddress object"""
        return stix2.EmailAddress(
            value=value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
        )

    def create_email_message(self, email_data: dict):
        """Create EmailMessage object"""
        return stix2.EmailMessage(**email_data)

    def create_file(
        self,
        hashes: dict,
        file_name: str | None,
        file_size: int | None,
        mime_type: str | None,
    ):
        """Create File object"""
        return stix2.File(
            hashes=hashes,
            name=file_name,
            size=file_size,
            mime_type=mime_type,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
        )

    def create_incident(
        self,
        name,
        created_timestamp,
        description,
        group_id,
        incident_type,
        url,
        severity,
    ):
        """Create Incident object"""
        return stix2.Incident(
            id=Incident.generate_id(name, created_timestamp),
            name=name,
            description=description,
            created=created_timestamp,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking.id],
            external_references=[
                {
                    "source_name": "Sublime",
                    "description": "View this message group in Sublime platform",
                    "url": url,
                    "external_id": str(group_id or "unknown"),
                }
            ],
            custom_properties={
                "x_opencti_type": "Incident",
                "x_opencti_incident_type": incident_type,
                "x_sublime_security_canonical_id": group_id,
            },
            allow_custom=True,
            incident_type=incident_type.capitalize(),
            source="Sublime Security",
            severity=severity,
        )

    def create_indicator(self, pattern):
        """Create Indicator object"""
        return stix2.Indicator(
            id=Indicator.generate_id(pattern),
            pattern=pattern,
            pattern_type="stix",
            labels=["malicious-activity"],
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_type": "Indicator",
            },
            allow_custom=True,
        )

    def create_ip_address(self, ip_value):
        """Create IPv4Address object"""
        if self._is_ipv4(ip_value):
            return stix2.IPv4Address(
                value=ip_value,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": f"{self.author.id}",
                },
            )
        elif self._is_ipv6(ip_value):
            return stix2.IPv6Address(
                value=ip_value,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": f"{self.author.id}",
                },
            )
        else:
            self.helper.connector_logger.error(
                "This value is not a valid IPv4 or IPv6 address",
                {"value": ip_value},
            )

    def create_relationship(
        self, source_id: str, target_id: str, relationship_type: str
    ) -> dict:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param target_id: ID of target in string
        :param relationship_type: Relationship type in string
        :return: Relationship STIX2 object
        """
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
        )

    def create_url(self, url: str):
        """Create URL object"""
        return stix2.URL(
            value=url,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )

    @staticmethod
    def _create_tlp_marking(level):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv4
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False
