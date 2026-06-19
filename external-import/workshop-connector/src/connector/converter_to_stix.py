import ipaddress
from typing import Literal

import stix2
import validators
from connectors_sdk.models import DomainName  # noqa: F401
from connectors_sdk.models import IPV4Address  # noqa: F401
from connectors_sdk.models import Relationship  # noqa: F401
from connectors_sdk.models import Software  # noqa: F401
from connectors_sdk.models import TLPMarking  # noqa: F401
from connectors_sdk.models import (
    OrganizationAuthor,
)
from connectors_sdk.models import Vulnerability as SDKVulnerability  # noqa: F401
from pycti import (
    Identity,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
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
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ):
        """
        Initialize the converter with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `tlp_level`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (str): The TLP level to add to the created STIX entities.
        """
        self.helper = helper

        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())

    @staticmethod
    def create_author() -> dict | OrganizationAuthor:
        """
        Create Author
        :return: Author in Stix2 object
        """
        stix2_author = stix2.Identity(
            id=Identity.generate_id(name="WORKSHOP", identity_class="organization"),
            name="WORKSHOP",
            identity_class="organization",
            description="Workshop purpose.",
            external_references=[
                stix2.ExternalReference(
                    source_name="External Source",
                    url="CHANGEME",
                    description="DESCRIPTION",
                )
            ],
        )

        # Or using connectors-sdk
        # sdk_author = OrganizationAuthor(
        #     name="Workshop Author",
        #     description="Workshop purpose."
        # )
        # return sdk_author.to_stix2_object()

        return stix2_author

    @staticmethod
    def _create_tlp_marking(level):
        # Marking definition using Stix2 Python library
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

        # Or using connectors-sdk
        # sdk_tlp_marking = TLPMarking(level=level)
        # return sdk_tlp_marking.to_stix2_object()

        return mapping[level]

    def create_relationship(
        self, source: str, relationship_type: str, target: str
    ) -> dict:
        """
        Creates Relationship object
        :param source: Source in string
        :param relationship_type: Relationship type in string
        :param target: Target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source.id, target.id
            ),
            relationship_type=relationship_type,
            source_ref=source.id,
            target_ref=target.id,
            created_by_ref=self.author["id"],
        )

        # Or using connectors-sdk example
        # sdk_stix_relationship = Relationship(
        #     source=source,
        #     type=relationship_type,
        #     target=target
        # )
        # return sdk_stix_relationship.to_stix2_object()

        return relationship

    # ===========================#
    # Other Examples
    # ===========================#

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

    @staticmethod
    def _is_domain(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_domain = validators.domain(value)

        if is_valid_domain:
            return True
        else:
            return False

    def create_obs(self, value: str) -> dict:
        """
        Create observable according to value given
        :param value: Value in string
        :return: Stix object for IPV4, IPV6 or Domain
        """
        if self._is_ipv6(value) is True:
            stix_ipv6_address = stix2.IPv6Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )

            # Or using connectors-sdk example
            # sdk_stix_ipv4 = IPV4Address(value=value, author=self.author)
            # return sdk_stix_ipv4.to_stix2_object()

            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )

            # Or using connectors-sdk example
            # sdk_stix_domain = DomainName(value=value, author=self.author)
            # return sdk_stix_domain.to_stix2_object()

            return stix_domain_name
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address nor DomainName: ",
                {"value": value},
            )

    def create_vulnerability(self, vulnerability: dict) -> dict:
        """
        Create a STIX 2.1 Vulnerability object from vulnerability data.
        :param vulnerability: Dictionary containing vulnerability data
        :return: A STIX 2.1 Vulnerability object.
        """
        stix_vulnerability = stix2.Vulnerability(
            id=Vulnerability.generate_id(name=vulnerability["name"]),
            name=vulnerability["name"],
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "x_opencti_created_by": self.author["id"],
                "x_opencti_labels": vulnerability["tags"],
                "x_opencti_description": vulnerability["description"],
                "x_opencti_epss_score": vulnerability["epss_score"],
                "x_opencti_epss_percentile": vulnerability["epss_percentile"],
                # Cvss v3 (default on OpenCTI)
                "x_opencti_cvss_vector_string": vulnerability["cvss_v3_vector_string"],
                "x_opencti_cvss_base_score": vulnerability["cvss_v3_base_score"],
                # CVSS v4
                "x_opencti_cvss_v4_vector_string": vulnerability[
                    "cvss_v4_vector_string"
                ],
                "x_opencti_cvss_v4_base_score": vulnerability["cvss_v4_base_score"],
            },
        )

        # Or using connectors-sdk example
        # sdk_stix_vulnerability = SDKVulnerability(
        #         name=vulnerability["name"],
        #         description=vulnerability["description"],
        #         author=self.author,
        #         markings=[self.tlp_marking],
        #         epss_score=vulnerability["epss_score"],
        #         epss_percentile=vulnerability["epss_percentile"],
        #         cvss_v3_vector_string=vulnerability["cvss_v3_vector_string"],
        #         cvss_v3_base_score=vulnerability["cvss_v3_base_score"],
        #         cvss_v4_vector_string=vulnerability["cvss_v4_vector_string"],
        #         cvss_v4_base_score=vulnerability["cvss_v4_base_score"],
        #     )
        # return sdk_stix_vulnerability.to_stix2_object()

        return stix_vulnerability

    def create_software(self, software: dict) -> dict:
        """
        Create a STIX 2.1 Software object from software data.
        :param software: Dictionary containing software data
        :return: A STIX 2.1 Software object.
        """
        stix_software = stix2.Software(
            name=software["name"],
            cpe=software["cpe"],
            vendor=software["vendor"],
            version=software["version"],
        )

        # Or using connectors-sdk example
        # sdk_stix_software = Software(
        #     name=software["name"],
        #     cpe=software["cpe"],
        #     vendor=software["vendor"],
        #     version=software["version"],)
        # return sdk_stix_software.to_stix2_object()

        return stix_software
