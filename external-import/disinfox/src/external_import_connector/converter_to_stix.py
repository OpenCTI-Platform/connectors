import ipaddress

import stix2
import validators
from pycti import Identity, StixCoreRelationship


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()
        self.external_reference = self.create_external_reference()

    @staticmethod
    def create_external_reference() -> list:
        """
        Create external reference
        :return: External reference STIX2 list
        """
        external_reference = stix2.ExternalReference(
            source_name="External Source",
            url="CHANGEME",
            description="DESCRIPTION",
        )
        return [external_reference]

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="Source Name", identity_class="organization"),
            name="Source Name",
            identity_class="organization",
            description="DESCRIPTION",
        )
        return author

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> dict:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
            external_references=self.external_reference,
        )
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
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_domain_name
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address nor DomainName: ",
                {"value": value},
            )
