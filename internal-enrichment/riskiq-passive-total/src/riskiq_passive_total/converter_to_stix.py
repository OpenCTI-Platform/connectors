import datetime

import stix2
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

    @staticmethod
    def create_author() -> stix2.Identity:
        """
        Create an Identity Stix object

        :return: An Identity STIX object
        """
        author = stix2.Identity(
            id=Identity.generate_id("RiskIQ PassiveTotal", "organization"),
            name="RiskIQ PassiveTotal",
            description="RiskIQ Passive Total enrichment connector can be used to enrich ipv4-address "
            "and domain-name observables with Passive DNS",
            identity_class="organization",
        )

        return author

    def create_ipv4_observable(self, data: dict) -> stix2.IPv4Address:
        """
        Create an IPv4Address observable object based on the provided PassiveTotal DNS data.

        :param data: Dictionary of PassiveDNS properties
        :return: An IPv4Address STIX object
        """
        stix_ip_v4_observable = stix2.IPv4Address(
            value=data["resolve"],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_main_observable_type": "IPv4-Addr",
            },
        )
        return stix_ip_v4_observable

    def create_ipv6_observable(self, data: dict) -> stix2.IPv6Address:
        """
        Create an IPv6Address observable object based on the provided PassiveTotal DNS data.

        :param data: Dictionary of PassiveDNS properties
        :return: An IPv6Address STIX object
        """
        stix_ip_v6_observable = stix2.IPv6Address(
            value=data["resolve"],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_main_observable_type": "IPv6-Addr",
            },
        )
        return stix_ip_v6_observable

    def create_domain_observable(self, data: dict) -> stix2.DomainName:
        """
        Create an DomainName observable object based on the provided PassiveTotal DNS data.

        :param data: Dictionary of PassiveDNS properties
        :return: An DomainName STIX object
        """
        stix_domain_observable = stix2.DomainName(
            value=data["resolve"],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_main_observable_type": "Domain-Name",
            },
        )
        return stix_domain_observable

    def create_email_observable(self, data: dict) -> stix2.EmailAddress:
        """
        Create an EmailAddress observable object based on the provided PassiveTotal DNS data.

        :param data: Dictionary of PassiveDNS properties
        :return: An EmailAddress STIX object
        """
        stix_email_observable = stix2.EmailAddress(
            value=data["resolve"],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_main_observable_type": "Email-Addr",
            },
        )
        return stix_email_observable

    def create_stix_relationship(
        self,
        source_ref: str,
        stix_core_relationship_type: str,
        target_ref: str,
        start_time: datetime,
        stop_time: datetime,
        description: str | None = None,
    ) -> StixCoreRelationship:
        """
        This method allows you to create a relationship in Stix2 format.

        :param source_ref: This parameter is the "from" of the relationship.
        :param stix_core_relationship_type: This parameter defines the type of relationship between the two entities.
        :param target_ref: This parameter is the "to" of the relationship.
        :param start_time: This parameter is the start of the relationship. Value not required, None by default.
        :param stop_time: This parameter is the stop of the relationship. Value not required, None by default.
        :param description: This parameter allows to add a description, used here to add the associated DNS record type.
        :return: An StixCoreRelationship STIX object
        """

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref, start_time
            ),
            description=description,
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            start_time=start_time,
            stop_time=stop_time,
            target_ref=target_ref,
            created_by_ref=self.author,
            object_marking_refs=[stix2.TLP_WHITE],
        )
