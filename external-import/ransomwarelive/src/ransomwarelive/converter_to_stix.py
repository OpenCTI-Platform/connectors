import stix2
import stix2.exceptions
from pycti import Identity, MarkingDefinition, StixCoreRelationship
import datetime
from .utils import is_ipv4, is_ipv6


def handle_stix2_error(decorated_function):
    """
    Decorate ConverterToStix instance method to handle STIX 2.1 exceptions.
    In case of an exception, log the error and return None.
    :param decorated_function: Method to decorate
    :return: Decorated method
    """

    def decorator(self, *args, **kwargs):
        try:
            return decorated_function(self, *args, **kwargs)
        except stix2.exceptions.STIXError as e:
            self.helper.connector_logger.error(str(e))
            return None

    return decorator


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.marking = stix2.TLP_WHITE
        self.author = self.create_author(marking=self.marking)

    @staticmethod
    def create_author(marking) -> dict:
        """
        Create STIX 2.1 Identity object representing the author of STIX objects
        :return: Identity in STIX 2.1 format
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="Ransomware.Live", identity_class="organization"),
            name="Ransomware.Live",
            identity_class="organization",
            type="identity",
            object_marking_refs=[marking.get("id")],
            contact_information="https://www.ransomware.live/about#data",
            x_opencti_reliability="A - Completely reliable",
            allow_custom=True,
        )

        return author

    @handle_stix2_error
    def relationship_generator(
            self,
            source_ref: str,
            target_ref: str,
            relationship_type: str,
            attack_date: datetime = None,
            discovered: datetime = None,
    ) -> stix2.Relationship:
        """
        Generates a relationship object
        :param source_ref:
        :param target_ref:
        :param relationship_type:
        :param attack_date:
        :param discovered:
        :return:
        """
        relation = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type,
                source_ref,
                target_ref,
                attack_date,
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            start_time=attack_date,
            created=discovered,
            created_by_ref=self.author.get("id"),
        )
        return relation

    @handle_stix2_error
    def domain_generator(self, domain_name: str, description="-"):
        """
        Generates a STIX object for a domain
        :param domain_name:
        :param description:
        :return: DomainName object
        """
        domain = stix2.DomainName(
            value=domain_name,
            type="domain-name",
            object_marking_refs=[self.marking.get("id")],
            allow_custom=True,
            created_by_ref=self.author.get("id"),
            x_opencti_description=description,
        )
        return domain

    @handle_stix2_error
    def ipv4_generator(self, ip: str):
        """
        Create STIX 2.1 IPv4 Address object
        :param ip:
        :return: IPv4 Address in STIX 2.1 format
        """
        return stix2.IPv4Address(
            value=ip,
            type="ipv4-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

    @handle_stix2_error
    def ipv6_generator(self, ip: str):
        """
        Create STIX 2.1 IPv6 Address object
        :param ip:
        :return: IPv6 Address in STIX 2.1 format
        """
        return stix2.IPv6Address(
            value=ip,
            type="ipv6-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

