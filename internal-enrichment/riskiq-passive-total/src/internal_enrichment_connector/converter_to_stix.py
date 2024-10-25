import stix2
from pycti import Identity


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
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                name="RiskIQ PassiveTotal",
                identity_class="organization"
            ),
            name="RiskIQ PassiveTotal",
            identity_class="organization",
        )

        return author

    def create_ipv4_observable(self, data: dict) -> dict:
        """
        Create observable according to value given
        :param data: Dictionary of PassiveDNS properties
        :return: IPV4 observable object
        """
        stix_ip_v4_observable = stix2.IPv4Address(
            value=data["resolve"],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            }
        )
        return stix_ip_v4_observable

    def create_ipv6_observable(self, data: dict) -> dict:
        """
        Create observable according to value given
        :param data: Dictionary of PassiveDNS properties
        :return: IPV4 observable object
        """
        stix_ip_v6_observable = stix2.IPv6Address(
            value=data["resolve"],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            }
        )
        return stix_ip_v6_observable

    def create_domain_observable(self, data: dict) -> dict:
        """
        Create observable according to value given
        :param data: Dictionary of PassiveDNS properties
        :return: Domain observable object
        """
        stix_domain_observable = stix2.DomainName(
            value=data["resolve"],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            }
        )
        return stix_domain_observable

    def create_email_observable(self, data: dict) -> dict:
        """
        Create observable according to value given
        :param data: Dictionary of PassiveDNS properties
        :return: Email-address observable object
        """
        stix_email_observable = stix2.EmailAddress(
            value=data["resolve"],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            }
        )
        return stix_email_observable
