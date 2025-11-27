import ipaddress

import stix2
from pycti import Identity, OpenCTIConnectorHelper, StixCoreRelationship


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
    ):
        """
        Initialize the converter with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `tlp_level`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
        """
        self.helper = helper

        self.author = self.create_author()

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="ShadowTrackr", identity_class="organization"),
            name="ShadowTrackr",
            identity_class="organization",
            description="ShadowTrackr is a service that provides information about IP addresses.",
            external_references=[
                stix2.ExternalReference(
                    source_name="External Source",
                    url="https://shadowtrackr.com",
                    description="ShadowTrackr is a service that provides information about IP addresses.",
                )
            ],
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
        )
        return relationship

    # ===========================#
    # Other Examples
    # ===========================#

    @staticmethod
    def _is_ip(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv4 or IPv6
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ipaddress.AddressValueError:
            return False
