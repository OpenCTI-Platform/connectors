from ipaddress import IPv4Address
from pycti import OpenCTIConnectorHelper
from ..models import (
    Author,
    MarkingDefinition,
    Relationship,
    IPAddress,
    DomainName,
    Indicator
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self._author = self.make_author()
        self._tlp_amber_strict = self.make_marking_definition_tlp_amber_strict()

    def make_author(self) -> Author:
        """
        Create Author
        :return: Author in Stix2 object
        """
        return Author(
            name=self.helper.connector.name,
            identity_class="organization",
            description="As a cyber security specialist, Proofpoint provides solutions to protect against digital threats. Proofpoint ET Reputation refers to the digital reputation of IP addresses and domains based on their activity on the network. This reputation is used to determine whether an IP address or domain is associated with malicious behaviour, such as phishing, botnets or spamming, or with legitimate activity.",
            x_opencti_organization_type="vendor",
        )

    @staticmethod
    def make_marking_definition_tlp_amber_strict() -> MarkingDefinition:
        return MarkingDefinition(
            definition_type="statement",
            definition={"statement": "custom"},
            x_opencti_definition_type="TLP",
            x_opencti_definition="TLP:AMBER+STRICT",
        )

    def make_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> Relationship:
        """
        Make Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        return Relationship(
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            markings=[self._tlp_amber_strict],
            created_by_ref=self._author,
        )

    def make_observable(self, value: IPv4Address | str, score: int, categories: list[str], collection: str) -> IPAddress | DomainName | None:

        properties = dict(
            value=value,
            markings=[self._tlp_amber_strict],
            x_opencti_score=score,
            x_opencti_labels=categories,
            x_opencti_created_by_ref=self._author,
            x_opencti_main_observable_type=collection,
        )

        if collection == "IPv4-Addr":
            return IPAddress.model_validate(properties)
        elif collection == "Domain-Name":
            return DomainName.model_validate(properties)
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4-Addr or Domain-Name: ",
                {"collection": collection, "value": value},
            )
            return None

    def make_indicator(self, entity: IPv4Address | str, score: int, categories: list[str], collection: str) -> Indicator :
            return Indicator(
                created_by_ref=self._author,
                name=entity,
                pattern=f"[{collection.lower()}:value='{entity}']",
                pattern_type="Stix",
                labels=categories,
                markings=[self._tlp_amber_strict],
                x_opencti_score=score,
                x_opencti_main_observable_type=collection,
            )
