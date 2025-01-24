from ipaddress import IPv4Address

from connector.models import (
    Author,
    DomainName,
    Indicator,
    IPAddress,
    MarkingDefinition,
    Relationship,
)
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    This class contains utility methods to create STIX-compliant objects, such as author, observables,
    indicators, relationships, and markings, to facilitate the integration of Proofpoint ET Reputation data
    with OpenCTI.
    """

    def __init__(self, helper: OpenCTIConnectorHelper):
        """
        Initializes the `ConverterToStix` class.

        Args:
            helper (OpenCTIConnectorHelper): The OpenCTI connector helper instance.
        """
        self.helper = helper
        self._author = self.make_author()
        self._tlp_amber_strict = self.make_marking_definition_tlp_amber_strict()

    def make_author(self) -> Author:
        """
         Creates an Author object and its representation in STIX 2.1 format.
        The author represents Proofpoint as the source of the reputation data.

        Returns:
            Author: A Author object and its representation in STIX 2.1 format.
        """
        return Author(
            name=self.helper.connector.name,
            identity_class="organization",
            description="As a cyber security specialist, Proofpoint provides solutions to protect against digital threats. Proofpoint ET Reputation refers to the digital reputation of IP addresses and domains based on their activity on the network. This reputation is used to determine whether an IP address or domain is associated with malicious behaviour, such as phishing, botnets or spamming, or with legitimate activity.",
            x_opencti_organization_type="vendor",
        )

    @staticmethod
    def make_marking_definition_tlp_amber_strict() -> MarkingDefinition:
        """
        Creates a TLP:AMBER+STRICT marking definition object and its representation in STIX 2.1 format.
        This marking is used to classify the confidentiality level of the data.

        Returns:
            MarkingDefinition: A TLP:AMBER+STRICT marking definition object and its representation in STIX 2.1 format.
        """
        return MarkingDefinition(
            definition_type="statement",
            definition={"statement": "custom"},
            x_opencti_definition_type="TLP",
            x_opencti_definition="TLP:AMBER+STRICT",
        )

    def make_relationship(
        self,
        source_object: Indicator,
        relationship_type: str,
        target_object: IPAddress | DomainName,
    ) -> Relationship:
        """
        Creates a relationship object and its representation in STIX 2.1 format.

        Args:
            source_object (Indicator): The source object.
            relationship_type (str): The type of the relationship.
            target_object (IPAddress | DomainName): The target object.

        Returns:
            Relationship: A relationship object and its representation in STIX 2.1 format.
        """
        return Relationship(
            relationship_type=relationship_type,
            source=source_object,
            target=target_object,
            markings=[self._tlp_amber_strict],
            created_by=self._author,
        )

    def make_observable(
        self,
        value: IPv4Address | str,
        score: int,
        categories: list[str],
        collection: str,
    ) -> IPAddress | DomainName | None:
        """
        Creates an observable object and its representation in STIX 2.1 format.

        Args:
            value (IPv4Address | str): The value of the observable ("IPv4-Addr" or "Domain-Name").
            score (int): The reputation score of the observable.
            categories (list[str]): A list of categories linked to the observable.
            collection (str): The type of the observable ("IPv4-Addr" or "Domain-Name").

        Returns:
            IPAddress | DomainName | None: A observable object and its representation in STIX 2.1 format, or None
            if the type is invalid.
        """

        properties = dict(
            value=value,
            markings=[self._tlp_amber_strict],
            x_opencti_score=score,
            x_opencti_labels=categories,
            x_opencti_created_by=self._author,
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

    def make_indicator(
        self,
        entity: IPv4Address | str,
        score: int,
        categories: list[str],
        collection: str,
    ) -> Indicator:
        """
        Creates an indicator object and its representation in STIX 2.1 format.

        Args:
            entity (IPv4Address | str): The value of the entity (IPv4 address or domain name).
            score (int): The reputation score of the indicator.
            categories (list[str]): A list of categories linked to the indicator.
            collection (str): The type of the indicator ("IPv4-Addr" or "Domain-Name").

        Returns:
            Indicator: A indicator object and its representation in STIX 2.1 format.
        """
        return Indicator(
            created_by=self._author,
            name=entity,
            pattern=f"[{collection.lower()}:value='{entity}']",
            pattern_type="Stix",
            labels=categories,
            markings=[self._tlp_amber_strict],
            x_opencti_score=score,
            x_opencti_main_observable_type=collection,
        )
