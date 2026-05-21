from typing import Optional

from connectors_sdk.models import (
    AutonomousSystem,
    City,
    Country,
    Indicator,
    IPV4Address,
    OrganizationAuthor,
    Reference,
    Region,
    Relationship,
    TLPMarking,
    Vulnerability,
)
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """
    Provides methods for converting various types of input data into
    STIX 2.1 objects with connectors_sdk models.
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """
        Initialize the converter with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
        """
        self.helper = helper
        self.author = self.create_author()
        self.tlp_clear = self.create_tlp_marking("clear")
        self.tlp_amber = self.create_tlp_marking("amber")

    def create_tlp_marking(self, level: str) -> TLPMarking:
        """
        Create TLPMarking object
        """
        tlp_marking = TLPMarking(level=level)
        return tlp_marking

    def create_author(self) -> OrganizationAuthor:
        """
        Create Author
        """
        author = OrganizationAuthor(
            name="Criminal IP", description="Criminal IP Cyber Threat Intelligence"
        )
        return author

    def create_autonomous_system(self, number: str, name: str) -> AutonomousSystem:
        """
        Create an AutonomousSystem object
        """
        return AutonomousSystem(
            number=number, name=name, author=self.author, markings=[self.tlp_clear]
        )

    def create_city(self, name: str, latitude: float, longitude: float) -> City:
        """Create a City object"""
        return City(
            name=name,
            latitude=latitude,
            longitude=longitude,
            markings=[self.tlp_clear],
        )

    def create_country(self, name: str) -> Country:
        """
        Create a Country object
        """
        return Country(name=name, author=self.author, markings=[self.tlp_clear])

    def create_indicator(
        self,
        name: str,
        pattern: str,
        pattern_type: str,
        description: str,
        labels: list[str],
    ) -> Indicator:
        """Creates an Indicator object"""
        return Indicator(
            name=name,
            pattern=pattern,
            pattern_type=pattern_type,
            description=description,
            labels=labels,
            author=self.author,
            markings=[self.tlp_amber],
        )

    def create_ipv4(self, ip: str) -> IPV4Address:
        """
        Create an IPv4 object
        """
        return IPV4Address(value=ip, author=self.author, markings=[self.tlp_amber])

    def create_reference(self, obs_id: str) -> Reference:
        """
        Create a simple Reference object
        """
        return Reference(id=obs_id)

    def create_region(self, name: str) -> Country:
        """
        Create a Region object
        """
        return Region(name=name, author=self.author, markings=[self.tlp_clear])

    def create_relationship(
        self,
        relationship_type: str,
        source_obj,
        target_obj,
        description: Optional[str] = None,
    ) -> Relationship:
        """
        Creates Relationship object
        """
        return Relationship(
            type=relationship_type,
            source=source_obj,
            target=target_obj,
            author=self.author,
            description=description,
            markings=[self.tlp_amber],
        )

    def create_vulnerability(self, name: str, description: str) -> Vulnerability:
        """Creates a Vulnerability object"""
        return Vulnerability(
            name=name,
            description=description,
            author=self.author,
            markings=[self.tlp_amber],
        )
