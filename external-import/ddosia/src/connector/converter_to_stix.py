import json
from typing import List, Dict, Any, Literal, Optional

from connectors_sdk.models import (
    DomainName,
    IPV4Address,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    Note,
)
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """
    Provides methods for converting DDoSIA target data into STIX 2.1 objects
    using the connectors-sdk models.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ):
        """
        Initialize the converter.

        Args:
            helper: OpenCTI connector helper for logging.
            tlp_level: The TLP level to apply to all created entities.
        """
        self.helper = helper
        self.tlp_level = tlp_level.lower()

        # Initialize author and marking once
        self.author = self.create_author()
        self.tlp_marking = self.create_tlp_marking(self.tlp_level)

    def create_author(self) -> OrganizationAuthor:
        """
        Create the author identity for the connector.

        Returns:
            OrganizationAuthor object.
        """
        return OrganizationAuthor(
            name="witha.name",
            # Identity class is implicitly organization in OrganizationAuthor
        )

    def create_tlp_marking(self, level: str) -> TLPMarking:
        """
        Create a TLP marking object.

        Args:
            level: TLP level string.

        Returns:
            TLPMarking object.
        """
        return TLPMarking(level=level)

    def create_domain(self, host: str) -> DomainName:
        """
        Create a STIX DomainName object.

        Args:
            host: The normalized domain name.

        Returns:
            DomainName object.
        """
        return DomainName(
            value=host,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def create_ipv4(self, ip: str) -> IPV4Address:
        """
        Create a STIX IPv4Address object.

        Args:
            ip: The validated IPv4 address.

        Returns:
            IPV4Address object.
        """
        return IPV4Address(
            value=ip,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def create_resolves_to_relationship(self, domain: DomainName, ip: IPV4Address) -> Relationship:
        """
        Create a 'resolves-to' relationship between a domain and an IP.

        Args:
            domain: The source DomainName object.
            ip: The target IPV4Address object.

        Returns:
            Relationship object.
        """
        return Relationship(
            type="resolves-to",
            source=domain.id,
            target=ip.id,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def create_note_for_host(
        self,
        domain: DomainName,
        cfg_id: str,
        cfg_ts: float,
        host: str,
        targets: List[Dict[str, Any]],
    ) -> Note:
        """
        Create a STIX Note containing the raw JSON targets for a specific domain.

        Args:
            domain: The target DomainName object.
            cfg_id: The ID of the configuration snapshot.
            cfg_ts: The timestamp of the snapshot.
            host: The normalized host name.
            targets: The list of raw target dictionaries.

        Returns:
            Note object.
        """
        note_content = {
            "cfg_id": cfg_id,
            "snapshot_ts": cfg_ts,
            "host": host,
            "targets": targets,
        }

        return Note(
            content=json.dumps(note_content, indent=2),
            object_refs=[domain.id],
            author=self.author,
            markings=[self.tlp_marking],
        )
