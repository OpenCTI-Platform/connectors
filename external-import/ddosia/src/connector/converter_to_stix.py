import json
from typing import Any, Dict, List, Literal

from connectors_sdk.models import (
    DomainName,
    ExternalReference,
    IPV4Address,
    Note,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
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

    def create_domain(self, host: str, cfg_id: str | None = None) -> DomainName:
        """
        Create a STIX DomainName object with optional external reference.

        Args:
            host: The normalized domain name.
            cfg_id: Optional configuration/snapshot ID for external reference.

        Returns:
            DomainName object.
        """
        external_references = None
        if cfg_id:
            snapshot_url = f"https://witha.name/config/{cfg_id}"
            external_ref = ExternalReference(
                source_name="witha.name",
                description="DDoSIA snapshot containing this target",
                url=snapshot_url,
                external_id=cfg_id,
            )
            external_references = [external_ref]

        return DomainName(
            value=host,
            author=self.author,
            markings=[self.tlp_marking],
            external_references=external_references,
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

    def create_resolves_to_relationship(
        self, domain: DomainName, ip: IPV4Address
    ) -> Relationship:
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
            source=domain,
            target=ip,
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
        Create a STIX Note with formatted attack summary and raw JSON.

        Args:
            domain: The target DomainName object.
            cfg_id: The ID of the configuration snapshot.
            cfg_ts: The timestamp of the snapshot.
            host: The normalized host name.
            targets: The list of raw target dictionaries.

        Returns:
            Note object with readable summary + raw JSON data.
        """
        # Count attacks by type
        attack_types = {}
        for target in targets:
            att_type = target.get("type", "unknown")
            attack_types[att_type] = attack_types.get(att_type, 0) + 1

        # Format content with summary + raw JSON
        summary_lines = [
            f"# DDoSIA Targets for {host}",
            "",
            f"**Snapshot ID:** {cfg_id}",
            f"**Timestamp:** {cfg_ts}",
            f"**Total targets:** {len(targets)}",
            "",
            "## Attack Summary",
            "",
        ]

        for att_type, count in sorted(attack_types.items()):
            summary_lines.append(f"- **{att_type}**: {count} targets")

        summary_lines.append("")
        summary_lines.append("## Raw Data (JSON)")
        summary_lines.append("```json")
        summary_lines.append(
            json.dumps(
                {
                    "cfg_id": cfg_id,
                    "snapshot_ts": cfg_ts,
                    "host": host,
                    "targets": targets,
                },
                indent=2,
            )
        )
        summary_lines.append("```")

        return Note(
            content="\n".join(summary_lines),
            objects=[domain],
            author=self.author,
            markings=[self.tlp_marking],
        )
