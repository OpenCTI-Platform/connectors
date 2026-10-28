"""Enrichment message module.

This module provides ``EnrichmentMessage``, a read-only view of the message that
``OpenCTIConnectorHelper.listen()`` passes to an internal enrichment connector's
callback, with the two views of the entity to enrich: ``OpenCTIEntity`` (as read from
OpenCTI) and ``StixEntity`` (as a STIX object).

Their models only declare the fields the connector needs; any other field can still be
read as an attribute (e.g. ``message.stix_entity.value``).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class OpenCTIEntity(BaseModel):
    """The entity to enrich, as read from OpenCTI.

    Only the id and the type are declared for now. The other fields sent by OpenCTI
    (``objectMarking``, ``parent_types``, ``importFiles``, ...) can be read as
    attributes.

    Attributes:
        id: The OpenCTI id of the entity.
        entity_type: The OpenCTI type of the entity (e.g. ``IPv4-Addr``, ``StixFile``).
            The connector scope uses these type names.
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    id: str
    entity_type: str

    @property
    def tlp_levels(self) -> list[str]:
        """The TLP levels of the entity (e.g. ``["TLP:AMBER"]``), empty if none."""
        markings = getattr(self, "objectMarking", None) or []
        return [
            marking["definition"]
            for marking in markings
            if marking.get("definition_type") == "TLP"
        ]


class StixEntity(BaseModel):
    """The entity to enrich, as a STIX 2.1 object.

    Only the fields the connector needs are declared. The other STIX properties
    (``value``, ``hashes``, ``extensions``, ...) can be read as attributes.

    Attributes:
        id: The STIX id of the entity, as used in the bundle.
        type: The STIX type of the entity (e.g. ``ipv4-addr``, ``file``).
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    id: str
    type: str


class EnrichmentMessage(BaseModel):
    """Read-only view of an enrichment message received from OpenCTI.

    Built by ``InternalEnrichmentConnector`` for each message, with
    ``EnrichmentMessage.model_validate(data)``, and passed to the processor's
    ``can_process()``, ``collect()`` and ``transform()`` methods.

    Attributes:
        enrichment_entity: The entity to enrich, as read from OpenCTI.
        stix_entity: The entity to enrich, as a STIX 2.1 object.
        stix_objects: The STIX 2.1 dicts of the bundle containing the entity.
            In a playbook, this is the bundle of the previous step.
        from_playbook: Whether the message comes from a playbook step.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    enrichment_entity: OpenCTIEntity
    stix_entity: StixEntity
    stix_objects: list[dict[str, Any]]
    from_playbook: bool

    def to_log_metadata(self) -> dict[str, Any]:
        """Return the context to log with every message about this enrichment.

        Returns:
            The ``meta`` dict to pass to the logger.
        """
        return {
            "octi_id": self.enrichment_entity.id,
            "octi_entity_type": self.enrichment_entity.entity_type,
            "from_playbook": self.from_playbook,
        }
