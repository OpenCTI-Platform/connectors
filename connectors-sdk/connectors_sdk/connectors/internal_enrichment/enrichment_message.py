"""Enrichment message module.

This module provides the ``EnrichmentMessage`` class, a read-only view of the
message that ``OpenCTIConnectorHelper.listen()`` passes to an internal enrichment
connector's callback.

The message has the same shape in every mode, but some fields are only reliable in one:

- Manual or automatic enrichment: the platform created a work, and ``data["event_type"]``
  and ``data["entity_type"]`` are set. ``stix_entity`` is usually a separate dict, not the
  object inside ``stix_objects`` (it is that object only when pycti builds ``stix_objects``
  itself, because the platform did not send them).
- Playbook: there is no work, ``data["event_type"]`` and ``data["entity_type"]`` are missing,
  ``stix_objects`` is the bundle of the previous playbook step, and ``stix_entity`` is the
  object inside it.

Never modify ``stix_entity`` in place: depending on the mode, the change may or may not
reach the bundle. Modify ``entity_copy()`` and return it from ``transform()`` instead.

``EnrichmentMessage`` only exposes fields that are reliable in both modes
(e.g. ``entity_type`` comes from ``enrichment_entity``).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EnrichmentMessage:
    """Read-only view of an enrichment message received from OpenCTI.

    Built by ``InternalEnrichmentConnector`` for each message and passed to
    the processor's ``supports()``, ``collect()`` and ``transform()`` methods.

    Attributes:
        entity_id: The STIX standard id of the entity to enrich.
        enrichment_entity: The entity as read from OpenCTI (``entity_type``,
            ``objectMarking``, ``parent_types``, ``importFiles``, ...).
        stix_entity: The entity to enrich, as a STIX 2.1 dict.
        stix_objects: The STIX 2.1 dicts of the bundle containing the entity.
            In a playbook, this is the bundle of the previous step.
        is_playbook: Whether the message comes from a playbook step.
    """

    entity_id: str
    enrichment_entity: dict[str, Any]
    stix_entity: dict[str, Any]
    stix_objects: list[dict[str, Any]]
    is_playbook: bool

    @classmethod
    def from_data(cls, data: dict[str, Any], is_playbook: bool) -> EnrichmentMessage:
        """Build an ``EnrichmentMessage`` from the data passed by ``OpenCTIConnectorHelper.listen()``.

        Args:
            data: The message data passed to the connector's callback.
            is_playbook: Whether the message comes from a playbook step.

        Returns:
            The corresponding ``EnrichmentMessage``.
        """
        return cls(
            entity_id=data["entity_id"],
            enrichment_entity=data["enrichment_entity"],
            stix_entity=data["stix_entity"],
            stix_objects=data["stix_objects"],
            is_playbook=is_playbook,
        )

    @property
    def entity_type(self) -> str:
        """The OpenCTI type of the entity to enrich (e.g. ``IPv4-Addr``, ``StixFile``).

        This is the value to compare with the connector's scope: unlike
        ``data["entity_type"]`` it is also set in playbooks, and unlike the
        ``entity_id`` prefix it matches the OpenCTI type names (``StixFile``
        and not ``file``).
        """
        entity_type: str = self.enrichment_entity["entity_type"]
        return entity_type

    @property
    def tlp_levels(self) -> list[str]:
        """The TLP levels of the entity to enrich (e.g. ``["TLP:AMBER"]``), empty if none."""
        markings = self.enrichment_entity.get("objectMarking") or []
        return [
            marking["definition"]
            for marking in markings
            if marking.get("definition_type") == "TLP"
        ]

    def entity_copy(self) -> dict[str, Any]:
        """Return a deep copy of ``stix_entity``, safe to modify.

        To update the enriched entity (score, labels, external references...),
        modify this copy and return it from ``transform()``: the connector replaces
        the original entity in the bundle with it, as both share the same id.

        Returns:
            A deep copy of ``stix_entity``.
        """
        return copy.deepcopy(self.stix_entity)
