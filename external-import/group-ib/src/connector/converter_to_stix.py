"""STIX 2.1 conversion boundary.

Per-collection conversion lives in ``adapters/``; routing lives in
``pipeline/collection_dispatch.py``.
"""

from __future__ import annotations

from typing import Any

from pycti import OpenCTIConnectorHelper

from connector.settings import ConfigConnector
from pipeline import collect_intelligence


class ConverterToStix:
    """Convert Group-IB TI events into STIX 2.1 objects."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConfigConnector,
    ) -> None:
        self.helper = helper
        self.config = config

    def convert_event(
        self,
        collection: str,
        event: dict[str, Any],
        mitre_mapper: dict[str, str],
        ttl: int | None = None,
        flag_intrusion_set_instead_of_threat_actor: bool = False,
    ) -> list[Any]:
        """Convert a single event of ``collection`` into STIX objects.

        :param collection: Group-IB collection slug, e.g. ``apt/threat``.
        :param event: one parsed event as returned by the ciaops portion parser.
        :param mitre_mapper: MITRE technique -> attack-pattern name mapping.
        :param ttl: Indicator validity in days; ``None`` falls back to the
            event's own TTL and then to the connector default.
        :param flag_intrusion_set_instead_of_threat_actor: emit Intrusion-Set
            SDOs in place of Threat-Actor.
        :return: STIX objects for the event, empty when it yields nothing.
        """
        return collect_intelligence(
            helper=self.helper,
            collection=collection,
            ttl=ttl,
            event=event,
            mitre_mapper=mitre_mapper,
            config=self.config,
            flag_intrusion_set_instead_of_threat_actor=(
                flag_intrusion_set_instead_of_threat_actor
            ),
        )
