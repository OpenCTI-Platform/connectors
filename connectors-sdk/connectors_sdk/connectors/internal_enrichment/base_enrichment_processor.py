"""Enrichment processor module.

This module provides the abstract ``BaseEnrichmentProcessor`` base class that defines
the contract for enriching one or more entity types from an external source.

Pipeline (run by ``InternalEnrichmentConnector`` for each message)::

    if processor.supports(message):
        objects = processor.transform(processor.collect(message), message)

A processor only fetches and converts: the connector checks the scope and the TLP,
builds the bundle, sends it and handles playbooks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

from connectors_sdk.connectors.external_import.logger import ConnectorLogger

if TYPE_CHECKING:
    from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
        EnrichmentMessage,
    )
    from connectors_sdk.settings.base_settings import BaseConnectorSettings
    from pycti import OpenCTIConnectorHelper


class BaseEnrichmentProcessor(ABC):
    """Abstract base class defining the enrichment contract.

    Each ``BaseEnrichmentProcessor`` is responsible for:

    - Declaring the entity types it handles (``entity_types``)
    - Fetching raw data about the entity from the external source (``collect()``)
    - Converting it to STIX objects (``transform()``)

    It must **not** send bundles, check the scope or the TLP, or handle playbooks:
    ``InternalEnrichmentConnector`` does it for every processor.

    A processor is created once and handles many messages: keep everything that is
    specific to a message in local variables, never in instance attributes.

    Subclasses can override ``__init__`` to accept custom arguments.

    Lifecycle:
        1. ``__init__()`` — called by connector code (custom args allowed)
        2. ``inject_dependencies()`` — called by the base connector (injects settings and logger)
        3. ``post_init()`` — called by the base connector after ``inject_dependencies()``
           (override to build the API client, the author and the markings)
        4. ``supports()``, ``collect()``, ``transform()`` — called by the base connector for each message

    Attributes:
        entity_types: The OpenCTI entity types handled by this processor
            (e.g. ``frozenset({"IPv4-Addr", "IPv6-Addr"})``), compared case-insensitively
            with the type of the entity to enrich. Must not be empty.
        settings: The connector settings, injected via ``inject_dependencies()``.
        logger: The ``ConnectorLogger`` instance, injected via ``inject_dependencies()``.

    Example:
        >>> class IPv4Processor(BaseEnrichmentProcessor):
        ...     entity_types = frozenset({"IPv4-Addr"})
        ...
        ...     def post_init(self):
        ...         self.client = MyClient(api_key=self.settings.my_source.api_key)
        ...         self.author = OrganizationAuthor(name="My Source")
        ...         self.tlp_marking = TLPMarking(level="clear")
        ...
        ...     def collect(self, message):
        ...         return self.client.get_ip(message.stix_entity["value"])
        ...
        ...     def transform(self, data, message):
        ...         if not data:
        ...             return []
        ...         entity = message.entity_copy()
        ...         entity["x_opencti_score"] = data["score"]
        ...         return [self.author, self.tlp_marking, entity]
    """

    entity_types: ClassVar[frozenset[str]]
    settings: BaseConnectorSettings
    logger: ConnectorLogger

    def inject_dependencies(
        self,
        settings: BaseConnectorSettings,
        helper: OpenCTIConnectorHelper,
    ) -> None:
        """Inject dependencies from the base connector.

        Called by ``InternalEnrichmentConnector`` after helper initialization.

        Args:
            settings: The connector configuration settings.
            helper: The ``OpenCTIConnectorHelper`` instance, used to create the logger.
        """
        self.settings = settings
        self.logger = ConnectorLogger(helper)

    def post_init(self) -> None:  # noqa: B027
        """Hook called after ``inject_dependencies()`` wires up dependencies.

        Override this method to perform initialization that requires
        the injected dependencies (e.g. build the API client, the author and the markings once).
        Called by ``InternalEnrichmentConnector._init_dependencies()``.

        By default, does nothing.
        """

    def supports(self, message: EnrichmentMessage) -> bool:
        """Tell whether this processor handles the entity of the message.

        By default, checks that the entity type is in ``entity_types`` (case-insensitive).
        Override it to filter further within a type, e.g. on an indicator's ``pattern_type``,
        and call ``super().supports(message)`` to keep the type check.

        The connector uses the first processor that supports the message,
        so put specific processors before generic ones.

        Args:
            message: The enrichment message.

        Returns:
            ``True`` if this processor handles the entity, ``False`` otherwise.
        """
        entity_type = message.entity_type.lower()
        return any(entity_type == handled.lower() for handled in self.entity_types)

    @abstractmethod
    def collect(self, message: EnrichmentMessage) -> Any:
        """Collect raw intelligence about the entity from the external source.

        This method should call the external source and return the raw response.
        No STIX conversion should happen here.

        When the source does not know the entity (e.g. HTTP 404), return an empty value
        (``None``, ``{}``...) so that ``transform()`` returns ``[]``: this is not an error.
        For a real failure, raise ``DataRetrievalError`` (``raise ... from err``).

        Args:
            message: The enrichment message.

        Returns:
            Raw data from the external source.
        """
        ...

    @abstractmethod
    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        """Transform raw data into STIX objects to add to the bundle.

        This method should convert the raw data from ``collect()`` into
        STIX 2.1 objects (connectors-sdk model instances, stix2 objects or STIX dicts).
        No network call should happen here.

        Return the author and the marking objects with the new objects, otherwise
        references to them break. To update the enriched entity itself, return a
        modified ``message.entity_copy()`` (or any object with the same id): it replaces
        the original entity in the bundle. Do not return ``message.stix_objects``:
        the connector adds them.

        Skip and log (WARNING) a single item that fails to convert instead of raising.
        Raise ``UseCaseError`` (``raise ... from err``) only when nothing can be converted.

        Args:
            data: The raw data returned by ``collect()``.
            message: The enrichment message.

        Returns:
            The STIX objects to add to the bundle, or ``[]`` when there is nothing to add.
        """
        ...
