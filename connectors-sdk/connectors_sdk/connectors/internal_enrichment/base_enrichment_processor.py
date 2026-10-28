"""Enrichment processor module.

This module provides the abstract ``BaseEnrichmentProcessor`` base class that defines
the contract for enriching one or more entity types from an external source.

Pipeline (run by ``InternalEnrichmentConnector`` for each message)::

    processor.process(message)  # send(message, transform(message, collect(message)))

A connector's processor only fetches and converts: the connector checks the scope and
the TLP, and the injected ``_MessageManager`` builds and sends the bundle.
"""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar, Iterable

from connectors_sdk.connectors.internal_enrichment.exceptions import (
    UnsupportedEntityError,
)
from connectors_sdk.logger._class_logger import _ClassLoggerMixin

if TYPE_CHECKING:
    from connectors_sdk.connectors.internal_enrichment._message_manager import (
        MessageManager,
    )
    from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
        EnrichmentMessage,
    )
    from connectors_sdk.settings.base_settings import BaseConnectorSettings


class BaseEnrichmentProcessor(_ClassLoggerMixin, ABC):
    """Abstract base class defining the enrichment contract.

    Each ``BaseEnrichmentProcessor`` is responsible for:

    - Declaring the entity types it handles (``handled_entity_types``)
    - Fetching raw data about the entity from the external source (``collect()``)
    - Converting it to STIX objects (``transform()``)

    Its ``collect()`` and ``transform()`` must **not** send bundles, check the scope or
    the TLP, or handle playbooks: ``InternalEnrichmentConnector`` checks the entity, and
    ``process()`` gives the objects to the injected ``message_manager``.

    A processor is created once and handles many messages: keep everything that is
    specific to a message in local variables, never in instance attributes.

    Subclasses can override ``__init__`` to accept custom arguments.

    Lifecycle:
        1. ``__init__()`` — called by connector code (custom args allowed)
        2. ``inject_dependencies()`` — called by the base connector (injects the settings
           and the bundle sender)
        3. ``post_init()`` — called by the base connector after ``inject_dependencies()``
           (override to build the API client, the author and the markings)
        4. ``can_process()`` and ``process()`` (``collect()`` then ``transform()``) — called by
           the base connector for each message

    Attributes:
        logger: A logger named after the module defining the processor class.
        handled_entity_types: The OpenCTI entity types handled by this processor
            (e.g. ``frozenset({"IPv4-Addr", "IPv6-Addr"})``), compared case-insensitively
            with the type of the entity to enrich. Required and not empty: otherwise
            defining the processor class raises ``TypeError``.
        settings: The connector settings, injected via ``inject_dependencies()``.
        message_manager: The sender of the bundles, shared with the connector and
            injected via ``inject_dependencies()``.

    Example:
        >>> class IPv4Processor(BaseEnrichmentProcessor):
        ...     handled_entity_types = frozenset({"IPv4-Addr"})
        ...
        ...     def post_init(self):
        ...         self.client = MyClient(api_key=self.settings.my_source.api_key)
        ...         self.author = OrganizationAuthor(name="My Source")
        ...         self.tlp_marking = TLPMarking(level="clear")
        ...
        ...     def collect(self, message):
        ...         return self.client.get_ip(message.stix_entity.value)
        ...
        ...     def transform(self, message, data):
        ...         if not data:
        ...             return []
        ...         ip = IPV4Address(value=message.stix_entity.value, score=data["score"])
        ...         return [self.author, self.tlp_marking, ip]
    """

    handled_entity_types: ClassVar[frozenset[str]]
    settings: BaseConnectorSettings
    message_manager: MessageManager

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Check that a processor declares the entity types it supports.

        Abstract subclasses (e.g. a base processor shared by a connector) are not
        checked: only the processors that can be created are.

        Raises:
            TypeError: If ``cls`` can be created but ``handled_entity_types`` is
                missing or empty.
        """
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return
        if not getattr(cls, "handled_entity_types", None):
            raise TypeError(
                f"`{cls.__qualname__}` must declare the entity types it supports, "
                'e.g. `handled_entity_types = frozenset({"IPv4-Addr"})`.'
            )

    def inject_dependencies(
        self, settings: BaseConnectorSettings, message_manager: MessageManager
    ) -> None:
        """Inject dependencies from the base connector.

        Called by ``InternalEnrichmentConnector`` after helper initialization.

        Args:
            settings: The connector configuration settings.
            message_manager: The sender of the bundles, shared with the connector.
        """
        self.settings = settings
        self.message_manager = message_manager

        self.logger.debug("Dependencies injected into enrichment processor")

    def post_init(self) -> None:  # noqa: B027
        """Hook called after ``inject_dependencies()`` wires up dependencies.

        Override this method to perform initialization that requires
        the injected dependencies (e.g. build the API client, the author and the markings once).
        Called by ``InternalEnrichmentConnector._init_dependencies()``.

        By default, does nothing.
        """

    def can_process(self, message: EnrichmentMessage) -> bool:
        """Tell whether this processor can process the entity in the message.

        By default, checks that the entity type is in ``handled_entity_types`` (case-insensitive).
        Override it to filter further within a type, e.g. on an indicator's ``pattern_type``,
        and call ``super().can_process(message)`` to keep the type check.

        Several processors may declare the same entity type, but for a given entity
        exactly one of them must return ``True``: the connector raises ``ValueError``
        otherwise. The order of the processors does not matter.

        Args:
            message: The enrichment message.

        Returns:
            ``True`` if this processor handles the entity, ``False`` otherwise.
        """
        entity_type = message.enrichment_entity.entity_type.lower()
        return any(
            entity_type == supported_entity_type.lower()
            for supported_entity_type in self.handled_entity_types
        )

    def process(self, message: EnrichmentMessage) -> None:
        """Run the processing pipeline for one message: collect → transform → send.

        Args:
            message: The enrichment message.

        Raises:
            UnsupportedEntityError: If this processor does not support the entity.
        """
        if not self.can_process(message):
            raise UnsupportedEntityError(
                f"{type(self).__name__} does not support this entity"
            )

        self.send(message, self.transform(message, self.collect(message)))

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
    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        """Transform raw data into STIX objects to add to the bundle.

        This method should convert the raw data from ``collect()`` into
        STIX 2.1 objects (connectors-sdk model instances, stix2 objects or STIX dicts).
        No network call should happen here.

        Return the author and the marking objects with the new objects, otherwise
        references to them break. To enrich the entity itself (score, labels,
        external references...), return a new version of it (e.g. an SDK model built
        from the same values). With the same id, it replaces the entity in the bundle,
        and OpenCTI merges it with the entity it holds. Adding a hash to a file can
        change its id (the id uses the first hash in a fixed order: MD5, SHA-1,
        SHA-256...): OpenCTI then deduplicates the two by their hashes. A ``Reference`` to the entity can be used as the source
        or target of a relationship; a ``Reference`` returned in the list is ignored.
        Do not return ``message.stix_objects``: the connector adds them.

        Skip and log (WARNING) a single item that fails to convert instead of raising.
        Raise ``UseCaseError`` (``raise ... from err``) only when nothing can be converted.

        Args:
            message: The enrichment message.
            data: The raw data returned by ``collect()``.

        Returns:
            The STIX objects to add to the bundle, or ``[]`` when there is nothing to add.
        """
        ...

    def send(self, message: EnrichmentMessage, bundle_objects: Iterable[Any]) -> None:
        """Send the original objects of the message with the processor's objects.

        Nothing is sent when ``bundle_objects`` is empty: the outcome stays
        "No enrichment data found".

        Args:
            message: The enrichment message.
            bundle_objects: The objects returned by the processor's ``transform()``.

        Raises:
            RuntimeError: If a bundle was already sent for this message.
        """
        log_metadata = message.to_log_metadata()

        bundle_objects = list(bundle_objects)

        if not bundle_objects:
            self.logger.info("No enrichment data found", meta=log_metadata)
            return

        self.message_manager.send(bundle_objects)

        self.logger.info(
            "Entity enriched",
            meta={**log_metadata, "objects_count": len(bundle_objects)},
        )
