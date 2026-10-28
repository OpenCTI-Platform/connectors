"""Base internal enrichment connector module.

This module provides the ``InternalEnrichmentConnector`` class that serves as the foundation
for internal enrichment connectors. It is a controller: it creates and validates the
parts a connector needs, checks each message, then passes it to the right processor.

Architecture::

    InternalEnrichmentConnector
    ├── OpenCTIConnectorHelper   → pycti bridge (created in _init_dependencies, listens to the queue)
    ├── ConnectorLoggerAdapter   → Logging (stdlib logging, pycti's format)
    ├── _MessageManager            → Builds and sends the bundle of each message
    └── BaseEnrichmentProcessor[] → can_process(), process() for one or more entity types

Message handling::

    invalid message?              → re-raised (pycti puts the work in error)
    out of scope?                 → playbook: skip; manual/auto: error
    no processor supports it?     → skip
    TLP not allowed?              → skip
    objects = processor.process()
    no objects?                   → skip
    otherwise                     → send stix_objects + objects

    skip: playbook → send the original bundle back; manual/auto → nothing sent, work completed
    error: playbook → send the original bundle back; then re-raise (manual/auto: work in error)

The connector neither builds nor sends bundles: ``_MessageManager`` does, and sends
exactly one bundle per playbook message.
"""

from __future__ import annotations

from typing import Any

from connectors_sdk.connectors.internal_enrichment._message_manager import (
    MessageManager,
)
from connectors_sdk.connectors.internal_enrichment.base_enrichment_processor import (
    BaseEnrichmentProcessor,
)
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from connectors_sdk.connectors.internal_enrichment.exceptions import (
    EntityOutOfScopeError,
    UnsupportedEntityError,
)
from connectors_sdk.logger._class_logger import _ClassLoggerMixin
from connectors_sdk.models.enums import TLPLevel
from connectors_sdk.settings.base_settings import (
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError


class InternalEnrichmentConnector(_ClassLoggerMixin):
    """Base class for internal enrichment connectors.

    This class provides the common message-handling logic for internal enrichment connectors:

    - Scope check against ``connector.scope``, on the OpenCTI type of the entity
    - Processor selection: the only processor whose ``can_process()`` returns ``True``
    - TLP check against ``connector.max_tlp``, before any call to the external source
    - Bundle sending, delegated to the ``_MessageManager`` given to the processors
    - Playbook compatibility: exactly one bundle sent per playbook message, whatever happens
    - Error handling and logging

    ``is_entity_in_scope()`` and ``is_entity_tlp_allowed()`` are static helpers that do
    not log, so that connectors not built on this class can use them too.

    The ``OpenCTIConnectorHelper`` is created lazily in ``_init_dependencies()``
    (called by ``start()``), so the connector can be instantiated without
    connecting to OpenCTI. This makes it easier to test.

    A connector may have **multiple processors** to handle different entity types
    (e.g. one for IP addresses, one for domain names).

    Attributes:
        logger: A logger named after the module defining the connector class.
        settings: The connector configuration. ``settings.connector`` must be a
            ``BaseInternalEnrichmentConnectorConfig`` (or subclass).
        enrichment_processors: The list of ``BaseEnrichmentProcessor`` instances.

    Example:
        >>> class IPv4Processor(BaseEnrichmentProcessor):
        ...     handled_entity_types = frozenset({"IPv4-Addr"})
        ...     def collect(self, message):
        ...         return api_client.get_ip(message.stix_entity.value)
        ...     def transform(self, message, data):
        ...         return [author, tlp_marking, *to_stix(data)]
        ...
        >>> settings = MyConnectorSettings()
        >>> connector = InternalEnrichmentConnector(
        ...     settings=settings,
        ...     enrichment_processors=[IPv4Processor()],
        ... )
        >>> connector.start()
    """

    def __init__(
        self,
        settings: BaseConnectorSettings,
        enrichment_processors: list[BaseEnrichmentProcessor],
    ) -> None:
        """Initialize the base internal enrichment connector.

        The ``OpenCTIConnectorHelper`` is **not** created here. It will be
        created when ``start()`` is called (via ``_init_dependencies()``).

        Args:
            settings: The connector configuration settings.
            enrichment_processors: The ``BaseEnrichmentProcessor`` instances.

        Raises:
            TypeError: If ``settings.connector`` is not a ``BaseInternalEnrichmentConnectorConfig``.
            ValueError: If no processor is provided, or if an entity type of
                ``connector.scope`` is declared by no processor.
        """
        if not isinstance(settings.connector, BaseInternalEnrichmentConnectorConfig):
            raise TypeError(
                "settings.connector must be a BaseInternalEnrichmentConnectorConfig (or subclass)."
            )

        if not enrichment_processors:
            raise ValueError("At least one BaseEnrichmentProcessor must be provided.")

        self.settings = settings
        self._enabled_entity_types = settings.connector.scope
        self._max_entity_tlp = settings.connector.max_tlp

        self.enrichment_processors = enrichment_processors
        processor_entity_types = [
            entity_type
            for processor in enrichment_processors
            for entity_type in processor.handled_entity_types
        ]
        for entity_type in self._enabled_entity_types:
            if not self.is_entity_in_scope(entity_type, processor_entity_types):
                raise ValueError(
                    f"No processor declares the entity type {entity_type} "
                    "of connector.scope."
                )

    def _init_dependencies(self) -> None:
        """Create the OpenCTI connector helper and wire up all components.

        This method:
        1. Creates the ``OpenCTIConnectorHelper`` from the config, as playbook compatible
        2. Creates the ``_MessageManager`` shared by the connector and its processors
        3. Calls ``inject_dependencies()`` and ``post_init()`` on each processor
        """
        self._helper = OpenCTIConnectorHelper(
            config=self.settings.to_helper_config(),
            playbook_compatible=True,
        )
        self._message_manager = MessageManager(self._helper)

        for processor in self.enrichment_processors:
            processor.inject_dependencies(
                settings=self.settings, message_manager=self._message_manager
            )
            processor.post_init()

    def _select_processor(self, message: EnrichmentMessage) -> BaseEnrichmentProcessor:
        """Return the only processor that supports the message.

        Args:
            message: The enrichment message.

        Returns:
            The processor whose ``can_process()`` returns ``True``.

        Raises:
            UnsupportedEntityError: If no processor can process the message.
            ValueError: If several processors can process the message.
        """
        message_processors = [
            processor
            for processor in self.enrichment_processors
            if processor.can_process(message)
        ]
        if not message_processors:
            self.logger.warning(
                "No processor can process the entity, skipping",
                meta=message.to_log_metadata(),
            )
            raise UnsupportedEntityError("No processor can process this entity")
        if len(message_processors) > 1:
            processor_names = ", ".join(
                type(processor).__name__ for processor in message_processors
            )
            raise ValueError(
                f"Several processors can process the entity ({processor_names}): the "
                "can_process() method of exactly one processor must return True."
            )
        return message_processors[0]

    def _check_scope(self, message: EnrichmentMessage) -> None:
        """Check that the entity type is in the connector scope.

        Args:
            message: The enrichment message.

        Raises:
            EntityOutOfScopeError: If the entity type is out of the connector scope.
        """
        if not self.is_entity_in_scope(
            message.enrichment_entity.entity_type, self._enabled_entity_types
        ):
            self.logger.info(
                "Entity type is out of the connector scope",
                meta=message.to_log_metadata(),
            )
            raise EntityOutOfScopeError(
                f"Entity type {message.enrichment_entity.entity_type} is out of scope"
            )

    def _check_tlp(self, message: EnrichmentMessage) -> None:
        """Check that the entity TLP is allowed by the connector max TLP.

        Args:
            message: The enrichment message.

        Raises:
            UnsupportedEntityError: If the entity TLP is not allowed.
        """
        tlp_levels = message.enrichment_entity.tlp_levels
        if not self.is_entity_tlp_allowed(tlp_levels, self._max_entity_tlp):
            self.logger.warning(
                "Entity TLP is not allowed by the connector max TLP, skipping",
                meta={
                    **message.to_log_metadata(),
                    "tlp_levels": tlp_levels,
                    "max_entity_tlp": self._max_entity_tlp.value,
                },
            )
            raise UnsupportedEntityError(
                f"Entity TLP is not allowed (max TLP: {self._max_entity_tlp.value})"
            )

    def callback(self, data: dict[str, Any]) -> str:
        """Handle one enrichment message.

        Called by ``OpenCTIConnectorHelper.listen()`` for each message. In manual or
        automatic mode, the returned message closes the work created by the platform,
        and an exception puts it in error. In a playbook, there is no work: only the
        bundle sent matters.

        Args:
            data: The message data passed by ``OpenCTIConnectorHelper.listen()``.

        Returns:
            A message describing the outcome, stored on the work.

        Raises:
            ValidationError: If the message is invalid. pycti must always send a valid
                message: nothing is sent back, even in a playbook.
            EntityOutOfScopeError: If the entity type is out of the connector scope,
                outside a playbook (in a playbook, the entity is skipped).
            Exception: Any exception raised while processing the message, after it is
                logged and, in a playbook, after the original bundle is sent back.
        """
        try:
            message = EnrichmentMessage.model_validate(
                # pycti resets `helper.playbook` for each message
                {**data, "from_playbook": self._helper.playbook is not None}
            )
        except ValidationError:
            # pycti logs a generic message without the exception text: log it here.
            self.logger.exception(
                "Invalid enrichment message", meta={"entity_id": data.get("entity_id")}
            )
            raise

        with self._message_manager.handle(message):
            # Skip unsupported entity before they can reach the processor
            self._check_scope(message)
            self._check_tlp(message)

            # `self._select_processor` calls `processor.can_process()` which can be overwritten
            # during implementation and potentially send data to external services.
            # OCTI entities with a TLP level above connector's threshold must never
            # reach any processor to avoid sensitive data leakage.
            processor = self._select_processor(message)
            processor.process(message)

        # Success, no data or skip: the manager knows how the message ended
        return self._message_manager.outcome

    def start(self) -> None:
        """Start the connector and listen to enrichment messages.

        Calls ``_init_dependencies()`` to create the helper and wire up components,
        then uses ``OpenCTIConnectorHelper.listen`` to run ``callback`` for each message.
        """
        self.logger.info("Connector starting")

        self._init_dependencies()
        self._helper.listen(message_callback=self.callback)

    @staticmethod
    def is_entity_in_scope(entity_type: str, enabled_entity_types: list[str]) -> bool:
        """Tell whether the entity type is in the connector scope, case-insensitively.

        Args:
            entity_type: The OpenCTI type of the entity (e.g. ``IPv4-Addr``).
            enabled_entity_types: The entity types of the connector scope
                (``connector.scope``).

        Returns:
            ``True`` if the entity type is in the scope, ``False`` otherwise.
        """
        return entity_type.lower() in [
            enabled_entity_type.lower() for enabled_entity_type in enabled_entity_types
        ]

    @staticmethod
    def is_entity_tlp_allowed(
        tlp_levels: list[str], max_entity_tlp: TLPLevel | str
    ) -> bool:
        """Tell whether every TLP of the entity is at or below the connector max TLP.

        Uses pycti's ``check_max_tlp()``, which holds the platform's TLP order. Every
        TLP is first converted to the ``TLP:XXX`` form it expects, so that connectors
        never convert it. An entity without TLP is allowed. An entity with a custom TLP
        marking (e.g. ``TLP:EX:CHEMICAL``) is not: the connector cannot compare it.

        Args:
            tlp_levels: The TLP levels of the entity, in any form accepted by
                ``TLPLevel`` (e.g. ``TLP:AMBER+STRICT`` or ``amber+strict``).
                Empty if the entity has no TLP.
            max_entity_tlp: The highest TLP of the entities the connector may send to
                the external source (``connector.max_tlp``), as a ``TLPLevel`` or in
                any form accepted by ``TLPLevel`` (e.g. ``amber+strict``).

        Returns:
            ``True`` if the entity may be enriched, ``False`` otherwise.

        Raises:
            ValueError: If ``max_entity_tlp`` is not a valid ``TLPLevel``.
        """
        max_tlp = f"TLP:{TLPLevel(max_entity_tlp).value.upper()}"
        for tlp in tlp_levels:
            try:
                tlp = f"TLP:{TLPLevel(tlp).value.upper()}"
            except ValueError:
                pass  # A custom TLP marking: check_max_tlp() refuses it
            if not OpenCTIConnectorHelper.check_max_tlp(tlp, max_tlp):
                return False
        return True
