"""Base internal enrichment connector module.

This module provides the ``InternalEnrichmentConnector`` class that serves as the foundation
for internal enrichment connectors. It handles the common message-handling logic:
scope check, TLP check, processor selection, bundle assembly and sending, playbook
compatibility and error handling.

Architecture::

    InternalEnrichmentConnector
    ├── OpenCTIConnectorHelper   → pycti bridge (created in _init_dependencies, listens to the queue)
    ├── ConnectorLogger          → Logging (wraps helper's AppLogger)
    └── BaseEnrichmentProcessor[] → supports(), collect(), transform() for one or more entity types

Message handling::

    out of scope?                 → skip
    no processor supports it?     → skip
    TLP above max_tlp?            → skip
    objects = transform(collect())
    no objects?                   → skip
    otherwise                     → send stix_objects + objects (enriched entity replaced by id)

    skip: playbook → send the original bundle back; manual/auto → nothing sent, work completed
    error: playbook → send the original bundle back; then re-raise (manual/auto: work in error)

In a playbook, exactly one bundle is sent per message: sending none stalls the playbook,
sending two runs the next step twice.
"""

from __future__ import annotations

from typing import Any

from connectors_sdk.connectors._stix_conversion import to_stix2_objects
from connectors_sdk.connectors.external_import.logger import ConnectorLogger
from connectors_sdk.connectors.internal_enrichment.base_enrichment_processor import (
    BaseEnrichmentProcessor,
)
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from connectors_sdk.settings.base_settings import (
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pycti import OpenCTIConnectorHelper


class InternalEnrichmentConnector:
    """Base class for internal enrichment connectors.

    This class provides the common message-handling logic for internal enrichment connectors:

    - Scope check against ``connector.scope``, on the OpenCTI type of the entity
    - Processor selection: the first processor whose ``supports()`` returns ``True``
    - TLP check against ``connector.max_tlp``, before any call to the external source
    - Bundle assembly: original ``stix_objects`` plus the processor's objects,
      the enriched entity being replaced when the processor returns an object with its id
    - Playbook compatibility: exactly one bundle sent per playbook message, whatever happens
    - Error handling and logging

    The ``OpenCTIConnectorHelper`` is created lazily in ``_init_dependencies()``
    (called by ``start()``), so the connector can be instantiated without
    connecting to OpenCTI. This makes it easier to test.

    A connector may have **multiple processors** to handle different entity types
    (e.g. one for IP addresses, one for domain names).

    Attributes:
        settings: The connector configuration. ``settings.connector`` must be a
            ``BaseInternalEnrichmentConnectorConfig`` (or subclass).
        logger: The ``ConnectorLogger`` for logging without direct pycti dependency.
        enrichment_processors: The list of ``BaseEnrichmentProcessor`` instances.

    Example:
        >>> class IPv4Processor(BaseEnrichmentProcessor):
        ...     entity_types = frozenset({"IPv4-Addr"})
        ...     def collect(self, message):
        ...         return api_client.get_ip(message.stix_entity["value"])
        ...     def transform(self, data, message):
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
            enrichment_processors: The ``BaseEnrichmentProcessor`` instances, by priority order.

        Raises:
            TypeError: If ``settings.connector`` is not a ``BaseInternalEnrichmentConnectorConfig``.
            ValueError: If no processor is provided, or if a processor has no ``entity_types``.
        """
        if not isinstance(settings.connector, BaseInternalEnrichmentConnectorConfig):
            raise TypeError(
                "settings.connector must be a BaseInternalEnrichmentConnectorConfig (or subclass)."
            )
        if not enrichment_processors:
            raise ValueError("At least one BaseEnrichmentProcessor must be provided.")
        for processor in enrichment_processors:
            if not getattr(processor, "entity_types", None):
                raise ValueError(
                    f"{type(processor).__name__}.entity_types must not be empty."
                )
        self.settings = settings
        self.enrichment_processors = enrichment_processors
        self._connector_config: BaseInternalEnrichmentConnectorConfig = (
            settings.connector
        )

    def _init_dependencies(self) -> None:
        """Create the OpenCTI connector helper and wire up all components.

        This method:
        1. Creates the ``OpenCTIConnectorHelper`` from the config, as playbook compatible
        2. Creates the ``ConnectorLogger``
        3. Calls ``inject_dependencies()`` and ``post_init()`` on each processor
        4. Warns about scope entries and processors that can never be used
        """
        self._helper = OpenCTIConnectorHelper(
            config=self.settings.to_helper_config(),
            playbook_compatible=True,
        )
        self.logger = ConnectorLogger(self._helper)
        for processor in self.enrichment_processors:
            processor.inject_dependencies(settings=self.settings, helper=self._helper)
            processor.post_init()
        self._check_processors_coverage()

    def _check_processors_coverage(self) -> None:
        """Warn about configuration and code that do not match.

        - A scope entry handled by no processor: such entities are always skipped.
        - An entity type already claimed by an earlier processor that does not override
          ``supports()``: the later processor never receives entities of this type.
        """
        handled_types = {
            entity_type.lower()
            for processor in self.enrichment_processors
            for entity_type in processor.entity_types
        }
        for scope_type in self._connector_config.scope:
            if scope_type.lower() not in handled_types:
                self.logger.warning(
                    "[CONNECTOR] Scope entity type is not handled by any processor",
                    {"entity_type": scope_type},
                )

        claimed_types: dict[str, str] = {}
        for processor in self.enrichment_processors:
            processor_name = type(processor).__name__
            for entity_type in sorted(processor.entity_types):
                claimed_by = claimed_types.get(entity_type.lower())
                if claimed_by is not None:
                    self.logger.warning(
                        "[CONNECTOR] Entity type already claimed by an earlier processor, "
                        "this processor will never receive it",
                        {
                            "entity_type": entity_type,
                            "processor": processor_name,
                            "claimed_by": claimed_by,
                        },
                    )
            if type(processor).supports is BaseEnrichmentProcessor.supports:
                for entity_type in processor.entity_types:
                    claimed_types.setdefault(entity_type.lower(), processor_name)

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
            Exception: Any exception raised while processing the message, after it is
                logged and, in a playbook, after the original bundle is sent back.
        """
        is_playbook = self._helper.playbook is not None
        try:
            message = EnrichmentMessage.from_data(data, is_playbook=is_playbook)
            bundle_objects, outcome = self._enrich(message)
            # Serialize here so that an object that cannot be serialized goes
            # through the error path, which sends the original bundle back.
            bundle = (
                None
                if bundle_objects is None
                else self._helper.stix2_create_bundle(bundle_objects)
            )
        except Exception as err:
            # pycti logs a generic message without the exception text: log it here.
            self.logger.error(
                "[CONNECTOR] Enrichment failed",
                {
                    "entity_id": data.get("entity_id"),
                    "is_playbook": is_playbook,
                    "error": str(err),
                },
            )
            if is_playbook:
                self._send_original_bundle(data)
            raise

        if bundle is not None:
            try:
                self._send(bundle)
            except Exception as err:
                self.logger.error(
                    "[CONNECTOR] Failed to send the enrichment bundle",
                    {
                        "entity_id": message.entity_id,
                        "is_playbook": is_playbook,
                        "error": str(err),
                    },
                )
                raise
        return outcome

    def _enrich(self, message: EnrichmentMessage) -> tuple[list[Any] | None, str]:
        """Run the checks and the processor for one message.

        Args:
            message: The enrichment message.

        Returns:
            The objects to send (``None`` when nothing must be sent) and the outcome message.
        """
        log_context: dict[str, Any] = {
            "entity_id": message.entity_id,
            "entity_type": message.entity_type,
            "is_playbook": message.is_playbook,
        }

        if not self._is_in_scope(message):
            self.logger.info(
                "[CONNECTOR] Entity is out of the connector scope, skipping",
                log_context,
            )
            return self._skip(
                message, f"Entity type {message.entity_type} is out of scope"
            )

        processor = self._select_processor(message)
        if processor is None:
            self.logger.warning(
                "[CONNECTOR] No processor supports the entity, skipping",
                log_context,
            )
            return self._skip(message, "No processor supports this entity")

        max_tlp = self._connector_config.max_tlp
        if not all(
            self._helper.check_max_tlp(tlp, max_tlp) for tlp in message.tlp_levels
        ):
            self.logger.warning(
                "[CONNECTOR] Entity TLP is above the connector max TLP, skipping",
                {**log_context, "tlp_levels": message.tlp_levels, "max_tlp": max_tlp},
            )
            return self._skip(message, f"Entity TLP is above max TLP ({max_tlp})")

        log_context["processor"] = type(processor).__name__
        new_objects = processor.transform(processor.collect(message), message)
        if not new_objects:
            self.logger.info("[CONNECTOR] No enrichment data found", log_context)
            return self._skip(message, "No enrichment data found")

        self.logger.info(
            "[CONNECTOR] Entity enriched",
            {**log_context, "objects_count": len(new_objects)},
        )
        return (
            self._build_bundle_objects(message, new_objects),
            f"Entity enriched with {len(new_objects)} objects",
        )

    def _is_in_scope(self, message: EnrichmentMessage) -> bool:
        """Check the entity type against the connector scope, case-insensitively."""
        entity_type = message.entity_type.lower()
        return any(
            entity_type == scope_type.lower()
            for scope_type in self._connector_config.scope
        )

    def _select_processor(
        self, message: EnrichmentMessage
    ) -> BaseEnrichmentProcessor | None:
        """Return the first processor that supports the message, if any."""
        return next(
            (
                processor
                for processor in self.enrichment_processors
                if processor.supports(message)
            ),
            None,
        )

    @staticmethod
    def _skip(message: EnrichmentMessage, reason: str) -> tuple[list[Any] | None, str]:
        """Skip the message: send the original bundle back in a playbook, nothing otherwise."""
        return (message.stix_objects if message.is_playbook else None), reason

    @staticmethod
    def _build_bundle_objects(
        message: EnrichmentMessage, new_objects: list[Any]
    ) -> list[Any]:
        """Merge the processor's objects into the original bundle objects.

        An object sharing its id with an original object (typically the modified
        enriched entity) replaces it; the other objects are appended.
        """
        new_objects_by_id = {obj["id"]: obj for obj in to_stix2_objects(new_objects)}
        bundle_objects = [
            new_objects_by_id.pop(obj["id"], obj) for obj in message.stix_objects
        ]
        bundle_objects.extend(new_objects_by_id.values())
        return bundle_objects

    def _send_original_bundle(self, data: dict[str, Any]) -> None:
        """Send the original bundle back to the playbook after an error.

        A failure is logged instead of raised, so that the caller re-raises the
        original error, while the text of this one still reaches the logs.
        """
        try:
            self._send(self._helper.stix2_create_bundle(data.get("stix_objects") or []))
        except Exception as err:
            self.logger.error(
                "[CONNECTOR] Failed to send the original bundle back",
                {"entity_id": data.get("entity_id"), "error": str(err)},
            )

    def _send(self, bundle: str) -> None:
        """Send a STIX bundle (to the workers, or to the next playbook step)."""
        self._helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)

    def start(self) -> None:
        """Start the connector and listen to enrichment messages.

        Calls ``_init_dependencies()`` to create the helper and wire up components,
        then uses ``OpenCTIConnectorHelper.listen`` to run ``callback`` for each message.
        """
        self._init_dependencies()
        self._helper.listen(message_callback=self.callback)
