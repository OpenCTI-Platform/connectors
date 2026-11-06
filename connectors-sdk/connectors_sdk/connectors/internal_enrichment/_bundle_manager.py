"""Bundle manager module.

This module provides ``BundleManager``, the only place that builds and sends the bundle
of an enrichment message, when the handling of the message ends:

- the original objects of the message with the processor's objects;
- in a playbook, the original bundle back when there is nothing else to send (skip,
  no data, failure, invalid message).

In a playbook, exactly one bundle must be sent per message: sending none stalls the
playbook, sending two runs the next step twice.

The manager does not merge the properties of an entity: OpenCTI does it, with the
worker upsert in manual/auto mode, and with the playbook executor in a playbook.
"""

from __future__ import annotations

from contextlib import AbstractContextManager, contextmanager
from copy import deepcopy
from types import TracebackType
from typing import Any, Generator

from connectors_sdk.connectors._stix_conversion import to_stix_dict
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from connectors_sdk.connectors.internal_enrichment.exceptions import (
    InvalidEnrichmentMessageError,
    UnsupportedEntityError,
)
from connectors_sdk.logger._class_logger import _ClassLoggerMixin
from connectors_sdk.models.reference import Reference
from pycti import OpenCTIConnectorHelper


class BundleManager(_ClassLoggerMixin):
    """Build and send the bundle of one enrichment message, exactly once in a playbook.

    The connector creates one manager per message, from the raw message data, so that
    even an invalid message gets its bundle back in a playbook. Processors never see
    it: they return their objects, and the connector stores them in ``objects``. The
    bundle is sent once, when the ``with`` block ends: a message gets exactly one
    bundle in a playbook, whichever processor handles it, and even when no processor
    handles it.

    It is a context manager, created for each message::

        with BundleManager(helper, data) as bundle_manager:
            message = ...  # validation
            bundle_manager.message = message
            ...  # checks
            bundle_manager.objects = processor.process(message)
        # The bundle is sent when the `with` block ends
        outcome = bundle_manager.outcome

    Attributes:
        message: The validated message, given by the connector, used for the context
            of the logs. ``None`` until the message is validated.
        objects: The objects returned by the processor, to send with the original
            objects of the message.
        outcome: A message describing the outcome of the message, stored on the work in
            manual/auto mode.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, data: dict[str, Any]) -> None:
        """Initialize the manager of one message.

        Args:
            helper: The OpenCTI connector helper, used to send the bundles.
            data: The message data passed by ``OpenCTIConnectorHelper.listen()``, not
                validated yet.
        """
        self._helper = helper
        self._entity_id = data.get("entity_id")
        # pycti resets `helper.playbook` for each message
        self._from_playbook = helper.playbook is not None
        stix_objects = data.get("stix_objects")
        # The bundle sent back must be the one received, even if a processor changed
        # it. An invalid message may hold no objects to send back.
        self._original_objects: list[dict[str, Any]] = (
            deepcopy(stix_objects) if isinstance(stix_objects, list) else []
        )
        self.message: EnrichmentMessage | None = None
        self.objects: list[Any] = []
        self._bundle_sent = False
        self.outcome = "No enrichment data found"

    @property
    def _log_metadata(self) -> dict[str, Any]:
        """The context to log: only the entity id until the message is validated."""
        if self.message is None:
            return {"entity_id": self._entity_id}
        return self.message.to_log_metadata()

    def _update_original_bundle(self, new_objects: list[Any]) -> list[dict[str, Any]]:
        """Add the processor's objects to the original objects of the message.

        - A ``Reference`` is ignored: it only points to an object already in OpenCTI.
        - An object with the id of an original object replaces it (e.g. a new version
          of the entity to enrich). In a playbook, two objects with the same id would
          both go to the next steps.
        - The other objects are added at the end.

        Args:
            new_objects: The objects returned by the processor's ``transform()``.

        Returns:
            The objects to send, as STIX dicts.
        """
        # Keyed by id: an id already present replaces the object in place,
        # a new id is added at the end.
        bundle_objects = {obj["id"]: obj for obj in self._original_objects}
        for obj in new_objects:
            if isinstance(obj, Reference):
                continue
            stix_object = to_stix_dict(obj)
            bundle_objects[stix_object["id"]] = stix_object
        return list(bundle_objects.values())

    def _send_original_bundle(self) -> None:
        """Send the objects received in a playbook back, as they are."""
        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle(self._original_objects)
            # do not set cleanup_inconsistent_bundle=True to avoid any data loss
        )

    def _send(self) -> None:
        """Send the original objects of the message with the processor's objects.

        Nothing is sent when ``objects`` is empty: the outcome stays
        "No enrichment data found".
        """
        if not self.objects:
            self.logger.info("No enrichment data found", meta=self._log_metadata)
            return

        bundle = self._helper.stix2_create_bundle(
            self._update_original_bundle(self.objects)
        )
        # Set before sending: once the platform may have the bundle, the original one
        # is never sent too, since the next playbook step would run twice
        self._bundle_sent = True
        self._helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
        self.outcome = f"Entity enriched with {len(self.objects)} objects"
        self.logger.info(
            "Entity enriched",
            meta={**self._log_metadata, "objects_count": len(self.objects)},
        )

    def __enter__(self) -> BundleManager:
        """Start handling the message.

        Returns:
            The manager itself, to store the message and the objects in.
        """
        # The logic lives in `_handle()`: as a generator, its ways out are plain
        # `except` clauses, which `__exit__` would have to rebuild by hand.
        self._handling: AbstractContextManager[None] = self._handle()
        self._handling.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """End handling the message: send its bundle, or handle the exception raised.

        Args:
            exc_type: The type of the exception raised in the ``with`` block, if any.
            exc: The exception raised in the ``with`` block, if any.
            traceback: The traceback of the exception raised, if any.

        Returns:
            ``True`` when the exception is a skip, stopped here.
        """
        return self._handling.__exit__(exc_type, exc, traceback)

    @contextmanager
    def _handle(self) -> Generator[None, Any, Any]:
        """Handle the message, then send its bundle: exactly one in a playbook.

        The ``with`` block ends in one of three ways:

        - Success (no exception): ``objects`` are sent with the original objects. When
          there are none, nothing is sent outside playbooks.
        - Skip (``UnsupportedEntityError``): the entity is not enriched, on purpose. The
          exception is stopped here and its message becomes the outcome.
        - Failure (any other exception, including while sending the bundle): it is
          logged, then raised again, so that pycti puts the work in error. An
          ``InvalidEnrichmentMessageError`` is logged as "Invalid enrichment message".

        In a playbook, the original bundle is sent back whenever the processor's
        objects were not sent, even for an invalid message when it holds objects. Once
        the processor's objects may have reached the platform, it is not: the next
        playbook step would run twice.

        Yields:
            Nothing: the connector stores the message and the processor's objects in
            ``message`` and ``objects``.
        """
        # pycti logs a generic message without the exception text: it is logged here.
        try:
            yield
            self._send()

        except UnsupportedEntityError as skip:
            self.outcome = str(skip)
        except InvalidEnrichmentMessageError:
            self.logger.exception("Invalid enrichment message", meta=self._log_metadata)
            raise
        except Exception:
            self.logger.exception("Enrichment failed", meta=self._log_metadata)
            raise

        finally:
            if self._from_playbook and not self._bundle_sent and self._original_objects:
                try:
                    self._send_original_bundle()
                except Exception:
                    # Logged, not raised: the failure raised must be the first one
                    self.logger.exception(
                        "Failed to send the original bundle back",
                        meta=self._log_metadata,
                    )
