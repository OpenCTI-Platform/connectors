"""Bundle sender module.

This module provides ``_MessageManager``, the only place that builds and sends the bundle
of an enrichment message:

- the original objects of the message with the processor's objects, through ``send()``;
- in a playbook, the original bundle back when nothing else was sent (skip, no data,
  failure).

In a playbook, exactly one bundle must be sent per message: sending none stalls the
playbook, sending two runs the next step twice.

The sender does not merge the properties of an entity: OpenCTI does it, with the
worker upsert in manual/auto mode, and with the playbook executor in a playbook.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from typing import Any, Generator

from connectors_sdk.connectors._stix_conversion import to_stix_dict
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from connectors_sdk.connectors.internal_enrichment.exceptions import (
    EntityOutOfScopeError,
    UnsupportedEntityError,
)
from connectors_sdk.logger._class_logger import _ClassLoggerMixin
from connectors_sdk.models.reference import Reference
from pycti import OpenCTIConnectorHelper


class MessageManager(_ClassLoggerMixin):
    """Build and send the bundle of each enrichment message, exactly once in a playbook.

    The connector creates one sender and gives it to every processor. Unlike the
    ``WorkManager`` of external import connectors, which belongs to one processor,
    the sender follows the message: a message gets exactly one bundle in a playbook,
    whichever processor handles it, and even when no processor handles it.

    For each message::

        with bundle_sender.handle(message):  # by the connector
            ...  # checks, then processor.process(message)
            bundle_sender.send(objects)  # by the processor
        outcome = bundle_sender.outcome

    The sender keeps the state of the current message: pycti handles one message at a
    time.

    Attributes:
        outcome: A message describing the outcome of the current message, stored on the
            work in manual/auto mode.
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """Initialize the sender.

        Args:
            helper: The OpenCTI connector helper, used to send the bundles.
        """
        self._helper = helper
        self._original_objects: list[dict[str, Any]] = []
        self._from_playbook = False
        self._log_metadata: dict[str, Any] = {}
        self._bundle_sent = False
        self.outcome = ""

    def _extract_message(self, message: EnrichmentMessage) -> None:
        """Reset the state for a new message.

        Args:
            message: The enrichment message to handle.
        """
        # The bundle sent back must be the one received, even if a processor changed it
        self._original_objects = deepcopy(message.stix_objects)
        self._from_playbook = message.from_playbook
        self._bundle_sent = False
        self.outcome = "No enrichment data found"

        self._log_metadata = message.to_log_metadata()

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
        """In a playbook, send the original bundle back if no bundle was sent yet."""
        if self._from_playbook and not self._bundle_sent:
            self._helper.send_stix2_bundle(
                self._helper.stix2_create_bundle(self._original_objects)
                # do not set cleanup_inconsistent_bundle=True to avoid any data loss
            )
            self._bundle_sent = True

    @contextmanager
    def handle(self, message: EnrichmentMessage) -> Generator[None, Any, Any]:
        """Handle one message, and send exactly one bundle for it in a playbook.

        The ``with`` block ends in one of three ways:

        - Success (no exception): the processor's objects were sent, or there was no data.
        - Skip (``UnsupportedEntityError``): the entity is not enriched, on purpose. The
          exception is stopped here and its message becomes the outcome.
          ``EntityOutOfScopeError`` is a skip only in a playbook: outside playbooks the
          platform only sends entities in scope, so there it is a failure.
        - Failure (any other exception): it is logged, then raised again, so that pycti
          puts the work in error.

        In a playbook, whatever the way, the original bundle is sent back if no bundle
        was sent yet.

        Args:
            message: The enrichment message to handle.

        Yields:
            Nothing: processors send their objects with ``send()``.
        """
        self._extract_message(message)

        try:
            yield

        except EntityOutOfScopeError as error:
            if self._from_playbook:
                self.outcome = str(error)
            else:
                # The platform only sends entities in scope, except in playbooks
                self.logger.exception("Enrichment failed", meta=self._log_metadata)
                raise
        except UnsupportedEntityError as skip:
            self.outcome = str(skip)
        except Exception:
            # pycti logs a generic message without the exception text: log it here.
            self.logger.exception("Enrichment failed", meta=self._log_metadata)
            raise

        finally:
            try:
                self._send_original_bundle()
            except Exception:
                # Logged, not raised: the failure raised must be the first one
                self.logger.exception(
                    "Failed to send the original bundle back", meta=self._log_metadata
                )

    def send(self, new_objects: list[Any]) -> None:
        """Send the original objects of the message with the processor's objects.

        Nothing is sent when ``new_objects`` is empty: the outcome stays
        "No enrichment data found".

        Args:
            new_objects: The objects returned by the processor's ``transform()``.

        Raises:
            RuntimeError: If a bundle was already sent for this message.
        """
        if self._bundle_sent:
            raise RuntimeError("A bundle was already sent for this message.")

        # `processor.send()` already skips empty lists: this guards direct calls
        if not new_objects:
            self.logger.info("No enrichment data found", meta=self._log_metadata)
            return

        bundle = self._helper.stix2_create_bundle(
            self._update_original_bundle(new_objects)
        )
        self._helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
        # Set after sending: if the platform never got the bundle, the original one
        # is sent instead (most failures happen before the platform uses it)
        self._bundle_sent = True
        self.outcome = f"Entity enriched with {len(new_objects)} objects"
