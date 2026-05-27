"""Work manager module.

This module provides the ``WorkManager`` and ``_Work`` classes
to manage the lifecycle of connector works in OpenCTI.

A *work* is a unit of execution tracked by the OpenCTI platform.
``WorkManager`` is used as a context manager: it creates works lazily
on ``send()``, and closes the work on exit. Only one work is active
at a time.

Architecture::

    with WorkManager(helper, logger) as wm:
        wm.send(objects, "Import indicators")  # creates work
        wm.send(objects, "Import indicators")  # same work, another bundle
        wm.send(reports, "Import reports")     # closes previous, opens new work
    # work auto-closed: success / fail / delete
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from connectors_sdk.logging.sdk_logger import sdk_logger
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connectors_sdk.logging._base_logger import BaseLogger


class _Work:
    """Manage the lifecycle of a single work in OpenCTI.

    A ``_Work`` is created by ``WorkManager`` via the ``create`` classmethod
    and represents an active work on the OpenCTI platform. Its lifecycle
    (success, fail, delete) is managed by the ``WorkManager``.

    Attributes:
        id: The OpenCTI work identifier.
        name: The human-readable name of the work, displayed in the OpenCTI UI.
    """

    logger: ClassVar[BaseLogger] = sdk_logger.get_child("WorkManager._Work")

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        work_id: str,
        work_name: str,
    ) -> None:
        """Initialize the work context.

        Args:
            helper: The ``OpenCTIConnectorHelper`` instance.
            work_id: The work ID returned by OpenCTI.
            work_name: The human-readable name of the work, displayed in the OpenCTI UI.
        """
        self.id = work_id
        self.name = work_name
        self._helper = helper
        self._closed = False
        self._has_sent_bundles = False

        self.logger.debug(f"{self.__class__.__name__} instantiated succesfully")

    @classmethod
    def create(cls, helper: OpenCTIConnectorHelper, work_name: str) -> _Work:
        """Create a new work in OpenCTI and return a ``_Work`` instance.

        This classmethod encapsulates the OpenCTI API call to initiate a work,
        so that ``WorkManager`` does not need to call the API directly.

        Args:
            helper: The ``OpenCTIConnectorHelper`` instance.
            work_name: The name of the work, displayed in the OpenCTI UI.

        Returns:
            A new ``_Work`` instance wrapping the created work.
        """
        work_id: str = helper.api.work.initiate_work(helper.connect_id, work_name)
        cls.logger.debug(
            "Work created",
            {"work_name": work_name, "work_id": work_id},
        )
        return cls(helper, work_id, work_name)

    def send_bundle(self, bundle_objects: list[Any], **kwargs: Any) -> None:
        """Create a STIX bundle from objects and send it to OpenCTI.

        Args:
            bundle_objects: A list of STIX/SDK objects to include in the bundle.
            **kwargs: Additional arguments forwarded to ``send_stix2_bundle``
                (e.g. ``cleanup_inconsistent_bundle``, ``update``, ``entities_types``).
        """
        stix_objects = self._to_stix(bundle_objects)
        bundle = self._helper.stix2_create_bundle(stix_objects)
        bundles_sent = self._helper.send_stix2_bundle(
            bundle,
            work_id=self.id,
            **kwargs,
        )
        self._has_sent_bundles = True
        self.logger.info(
            "Sent STIX objects to OpenCTI",
            {
                "bundles_sent": len(bundles_sent),
                "work_name": self.name,
                "work_id": self.id,
            },
        )

    def success(self, message: str) -> None:
        """Mark the work as successfully completed.

        Args:
            message: A completion message stored alongside the work.
        """
        self._helper.api.work.to_processed(self.id, message)
        self.logger.debug(
            "Work marked as completed on OpenCTI",
            {"work_name": self.name, "work_id": self.id, "message": message},
        )
        self._closed = True

    def fail(self, message: str) -> None:
        """Mark the work as failed.

        Args:
            message: An error message stored alongside the work.
        """
        self._helper.api.work.to_processed(self.id, message, in_error=True)
        self.logger.debug(
            "Work marked as failed on OpenCTI",
            {"work_name": self.name, "work_id": self.id, "message": message},
        )
        self._closed = True

    def _delete(self) -> None:
        """Delete the work from OpenCTI.

        Warning:
            This is a destructive operation. It should only be called from
            the ``WorkManager`` to clean up orphaned or invalid works.
        """
        self._helper.api.work.delete(id=self.id)
        self.logger.debug(
            "Work deleted on OpenCTI",
            {"work_name": self.name, "work_id": self.id},
        )
        self._closed = True

    @staticmethod
    def _to_stix(objects: list[Any]) -> list[Any]:
        """Convert objects to stix2, calling ``to_stix2_object()`` when available."""
        return [
            obj.to_stix2_object() if hasattr(obj, "to_stix2_object") else obj
            for obj in objects
        ]


class WorkManager:
    """Manage the lifecycle of works in OpenCTI.

    Used as a context manager: creates a work lazily on ``send()``, and
    closes it on ``__exit__``. Only one work is active at a time.

    Behavior on exit:

    - On exception: the work is marked as failed.
    - If no bundles were sent: the work is deleted.
    - Otherwise: the work is marked as completed.

    Each ``send()`` call routes to a work by name.

    Sending to a new name closes the previous work first, then opens a new one.

    Objects passed to ``send()`` can be raw stix2 objects or connectors-sdk
    model instances (with a ``to_stix2_object()`` method). SDK objects are
    converted automatically.

    Example::

        work_manager = WorkManager(helper)
        with work_manager:
            work_manager.send(stix_objects, "Import indicators")
            work_manager.send(more_objects, "Import indicators")  # same work
            work_manager.send(reports, "Import reports")  # closes previous, new work
        # work auto-closed
    """

    logger: ClassVar[BaseLogger] = sdk_logger.get_child("WorkManager")

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """Initialize the work manager.

        Args:
            helper: The ``OpenCTIConnectorHelper`` instance.
        """
        self._helper = helper
        self._current_work: _Work | None = None
        self._active = False

        self.logger.debug(f"{self.__class__.__name__} instantiated succesfully")

    def __enter__(self) -> WorkManager:
        """Enter the context manager."""
        self._current_work = None
        self._active = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Close the active work.

        - Work with no bundles sent is deleted.
        - On exception: work with bundles is marked as failed.
        - Otherwise: work with bundles is marked as completed.
        """
        if self._current_work is not None and not self._current_work._closed:
            if not self._current_work._has_sent_bundles:
                self.logger.info(
                    "Zero bundles were sent, deleting work",
                    {
                        "work_name": self._current_work.name,
                        "work_id": self._current_work.id,
                    },
                )
                self._current_work._delete()
            elif exc_type is not None:
                message = f"Work failed with error: {exc_val}"
                self.logger.error(
                    message,
                    {
                        "work_name": self._current_work.name,
                        "work_id": self._current_work.id,
                    },
                )
                self._current_work.fail(message)
            else:
                message = "Work completed successfully"
                self.logger.info(
                    message,
                    {
                        "work_name": self._current_work.name,
                        "work_id": self._current_work.id,
                    },
                )
                self._current_work.success(message)
        self._current_work = None
        self._active = False

    def send(
        self,
        bundle_objects: list[Any],
        work_name: str,
        **kwargs: Any,
    ) -> None:
        """Send bundle objects to a work, creating it if needed.

        If the current work has the same name, the bundle is sent to it.
        Otherwise the current work is closed and a new one is created.

        Args:
            bundle_objects: A list of STIX/SDK objects to send as a bundle.
            work_name: The name for the work, displayed in the OpenCTI UI.
            **kwargs: Additional arguments forwarded to ``send_stix2_bundle``
                (e.g. ``cleanup_inconsistent_bundle``, ``update``, ``entities_types``).
        """
        if not bundle_objects:
            self.logger.info(
                "No objects to send",
                {"work_name": work_name},
            )
            return

        if not self._active:
            msg = "WorkManager.send() must be called inside a 'with' block."
            raise RuntimeError(msg)

        if self._current_work is None or self._current_work.name != work_name:
            self._close_current_work()

            self.logger.info(
                "Creating a new work",
                {
                    "new_work_name": work_name,
                    "previous_work_name": (
                        self._current_work.name
                        if self._current_work is not None
                        else None
                    ),
                },
            )
            self._current_work = _Work.create(self._helper, work_name)

        self._current_work.send_bundle(bundle_objects, **kwargs)

    def _close_current_work(self) -> None:
        """Close the current work if it exists and is not already closed."""
        if self._current_work is not None and not self._current_work._closed:
            if not self._current_work._has_sent_bundles:
                self.logger.info(
                    "Zero bundles were sent, deleting work",
                    {
                        "work_name": self._current_work.name,
                        "work_id": self._current_work.id,
                    },
                )
                self._current_work._delete()
            else:
                message = "Work completed successfully"
                self.logger.info(
                    message,
                    {
                        "work_name": self._current_work.name,
                        "work_id": self._current_work.id,
                    },
                )
                self._current_work.success(message)
