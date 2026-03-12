from typing import TYPE_CHECKING

from connectors_sdk.logging.sdk_logger import sdk_logger as logger

if TYPE_CHECKING:
    import stix2
    from pycti import OpenCTIConnectorHelper


class WorkManagerError(Exception):
    """Custom exception for WorkManager errors."""


class WorkManager:
    """Manages work lifecycle with OpenCTI.

    Responsibilities:
    - Initiate work
    - Mark work complete
    - Handle work cleanup
    """

    def __init__(self, helper: "OpenCTIConnectorHelper") -> None:
        """Initialize with OpenCTI helper."""
        self.helper = helper

        # Ensure OpenCTIConnectorHelper's logger is attached to SDK's logger as soon as it's reachable
        logger.attach_connector_helper_logger(self.helper)
        self._logger = logger.get_child("work_manager")

        self._logger.debug("WorkManager initialized succesfully")

    def init_work(self, name: str) -> str:
        """Initialize a new work and return its ID."""
        work_id = self.helper.api.work.initiate_work(
            connector_id=str(self.helper.connect_id), friendly_name=name
        )
        if not isinstance(work_id, str):
            raise WorkManagerError("Failed to initiate work")

        self._logger.debug("Initiated work", {"work_id": work_id, "work_name": name})

        return work_id

    def send_bundle(
        self, work_id: str, stix_objects: list["stix2.v21._STIXBase21"]
    ) -> None:
        """Send a STIX bundle to OpenCTI and mark the work as completed."""
        if not stix_objects:
            raise WorkManagerError("Cannot send empty STIX bundle")

        bundle = self.helper.stix2_create_bundle(stix_objects)
        sent_bundles = self.helper.send_stix2_bundle(bundle=bundle, work_id=work_id)

        self._logger.debug(
            "Bundles sent to work",
            {"work_id": work_id, "object_count": len(sent_bundles)},
        )

    def complete_work(self, work_id: str, message: str, in_error: bool = False) -> None:
        """Mark the work as completed."""
        self.helper.api.work.to_processed(work_id, message, in_error)

        self._logger.debug(
            "Completed work",
            {"work_id": work_id, "message": message, "in_error": in_error},
        )

    def delete_work(self, work_id: str) -> None:
        """Delete a work."""
        self.helper.api.work.delete_work(work_id)

        self._logger.debug("Deleted work", {"work_id": work_id})
