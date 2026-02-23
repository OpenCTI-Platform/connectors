from typing import TYPE_CHECKING

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

    def init_work(self, name: str) -> str:
        """Initialize a new work and return its ID."""
        work_id = self.helper.api.work.initiate_work(
            connector_id=str(self.helper.connect_id), friendly_name=name
        )
        if not isinstance(work_id, str):
            raise WorkManagerError("Failed to initiate work")

        return work_id

    def send_bundle(
        self, work_id: str, stix_objects: list["stix2.v21._STIXBase21"]
    ) -> None:
        """Send a STIX bundle to OpenCTI and mark the work as completed."""
        bundle = self.helper.stix2_create_bundle(stix_objects)
        if not bundle:
            raise WorkManagerError("Failed to create STIX bundle")

        self.helper.send_stix2_bundle(bundle=bundle, work_id=work_id)

    def complete_work(self, work_id: str, message: str, in_error: bool = False) -> None:
        """Mark the work as completed."""
        self.helper.api.work.to_processed(work_id, message, in_error)

    def delete_work(self, work_id: str) -> None:
        """Delete a work."""
        self.helper.api.work.delete_work(work_id)
