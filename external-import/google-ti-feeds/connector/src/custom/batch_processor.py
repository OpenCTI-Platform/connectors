"""The module will contains method to process batches of STIX objects."""

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from connector.src.custom.exceptions import GTIWorkProcessingError

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.custom.convert_to_stix import ConvertToSTIX
    from connector.src.octi.work_manager import WorkManager

LOG_PREFIX = "[BatchProcessor]"


class BatchProcessor:
    """The class will contains method to process batches of STIX objects."""

    def __init__(
        self,
        work_manager: "WorkManager",
        work_id: str,
        converter: "ConvertToSTIX",
        logger: Optional["Logger"] = None,
    ) -> None:
        """Initialize the BatchProcessor.

        Args:
            work_manager: The work manager object
            work_id: The ID of the current work
            converter: ConvertToSTIX instance
            logger: Logger for logging messages

        """
        self._work_manager = work_manager
        self._work_id = work_id
        self._work_manager.set_current_work_id(work_id)
        self._converter = converter
        self._logger = logger or logging.getLogger(__name__)
        self._latest_modified_date: Optional[str] = None
        self._total_stix_objects_sent = 0
        self._total_batches_processed = 0
        self._all_stix_objects: List[Any] = []
        self._state_key = "last_report_date"

    def process_batch(
        self,
        reports: List[Any],
        related_entities: Dict[str, Dict[str, List[Any]]],
    ) -> None:
        """Process a batch of data by converting to STIX and sending to OpenCTI.

        Args:
            reports: List of report data for this batch
            related_entities: Dictionary of related entities for this batch

        Raises:
            GTIWorkProcessingError: If there's an error processing the work

        """
        if not reports:
            self._logger.info(f"{LOG_PREFIX} No reports in batch to process")
            return

        try:
            self._total_batches_processed += 1
            batch_num = self._total_batches_processed

            self._logger.info(
                f"{LOG_PREFIX} Converting batch #{batch_num} ({len(reports)} reports) to STIX format"
            )
            stix_objects = self._converter.convert_all_data(reports, related_entities)
            self._all_stix_objects.extend(stix_objects)

            self._logger.info(
                f"{LOG_PREFIX} Sending {len(stix_objects)} STIX objects to OpenCTI (batch #{batch_num})"
            )

            try:
                self._work_manager.send_bundle(
                    work_id=self._work_id, bundle=stix_objects
                )

                self._work_manager.work_to_process(work_id=self._work_id)
                new_work_id = self._work_manager.initiate_work(
                    name=f"Google Threat Intel Feeds - Batch #{batch_num + 1}"
                )
                self._work_id = new_work_id

                self._total_stix_objects_sent += len(stix_objects)
                self._logger.info(
                    f"{LOG_PREFIX} Successfully sent batch #{batch_num}. Total STIX objects sent: {self._total_stix_objects_sent}"
                )

                converter_latest_date = self._converter.get_latest_report_date()
                if converter_latest_date:
                    if (
                        not self._latest_modified_date
                        or converter_latest_date > self._latest_modified_date
                    ):
                        self._latest_modified_date = converter_latest_date

                if self._latest_modified_date:
                    self._logger.info(
                        f"{LOG_PREFIX} Updating state with latest date: {self._latest_modified_date}"
                    )
                    self._work_manager.update_state(
                        state_key=self._state_key, date_str=self._latest_modified_date
                    )

            except Exception as bundle_err:
                raise GTIWorkProcessingError(
                    f"Failed to send bundle for batch #{batch_num}: {str(bundle_err)}",
                    self._work_id,
                    {"stix_objects_count": len(stix_objects)},
                ) from bundle_err

        except Exception as e:
            if isinstance(e, GTIWorkProcessingError):
                raise

            raise GTIWorkProcessingError(
                f"Failed to process fetched data batch #{batch_num}: {str(e)}",
                self._work_id,
                {"batch_number": batch_num, "reports_count": len(reports)},
            ) from e

    def get_latest_modified_date(self) -> Optional[str]:
        """Get the latest modified date across all processed batches.

        Returns:
            The latest modification date (ISO format) if available, None otherwise

        """
        return self._latest_modified_date

    def set_latest_modified_date(self, date_str: str) -> None:
        """Set the latest modified date.

        Args:
            date_str: The date string in ISO format

        """
        if date_str and (
            not self._latest_modified_date or date_str > self._latest_modified_date
        ):
            self._latest_modified_date = date_str

    def update_final_state(self) -> None:
        """Update the state with the final latest modification date after all processing is complete."""
        if self._latest_modified_date:
            self._logger.info(
                f"{LOG_PREFIX} Updating final state with latest date: {self._latest_modified_date}"
            )
            self._work_manager.update_state(
                state_key=self._state_key, date_str=self._latest_modified_date
            )

    def get_all_stix_objects(self) -> List[Any]:
        """Get all STIX objects processed across all batches.

        Returns:
            List of all STIX objects

        """
        return self._all_stix_objects

    def get_total_stix_objects_count(self) -> int:
        """Get the total number of STIX objects sent.

        Returns:
            The total number of STIX objects sent

        """
        return self._total_stix_objects_sent

    def get_total_batches_processed(self) -> int:
        """Get the total number of batches processed.

        Returns:
            The total number of batches processed

        """
        return self._total_batches_processed
