"""Offer Application containing orchestration logic for the Dragos Connector."""

import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dragos.domain.use_cases.common import UseCaseError
from dragos.domain.use_cases.ingest_report import ReportProcessor
from dragos.interfaces.common import DataRetrievalError
from pycti import (  # type: ignore[import-untyped]  # PyCTI is not typed
    OpenCTIConnectorHelper,
)

if TYPE_CHECKING:
    from dragos.interfaces.config import ConfigLoader
    from dragos.interfaces.geocoding import Geocoding
    from dragos.interfaces.report import Report, Reports


class Connector:
    """Dragos Connector class.

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    """

    LAST_RUN_KEY = "last_run"

    # Define ETL
    def _process_report(self, report: "Report") -> bool:
        """Fetch data, transform and send bundle. Return True if successful, False otherwise."""
        try:
            # extract entities with the report processor
            entities = self._report_processor.run_on(report)
            # transform to stix2 objects
            stix_objects = [entity.to_stix2_object() for entity in entities]
            # send to OpenCTI
            self._send_bundle(self._helper.stix2_create_bundle(stix_objects))
            return True

        except DataRetrievalError as e:
            self._logger.warning(f"Data retrieval error: {str(e)}")
        except UseCaseError as e:
            self._logger.warning(f"Use case error: {str(e)}")

        return False

    # Explicit workflow
    def work(self) -> None:
        """Define the main process of the connector."""
        error_flag = True

        if self._acquire_since is None:
            # check for the scatterbrained developer
            raise ValueError(
                "No start datetime to fetch reports, call _initiate_work first."
            )

        try:
            self._initiate_work()
            successes: list[bool] = []
            for report in self._reports.iter(since=self._acquire_since):
                successes.append(self._process_report(report))

            # update error flag if not all successes
            # do not fail if no reports were found
            error_flag = not (all(successes))

        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped by user"
            self._log_error(error_message)
            sys.exit(0)

        except Exception as err:
            error_flag = True
            self._logger.error("[CONNECTOR] Unexpected error.", {"error": str(err)})
            self._log_error("Unexpected error. See connector's log for more details.")

        finally:
            self._finalize_work(error_flag)

    # Tools
    def __init__(
        self,
        config: "ConfigLoader",
        reports: "Reports",
        geocoding: "Geocoding",
        helper: OpenCTIConnectorHelper,
    ):
        """Initialize the Connector with necessary configurations."""
        # Load configuration file and connection helper
        self._config = config
        self._helper = helper
        self._logger = helper.connector_logger
        self._reports = reports
        self._geocoding = geocoding
        self._report_processor = ReportProcessor(
            tlp_level=self._config.dragos.tlp_level,
            geocoding=self._geocoding,
        )
        # To be intialized during work
        # keep track of current work
        self.work_id = None
        # keep track of current work datetime to update state
        # when finalizing work
        self._work_start_datetime: datetime | None = None
        # keep track of last run datetime
        # for ingestion driving
        self._acquire_since: datetime | None = None

    def _log_error(self, error_message: str) -> None:
        # to connector logger
        self._logger.error(message=error_message)
        # to OpenCTI
        self._helper.api.work.report_expectation(
            work_id=self.work_id, error={"error": error_message, "source": "CONNECTOR"}
        )

    def _force_get_state(self) -> dict[str, str]:
        self._helper.force_ping()
        return self._helper.get_state() or {}

    def _force_set_state(self, state: dict[str, str]) -> None:
        self._helper.set_state(state=state)
        self._helper.force_ping()

    def _force_update_state(self, key: str, value: "datetime") -> None:
        state = self._force_get_state()
        state[key] = value.isoformat()
        self._force_set_state(state)

    def _initiate_work(self) -> None:
        """Initiate a new work process in the OpenCTI platform.

        This method:
            1. Update data retrieval start date based on state
            2. Initiates work in OpenCTI platform and register work_id attribute
            3. Logs the event
            4. set the work ID for future use.
        """
        state = self._force_get_state()
        self._logger.debug("[CONNECTOR] Connector current state", {"state": state})

        # set aquisition date

        last_run_datetime_state = state.get(self.LAST_RUN_KEY)

        if last_run_datetime_state is not None:

            self._logger.debug(
                "[CONNECTOR] Connector acquisition SINCE parameter overwritten"
            )
            self._acquire_since = datetime.fromisoformat(last_run_datetime_state)
        else:
            self._logger.debug("[CONNECTOR] Connector has never run successfully.")
            _acquire_since = self._config.dragos.import_start_date

        # Initiate a new work
        self.work_id = self._helper.api.work.initiate_work(
            self._helper.connect_id, self._helper.connect_name
        )
        self._work_start_datetime = datetime.now(timezone.utc)

        self._logger.info(
            "[CONNECTOR] Running connector...",
            {
                "connector_name": self._helper.connect_name,
                "work_id": self.work_id,
                "acquire_since": self._acquire_since,
            },
        )

    def _finalize_work(self, error_flag: bool) -> None:
        """Finalize the work process in the OpenCTI platform.

        Args:
            error_flag(bool): Flag to indicate if an error occurred during the work process.

        Returns:
            None

        """
        # Update State
        self._force_update_state(
            key=self.LAST_RUN_KEY,
            value=self._work_start_datetime,  # type: ignore[arg-type] # should not be None
        )

        self._helper.api.work.to_processed(
            work_id=self.work_id,
            message="Connector's work finished gracefully",
            in_error=error_flag,
        )

        # reset
        self.work_id = None
        self._work_start_datetime = None
        self._acquire_since = None

    def _send_bundle(self, bundle_json: str) -> None:
        """Send the STIX bundle to the OpenCTI platform and update the total expectation.

        Args:
            bundle_json(str): The STIX bundle to send.

        Returns:
           None

        """
        bundles_sent = self._helper.send_stix2_bundle(
            bundle=bundle_json,
            work_id=self.work_id,
            cleanup_inconsistent_bundle=True,
        )
        self._logger.info(
            "STIX objects sent to OpenCTI.",
            {"bundles_sent": str(len(bundles_sent))},
        )

    def start(self) -> None:
        """Run the main process encapsulated in a scheduler.

        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        """
        self._helper.schedule_iso(
            message_callback=self.work,
            duration_period=self._config.connector.duration_period,
        )
