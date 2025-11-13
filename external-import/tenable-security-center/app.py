# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy
"""Define the Connector class for the Tenable Security Center integration with OpenCTI.
It handles the initialization, data retrieval, transformation to STIX format, and sending of data to OpenCTI.
"""

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING
import sys


from pycti import (  # type: ignore[import-untyped] # pycti does not provide stubs
    OpenCTIConnectorHelper,
)

from tenable_security_center.domain.use_case import ConverterToStix

from tenable_security_center.ports.errors import DataRetrievalError

if TYPE_CHECKING:
    from tenable_security_center.ports.asset import AssetsPort, AssetsChunkPort
    from tenable_security_center.ports.config import ConfigLoaderPort


class Connector:
    """Specifications of the external import connector.

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    """

    def __init__(
        self,
        config: "ConfigLoaderPort",
        assets: "AssetsPort",
        helper: OpenCTIConnectorHelper,
    ):
        """Initialize the Connector with necessary configurations."""
        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.logger = helper.connector_logger
        self.assets = assets
        self.converter_to_stix = ConverterToStix(
            self.logger, self.config.tenable_security_center.marking_definition
        )
        self.work_id = None
        self._expected_stix_objects = 0

    def _log_error(self, error_message: str) -> None:
        # to connector logger
        self.logger.error(message=error_message)
        # to OpenCTI
        self.helper.api.work.report_expectation(
            work_id=self.work_id, error={"error": error_message, "source": "CONNECTOR"}
        )

    def _force_get_state(self) -> dict[str, str]:
        self.helper.force_ping()
        return self.helper.get_state() or {}

    def _initiate_work(self) -> None:
        """Initiate a new work process in the OpenCTI platform.

        This method:
            1. Update data retrieval start date based on state
            2. Initiates work in OpenCTI platform and register work_id attribute
            3. Logs the event
            4. Returns the work ID for future use.
        """
        now_isodatetime = datetime.now(timezone.utc).isoformat()

        state = self._force_get_state()
        self.logger.debug("[CONNECTOR] Connector current state", {"state": state})

        last_run = state.get("last_run_start_datetime")
        last_successful_run = state.get("last_successful_run_start_datetime")

        # Update state
        state.update({"last_run_start_datetime": now_isodatetime})
        self.helper.set_state(state=state)

        # Update data retrieval start datetime
        if last_successful_run is not None:
            self.logger.info(
                "[CONNECTOR] Connector last run", {"last_run_start_datetime": last_run}
            )
            previous_since = str(self.config.tenable_security_center.export_since)

            self.logger.warning(
                "[CONNECTOR] Connector acquisition SINCE parameter overwritten",
                {"previous": previous_since, "current": last_successful_run},
            )
            self.assets.since_datetime = datetime.fromisoformat(last_successful_run)
        else:
            self.logger.info("[CONNECTOR] Connector has never run successfully...")
            self.assets.since_datetime = (
                self.config.tenable_security_center.export_since
            )

        # Initiate a new work
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, self.helper.connect_name
        )

        # Reset expectations
        self._expected_stix_objects = 0
        self.logger.info(
            "[CONNECTOR] Running connector...",
            {"connector_name": self.helper.connect_name},
        )

    def _finalize_work(self, error_flag: bool) -> None:
        """Finalize the work process and logs the completion message.

        This method
            1. Update the connector state depending on the results.
            2. Marks the work as processed on the OpenCTI platform.
            3. Logs a message indicating that the connector ran.

        Args:
            error_flag(bool): The overall processing results (True if OK False otherwise).

        See Also:
            _initiate_work method

        """
        state = self.helper.get_state() or {}
        now_isodatetime = datetime.now(timezone.utc).isoformat()
        if not error_flag:
            state.update(
                {
                    "last_successful_run_start_datetime": state.get(
                        "last_run_start_datetime"
                    ),
                }
            )
        self.helper.set_state(state=state)
        message = (
            f"{self.helper.connect_name} connector {'successfully' if not error_flag else ''} run, "
            f"storing last_run as {now_isodatetime}"
        )
        self.logger.info(message)

    def _send_bundle(self, bundle_json: str) -> None:
        """Send the STIX bundle to the OpenCTI platform and update the total expectation.

        Args:
            bundle_json(str): The STIX bundle to send.

        Returns:
           None

        """
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=bundle_json,
            work_id=self.work_id,
            cleanup_inconsistent_bundle=True,
        )
        self.logger.info(
            "STIX objects sent to OpenCTI.",
            {"bundles_sent": str(len(bundles_sent))},
        )

    def _process(self, chunk: "AssetsChunkPort") -> bool:
        """Fetch data, transform and send bundle."""
        try:

            stix_objects = self.converter_to_stix.process_assets_chunk(
                chunk,
                process_systems_without_vulnerabilities=self.config.tenable_security_center.process_systems_without_vulnerabilities,
            )
            self.logger.info(
                "STIX objects incoming.",
                {"number_stix_objects": str(len(stix_objects))},
            )

            if len(stix_objects) == 0:
                return True

            self._send_bundle(self.helper.stix2_create_bundle(stix_objects))

            return True

        except DataRetrievalError as e:
            self._log_error(f"Data retrieval error: {str(e)}")
            return False

    def work(self) -> None:
        """Define the main process of the connector."""
        error_flag = True
        try:
            self.logger.info(
                "[CONNECTOR] Starting connector work...",
                {"connector_name": self.helper.connect_name},
            )

            self._initiate_work()

            with ThreadPoolExecutor(
                self.config.tenable_security_center.num_threads
            ) as executor:
                results = list(executor.map(self._process, self.assets.chunks))

            error_flag = (
                not all(results) if len(results) != 0 else False
            )  # not in error if nothing to retrieve

            self._finalize_work(error_flag=error_flag)

        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped by user"
            self._log_error(error_message)
            sys.exit(0)

        except Exception as err:
            self.logger.error("Unexpected error.", {"error": str(err)})
            self._log_error("Unexpected error. See connector's log for more details.")

        finally:
            self.helper.api.work.to_processed(
                work_id=self.work_id,
                message="Connector's work finished gracefully",
                in_error=error_flag,
            )
            self.work_id = None

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
        self.helper.schedule_iso(
            message_callback=self.work,
            duration_period=self.config.connector.duration_period,
        )


if __name__ == "__main__":
    import traceback

    from tenable_security_center.adapters.config.env import ConfigLoaderEnv
    from tenable_security_center.adapters.tsc_api.v5_13_from_asset import (
        AssetsAPI,
    )

    # Configuration
    try:
        config = ConfigLoaderEnv()
        helper = OpenCTIConnectorHelper(config.to_dict())
        assets = AssetsAPI(
            url=config.tenable_security_center.api_base_url,
            access_key=config.tenable_security_center.api_access_key,
            secret_key=config.tenable_security_center.api_secret_key,
            retries=config.tenable_security_center.api_retries,
            backoff=config.tenable_security_center.api_backoff,
            timeout=config.tenable_security_center.api_timeout,
            since_datetime=config.tenable_security_center.export_since,
            num_threads=config.tenable_security_center.num_threads,
            logger=helper.connector_logger,
            findings_min_severity=config.tenable_security_center.severity_min_level,
        )
    except (
        Exception
    ):  # Start up issue exception, Otherwise shoud be handle gracefully by the connector
        traceback.print_exc()
        sys.exit(1)

    # Run the connector
    # Error will be handled in the connector
    connector = Connector(config, assets, helper)
    connector.start()
