# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy
"""Define the Connector class for the ProofPoint TAP module integration with OpenCTI.
It handles the initialization, data retrieval, transformation to STIX format, and sending of data to OpenCTI.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING
import sys


from pycti import (  # type: ignore[import-untyped] # pycti does not provide stubs
    OpenCTIConnectorHelper,
)


from proofpoint_tap.domain.use_cases.ingest_report import ReportProcessor
from proofpoint_tap.errors import DataRetrievalError

if TYPE_CHECKING:
    from proofpoint_tap.ports.config import ConfigLoaderPort
    from proofpoint_tap.ports.campaign import CampaignsPort


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
        campaigns: "CampaignsPort",
        helper: OpenCTIConnectorHelper,
    ):
        """Initialize the Connector with necessary configurations."""
        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.logger = helper.connector_logger
        self.campaigns = campaigns
        self.report_processor = ReportProcessor(
            tlp_marking_name=self.config.tap.marking_definition,
        )
        self.work_id = None
        self.campaign_since_datetime: datetime | None = None

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

    def _force_set_state(self, state: dict[str, str]) -> None:
        self.helper.set_state(state=state)
        self.helper.force_ping()

    def _initiate_work(self) -> None:
        """Initiate a new work process in the OpenCTI platform.

        This method:
            1. Update data retrieval start date based on state
            2. Initiates work in OpenCTI platform and register work_id attribute
            3. Logs the event
            4. set the work ID for future use.
        """
        state = self._force_get_state()
        self.logger.debug("[CONNECTOR] Connector current state", {"state": state})

        last_ingested_campaign_start_time_str = state.get(
            "last_ingested_campaign_start_time"
        )

        # Update data retrieval start datetime
        if last_ingested_campaign_start_time_str is not None:
            self.logger.info(
                "[CONNECTOR] Connector last ingested camapign start datetime",
                {
                    "last_ingested_campaign_start_time": last_ingested_campaign_start_time_str
                },
            )

            self.logger.warning(
                "[CONNECTOR] Connector acquisition SINCE parameter overwritten",
                {
                    "previous": str(self.config.tap.export_since),
                    "current": last_ingested_campaign_start_time_str,
                },
            )
            self.campaign_since_datetime = datetime.fromisoformat(
                last_ingested_campaign_start_time_str
            )
        else:
            self.logger.info("[CONNECTOR] Connector has never run successfully...")
            self.campaign_since_datetime = self.config.tap.export_since

        # Initiate a new work
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, self.helper.connect_name
        )

        self.logger.info(
            "[CONNECTOR] Running connector...",
            {"connector_name": self.helper.connect_name},
        )

    def _finalize_work(self, error_flag: bool) -> None:
        """Finalize the work process in the OpenCTI platform.

        Args:
            error_flag(bool): Flag to indicate if the work process has an error.

        Returns:
            None

        """
        self.helper.api.work.to_processed(
            work_id=self.work_id,
            message="Connector's work finished gracefully",
            in_error=error_flag,
        )
        self.work_id = None

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

    def _process_campaigns(self) -> bool:
        """Fetch data, transform and send bundle. Return True if successful, False otherwise."""
        try:
            # Fetch data
            if self.campaign_since_datetime is None:
                raise ValueError(
                    "No start datetime to fetch campaigns, call _initiate_work first."
                )
            campaign_ids = self.campaigns.list(
                start_time=self.campaign_since_datetime,
                stop_time=datetime.now(timezone.utc),
            )
            self.logger.info(
                "[CONNECTOR] Campaigns IDs fetched",
                {"campaigns_count": len(campaign_ids)},
            )
            if len(campaign_ids) == 0:
                self.logger.info("No campaign IDs fetched.")
                return True

            # fetch details
            for campaign_id in campaign_ids:
                campaign_info = self.campaigns.details(campaign_id)
                self.logger.info(
                    "[CONNECTOR] Campaign details fetched",
                    {"campaign_id": campaign_id},
                )
                # process
                entities = self.report_processor.run_on(campaign_info)
                if len(entities) == 0:
                    self.logger.info("No entities to process.")
                    continue
                stix_objects = [entity.to_stix2_object() for entity in entities]
                # send
                self._send_bundle(self.helper.stix2_create_bundle(stix_objects))
                # update state
                last_ingested_campaign_start_time = campaign_info.start_datetime
                self.helper.set_state(
                    {
                        "last_ingested_campaign_start_time": last_ingested_campaign_start_time.isoformat(),
                    }
                )
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

            error_flag = not self._process_campaigns()

        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped by user"
            self._log_error(error_message)
            sys.exit(0)

        except Exception as err:
            error_flag = True
            self.logger.error("[CONNECTOR] Unexpected error.", {"error": str(err)})
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

    from proofpoint_tap.adapters.campaign import CampaignsAPIV2
    from proofpoint_tap.adapters.config import ConfigLoaderEnv

    # Configuration
    try:
        config = ConfigLoaderEnv()
        helper = OpenCTIConnectorHelper(config=config.to_dict())
        campaigns = CampaignsAPIV2(
            base_url=config.tap.api_base_url,
            principal=config.tap.api_principal_key,
            secret=config.tap.api_secret_key,
            timeout=config.tap.api_timeout,
            retry=config.tap.api_retries,
            backoff=config.tap.api_backoff,
        )
    except (
        Exception
    ):  # Start up issue exception, Otherwise shoud be handle gracefully by the connector
        traceback.print_exc()
        sys.exit(1)

    # Run the connector
    # Error will be handled in the connector
    connector = Connector(config, campaigns, helper)
    connector.start()
