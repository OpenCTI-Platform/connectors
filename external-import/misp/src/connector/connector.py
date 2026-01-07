from typing import TYPE_CHECKING

from connector.settings import ConnectorSettings
from exceptions.connector_errors import MispWorkProcessingError
from pycti import OpenCTIConnectorHelper
from utils.orchestrators import Orchestrator
from utils.work_manager import WorkManager

if TYPE_CHECKING:
    from connector.settings import MispConfig

LOG_PREFIX = "[Connector]"


class Misp:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.config_misp: MispConfig = config.misp

        self.helper = helper
        self.logger = helper.connector_logger

        self.work_manager = WorkManager(self.config, self.helper, self.logger)

    def batch_process_event(self) -> str | None:
        """Setup and run the orchestrator to process MISP events."""

        try:
            orchestrator = Orchestrator(
                work_manager=self.work_manager,
                logger=self.logger,
                config=self.config_misp,
            )

            initial_state = self.helper.get_state()
            self.logger.info(
                "Retrieved state",
                {"prefix": LOG_PREFIX, "initial_state": initial_state},
            )

            self.logger.info("Starting MISP full ingestion...", {"prefix": LOG_PREFIX})
            orchestrator.run_event(initial_state)
            return None

        except Exception as e:
            error_msg = f"MISP events processing failed: {e}"
            self.logger.error(
                "MISP events processing failed",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )
            return error_msg

    def process(self):
        """Connector main process to collect intelligence."""
        error_flag = False
        error_message = None

        try:
            try:
                error_result = self.batch_process_event()
                if error_result:
                    error_message = error_result
                    error_flag = True
            except KeyboardInterrupt:
                raise KeyboardInterrupt("MISP imports processing interrupted") from None

        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped due to user interrupt"
            self.logger.info(
                "Connector stopped due to user interrupt",
                {"prefix": LOG_PREFIX, "connector_name": self.helper.connect_name},
            )
            error_flag = True
            raise

        except MispWorkProcessingError as work_err:
            error_message = f"Work processing error: {work_err}"
            work_id = getattr(
                work_err, "work_id", self.work_manager.get_current_work_id()
            )
            self.logger.warning(
                "Work processing error",
                meta={
                    "prefix": LOG_PREFIX,
                    "error": str(work_err),
                    "work_id": work_id,
                },
            )
            error_flag = True

        except Exception as err:
            error_message = f"Unexpected error: {err}"
            self.logger.error(
                "Unexpected error",
                {"prefix": LOG_PREFIX, "error": str(err)},
            )
            error_flag = True

        finally:
            self.logger.info(
                "Connector stopped",
                {"prefix": LOG_PREFIX, "connector_name": self.helper.connect_name},
            )
            try:
                self.work_manager.process_all_remaining_works(
                    error_flag=error_flag, error_message=error_message
                )
                self.logger.info(
                    "All remaining works marked to process", {"prefix": LOG_PREFIX}
                )
            except Exception as cleanup_err:
                self.logger.error(
                    "Error during cleanup",
                    meta={"prefix": LOG_PREFIX, "error": str(cleanup_err)},
                )

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
