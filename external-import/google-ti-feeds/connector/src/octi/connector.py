"""Core connector as defined in the OpenCTI connector template."""

import asyncio
from typing import TYPE_CHECKING

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions.connector_errors.gti_work_processing_error import (
    GTIWorkProcessingError,
)
from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from connector.src.octi.work_manager import WorkManager

if TYPE_CHECKING:
    from connector.src.octi.global_config import GlobalConfig
    from pycti import OpenCTIConnectorHelper as OctiHelper  # type: ignore


LOG_PREFIX = "[Connector]"


class Connector:
    """Specifications of the external import connector.

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.
    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self, config: "GlobalConfig", helper: "OctiHelper") -> None:
        """Initialize the connector with necessary configuration environment variables
        and the helper to use.

        Arguments:

        ----------
        config : GlobalConfig
            Configuration object containing the connector's configuration variables.
        helper : OpenCTIConnectorHelper
            This is the helper from the OpenCTI client python library.

        """
        self._config = config
        self._helper = helper
        self._logger = self._helper.connector_logger
        self.work_manager = WorkManager(self._config, self._helper, self._logger)

    def _process_callback(self) -> None:
        """Connector main process to collect intelligence using GTI orchestrator."""
        error_flag = False
        error_message = None

        try:
            try:
                gti_config = self._config.get_config_class(GTIConfig)
            except Exception as config_err:
                raise GTIConfigurationError(
                    f"Failed to load GTI configuration: {str(config_err)}"
                ) from config_err

            if gti_config.import_reports:
                self._logger.info(f"{LOG_PREFIX} Starting GTI reports processing...")
                error_message = asyncio.run(self._process_gti_reports(gti_config))
                if error_message:
                    error_flag = True
            else:
                self._logger.info(
                    f"{LOG_PREFIX} GTI reports import is disabled in configuration"
                )

        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped due to user interrupt"
            self._logger.info(
                f"{LOG_PREFIX} {error_message}...",
                {"connector_name": self._helper.connect_name},
            )
            error_flag = True
            raise

        except asyncio.CancelledError:
            error_message = "Operation was cancelled"
            self._logger.info(
                f"{LOG_PREFIX} {error_message}.",
                {"connector_name": self._helper.connect_name},
            )
            error_flag = True

        except GTIConfigurationError as config_err:
            error_message = f"Configuration error: {str(config_err)}"
            self._logger.error(
                f"{LOG_PREFIX} {error_message}",
                meta={"error": str(config_err)},
            )
            error_flag = True

        except GTIWorkProcessingError as work_err:
            error_message = f"Work processing error: {str(work_err)}"
            work_id = getattr(
                work_err, "work_id", self.work_manager.get_current_work_id()
            )
            self._logger.warning(
                f"{LOG_PREFIX} {error_message}",
                meta={
                    "error": str(work_err),
                    "work_id": work_id,
                },
            )
            error_flag = True

        except Exception as err:
            error_message = f"Unexpected error: {str(err)}"
            self._logger.error(
                f"{LOG_PREFIX} {error_message}", meta={"error": str(err)}
            )
            error_flag = True

        finally:
            self._logger.info(
                f"{LOG_PREFIX} Connector stopped...",
                {"connector_name": self._helper.connect_name},
            )
            try:
                self.work_manager.process_all_remaining_works(
                    error_flag=error_flag, error_message=error_message
                )
                self._logger.info(
                    f"{LOG_PREFIX} All remaining works marked to process."
                )
            except Exception as cleanup_err:
                self._logger.error(
                    f"{LOG_PREFIX} Error during cleanup: {str(cleanup_err)}",
                    meta={"error": str(cleanup_err)},
                )

    async def _process_gti_reports(self, gti_config: GTIConfig) -> None:
        """Process GTI reports using the orchestrator."""
        try:
            from connector.src.custom.orchestrators.orchestrator import (
                Orchestrator,
            )

            orchestrator = Orchestrator(
                work_manager=self.work_manager,
                logger=self._logger,
                config=gti_config,
                tlp_level=self._config.connector_config.tlp_level,
            )

            initial_state = self._helper.get_state()
            self._logger.info(f"{LOG_PREFIX} Retrieved state: {initial_state}")

            self._logger.info(f"{LOG_PREFIX} Starting GTI full ingestion...")
            await orchestrator.run(initial_state)

        except Exception as e:
            self._logger.error(f"{LOG_PREFIX} GTI reports processing failed: {str(e)}")

    def run(self) -> None:
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
            message_callback=self._process_callback,
            duration_period=self._config.connector_config.duration_period,
        )
