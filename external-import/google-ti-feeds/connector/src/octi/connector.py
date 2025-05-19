"""Core connector as defined in the OpenCTI connector template."""

import asyncio
import sys
from typing import TYPE_CHECKING

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.pipeline_reports_orchestrator import (
    PipelineReportsOrchestrator,
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

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

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
        """Connector main process to collect intelligence.

        For now, it only imports reports from Google Threat Intelligence.
        But it can be extended to import other types of intelligence in the future.
        """
        error_flag = True
        split_work = self._config.connector_config.split_work
        try:
            gti_config = self._config.get_config_class(GTIConfig)
            if gti_config.import_reports:
                orchestrator = PipelineReportsOrchestrator(
                    gti_config=gti_config,
                    work_manager=self.work_manager,
                    tlp_level=self._config.connector_config.tlp_level.lower(),
                    batch_size=40,
                    flush_interval=300,
                    http_timeout=60,
                    max_failures=5,
                    cooldown_time=60,
                    max_requests=60,
                    period=60,
                    max_retries=5,
                    backoff=2,
                    logger=self._logger,
                    split_work=split_work,
                )
                loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(loop)
                    error_flag = loop.run_until_complete(orchestrator.run())
                except asyncio.CancelledError:
                    self._logger.info(
                        f"{LOG_PREFIX} Pipeline execution was cancelled.",
                        meta={"operation": "cancelled"},
                    )
                    error_flag = True
                finally:
                    try:
                        loop.run_until_complete(
                            asyncio.wait_for(orchestrator.shutdown(), timeout=120)
                        )
                    except (asyncio.TimeoutError, Exception) as e:
                        self._logger.error(
                            f"{LOG_PREFIX} Error during shutdown: {str(e)}",
                            meta={"error": str(e)},
                        )
                    loop.close()
        except (KeyboardInterrupt, SystemExit):
            self._logger.info(
                f"{LOG_PREFIX} Connector stopped...",
                {"connector_name": self._helper.connect_name},
            )
            sys.exit(0)
        except asyncio.CancelledError:
            self._logger.info(
                f"{LOG_PREFIX} Operation was cancelled.",
                {"connector_name": self._helper.connect_name},
            )
        except Exception as err:
            self._logger.error(
                f"{LOG_PREFIX} An unexpected error occurred.", meta={"error": str(err)}
            )
        finally:
            self._logger.info(
                f"{LOG_PREFIX} Connector stopped...",
                {"connector_name": self._helper.connect_name},
            )
            self.work_manager.process_all_remaining_works(error_flag=error_flag)
            self._logger.info(f"{LOG_PREFIX} All remaining works marked to process.")

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
