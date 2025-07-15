"""Core connector as defined in the OpenCTI connector template."""

import asyncio
from typing import TYPE_CHECKING, Optional

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

            try:
                error_result = asyncio.run(self._process_gti_imports(gti_config))
                if error_result:
                    error_message = error_result
                    error_flag = True
            except (KeyboardInterrupt, asyncio.CancelledError):
                raise KeyboardInterrupt("GTI imports processing interrupted") from None

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

    async def _process_gti_imports(self, gti_config: GTIConfig) -> Optional[str]:
        """Process GTI imports either in parallel or sequentially based on configuration."""
        enable_parallelism = True

        reports_enabled = gti_config.import_reports
        threat_actors_enabled = gti_config.import_threat_actors
        malware_families_enabled = gti_config.import_malware_families

        if (
            not reports_enabled
            and not threat_actors_enabled
            and not malware_families_enabled
        ):
            self._logger.info(
                f"{LOG_PREFIX} No GTI imports are enabled in configuration"
            )
            return None

        try:
            if enable_parallelism and (
                reports_enabled or threat_actors_enabled or malware_families_enabled
            ):
                return await self._process_gti_parallel(gti_config)
            else:
                return await self._process_gti_sequential(
                    gti_config,
                    reports_enabled,
                    threat_actors_enabled,
                    malware_families_enabled,
                )
        except (KeyboardInterrupt, asyncio.CancelledError):
            self._logger.info(
                f"{LOG_PREFIX} GTI imports processing interrupted by user"
            )
            raise
        except Exception as e:
            error_msg = f"Unexpected error in GTI imports processing: {str(e)}"
            self._logger.error(f"{LOG_PREFIX} {error_msg}")
            return error_msg

    async def _process_gti_parallel(self, gti_config: GTIConfig) -> Optional[str]:
        """Process GTI imports in parallel."""
        enabled_imports = []
        if gti_config.import_reports:
            enabled_imports.append("reports")
        if gti_config.import_threat_actors:
            enabled_imports.append("threat_actors")
        if gti_config.import_malware_families:
            enabled_imports.append("malware_families")

        self._logger.info(
            f"{LOG_PREFIX} Starting parallel processing of: {', '.join(enabled_imports)}"
        )

        tasks = []

        if gti_config.import_reports:
            reports_task = asyncio.create_task(
                self._process_gti_reports(gti_config), name="reports"
            )
            tasks.append(reports_task)

        if gti_config.import_threat_actors:
            threat_actors_task = asyncio.create_task(
                self._process_gti_threat_actors(gti_config), name="threat_actors"
            )
            tasks.append(threat_actors_task)

        if gti_config.import_malware_families:
            malware_families_task = asyncio.create_task(
                self._process_gti_malware_families(gti_config), name="malware_families"
            )
            tasks.append(malware_families_task)

        any_error = False
        first_error = None

        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)

            for task in done:
                task_name = task.get_name()
                try:
                    result = task.result()
                    self._logger.info(f"{LOG_PREFIX} {task_name} processing completed")

                    if result:
                        if not any_error:
                            first_error = f"Error in {task_name} processing: {result}"
                            any_error = True

                except Exception as e:
                    error_msg = f"Error in {task_name} processing: {str(e)}"
                    self._logger.error(f"{LOG_PREFIX} {error_msg}")
                    if not any_error:
                        first_error = error_msg
                        any_error = True

        except (KeyboardInterrupt, asyncio.CancelledError):
            self._logger.info(
                f"{LOG_PREFIX} Parallel processing interrupted, cancelling tasks..."
            )

            for task in tasks:
                if not task.done():
                    task.cancel()

            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        return first_error if any_error else None

    async def _process_gti_sequential(
        self,
        gti_config: GTIConfig,
        reports_enabled: bool,
        threat_actors_enabled: bool,
        malware_families_enabled: bool,
    ) -> Optional[str]:
        """Process GTI imports sequentially."""
        self._logger.info(f"{LOG_PREFIX} Starting sequential processing...")

        try:
            if reports_enabled:
                self._logger.info(f"{LOG_PREFIX} Starting GTI reports processing...")
                error_result = await self._process_gti_reports(gti_config)
                if error_result:
                    return error_result
            else:
                self._logger.info(
                    f"{LOG_PREFIX} GTI reports import is disabled in configuration"
                )

            if threat_actors_enabled:
                self._logger.info(
                    f"{LOG_PREFIX} Starting GTI threat actors processing..."
                )
                error_result = await self._process_gti_threat_actors(gti_config)
                if error_result:
                    return error_result
            else:
                self._logger.info(
                    f"{LOG_PREFIX} GTI threat actors import is disabled in configuration"
                )

            if malware_families_enabled:
                self._logger.info(
                    f"{LOG_PREFIX} Starting GTI malware families processing..."
                )
                error_result = await self._process_gti_malware_families(gti_config)
                if error_result:
                    return error_result
            else:
                self._logger.info(
                    f"{LOG_PREFIX} GTI malware families import is disabled in configuration"
                )

            return None

        except (KeyboardInterrupt, asyncio.CancelledError):
            self._logger.info(f"{LOG_PREFIX} Sequential processing interrupted by user")
            raise
        except Exception as e:
            error_msg = f"Unexpected error in sequential processing: {str(e)}"
            self._logger.error(f"{LOG_PREFIX} {error_msg}")
            return error_msg

    async def _process_gti_reports(self, gti_config: GTIConfig) -> Optional[str]:
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
            await orchestrator.run_report(initial_state)
            return None

        except Exception as e:
            error_msg = f"GTI reports processing failed: {str(e)}"
            self._logger.error(f"{LOG_PREFIX} {error_msg}")
            return error_msg

    async def _process_gti_threat_actors(self, gti_config: GTIConfig) -> Optional[str]:
        """Process GTI threat actors using the orchestrator."""
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

            self._logger.info(f"{LOG_PREFIX} Starting GTI threat actors ingestion...")
            await orchestrator.run_threat_actor(initial_state)
            return None

        except Exception as e:
            error_msg = f"GTI threat actors processing failed: {str(e)}"
            self._logger.error(f"{LOG_PREFIX} {error_msg}")
            return error_msg

    async def _process_gti_malware_families(
        self, gti_config: GTIConfig
    ) -> Optional[str]:
        """Process GTI malware families using the orchestrator."""
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

            self._logger.info(
                f"{LOG_PREFIX} Starting GTI malware families ingestion..."
            )
            await orchestrator.run_malware_family(initial_state)
            return None

        except Exception as e:
            error_msg = f"GTI malware families processing failed: {str(e)}"
            self._logger.error(f"{LOG_PREFIX} {error_msg}")
            return error_msg

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
