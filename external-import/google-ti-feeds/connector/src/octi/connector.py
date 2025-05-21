"""Core connector as defined in the OpenCTI connector template."""

import asyncio
from typing import TYPE_CHECKING
from uuid import uuid4

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.convert_to_stix import ConvertToSTIX
from connector.src.custom.exceptions import (
    GTIApiClientError,
    GTIAsyncError,
    GTIEntityConversionError,
    GTIPartialDataProcessingError,
    GTIStateManagementError,
    GTIWorkProcessingError,
)
from connector.src.custom.fetch_all import FetchAll
from connector.src.octi.work_manager import WorkManager
from connector.src.utils.api_engine.aio_http_client import AioHttpClient
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.circuit_breaker import CircuitBreaker
from connector.src.utils.api_engine.retry_request_strategy import RetryRequestStrategy

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
        error_flag = False
        error_message = None
        try:
            gti_config = self._config.get_config_class(GTIConfig)
            if gti_config.import_reports:
                error_message = self._process_reports()
                if error_message:
                    error_flag = True
        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped due to user interrupt"
            self._logger.info(
                f"{LOG_PREFIX} {error_message}...",
                {"connector_name": self._helper.connect_name},
            )
            error_flag = True
        except asyncio.CancelledError:
            error_message = "Operation was cancelled"
            self._logger.info(
                f"{LOG_PREFIX} {error_message}.",
                {"connector_name": self._helper.connect_name},
            )
            error_flag = True
        except GTIWorkProcessingError as work_err:
            error_message = f"Work processing error: {str(work_err)}"
            self._logger.error(
                f"{LOG_PREFIX} {error_message}",
                meta={
                    "error": str(work_err),
                    "work_id": getattr(work_err, "work_id", None),
                },
            )
            error_flag = True
        except Exception as err:
            error_message = f"An unexpected error occurred: {str(err)}"
            self._logger.error(
                f"{LOG_PREFIX} {error_message}", meta={"error": str(err)}
            )
            error_flag = True
        finally:
            self._logger.info(
                f"{LOG_PREFIX} Connector stopped...",
                {"connector_name": self._helper.connect_name},
            )
            self.work_manager.process_all_remaining_works(
                error_flag=error_flag, error_message=error_message
            )
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

    def _process_reports(self):
        """Process GTI reports and related entities.

        Returns:
            str: Error message if an error occurred, None otherwise
        """
        error_flag = False
        error_message = None
        self._logger.info(f"{LOG_PREFIX} Starting Google Threat Intel Feeds process")

        reports = []
        related_entities = {}
        latest_modified_date = None
        fetch_task = None

        try:
            api_client = self._setup_api_client()
            work_id = self.work_manager.initiate_work(
                name="Google Threat Intel Feeds - Reports"
            )
            state = self.work_manager.get_state()
            gti_config = self._config.get_config_class(GTIConfig)

            fetcher, converter = self._create_fetcher_and_converter(
                api_client, state, gti_config
            )

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:

                fetch_task = asyncio.ensure_future(fetcher.fetch_all_data(), loop=loop)
                self._logger.info(
                    f"{LOG_PREFIX} Fetching data from Google Threat Intelligence API"
                )

                try:

                    reports, related_entities, latest_modified_date = (
                        loop.run_until_complete(fetch_task)
                    )
                    self._logger.info(
                        f"{LOG_PREFIX} Fetched {len(reports)} reports with related entities"
                    )

                    if not reports:
                        self._logger.info(f"{LOG_PREFIX} No reports to process")
                        return

                    self._process_fetched_data(
                        work_id,
                        reports,
                        related_entities,
                        latest_modified_date,
                        converter,
                    )
                except (KeyboardInterrupt, SystemExit):
                    error_flag, error_message = self._handle_keyboard_interrupt(
                        loop, fetch_task, work_id, converter
                    )

            except asyncio.CancelledError:
                self._logger.info(
                    f"{LOG_PREFIX} Operation was cancelled.",
                    meta={"operation": "cancelled"},
                )

                error_message = self._try_process_partial_data(
                    fetch_task, work_id, converter, "cancellation"
                )
            except GTIEntityConversionError as conversion_err:
                error_message = f"Entity conversion error: {str(conversion_err)}"
                self._logger.error(
                    f"{LOG_PREFIX} {error_message}",
                    meta={
                        "error": str(conversion_err),
                        "entity_type": getattr(conversion_err, "entity_type", None),
                    },
                )
                error_flag = True

                partial_error = self._try_process_partial_data(
                    fetch_task, work_id, converter, "conversion_error"
                )
                if partial_error:
                    error_message = f"{error_message}. Additionally: {partial_error}"
            except Exception as e:
                error_message = f"An error occurred while processing the work: {str(e)}"
                self._logger.error(
                    f"{LOG_PREFIX} An error occurred while processing the work.",
                    meta={"error": str(e)},
                )
                error_flag = True

                partial_error = self._try_process_partial_data(
                    fetch_task, work_id, converter, "exception"
                )
                if partial_error:
                    error_message = f"{error_message}. Additionally: {partial_error}"
        except GTIApiClientError as api_err:
            error_message = f"API client setup error: {str(api_err)}"
            self._logger.error(
                f"{LOG_PREFIX} {error_message}",
                meta={
                    "error": str(api_err),
                    "component": getattr(api_err, "client_component", None),
                },
            )
            error_flag = True

            work_id = work_id if "work_id" in locals() else None
        finally:
            self._cleanup_event_loop(loop)

        self.work_manager.work_to_process(
            work_id=work_id,
            error_flag=error_flag,
            error_message=error_message if error_flag else None,
        )
        return error_message

    def _setup_api_client(self):
        """Set up the API client with retry strategy and circuit breaker.

        Returns:
            ApiClient: Configured API client

        Raises:
            GTIApiClientError: If there's an error setting up the API client
        """
        try:
            http_client = AioHttpClient(default_timeout=120, logger=self._logger)
            breaker = CircuitBreaker(max_failures=5, cooldown_time=60)
            limiter_config = {
                "key": f"gti-api-{uuid4()}",
                "max_requests": 60,
                "period": 60,
            }
            retry_strategy = RetryRequestStrategy(
                http=http_client,
                breaker=breaker,
                limiter=limiter_config,
                hooks=None,
                max_retries=5,
                backoff=2,
                logger=self._logger,
            )
            return ApiClient(strategy=retry_strategy, logger=self._logger)
        except Exception as e:
            raise GTIApiClientError(
                f"Failed to set up API client: {str(e)}", "setup"
            ) from e

    def _create_fetcher_and_converter(self, api_client, state, gti_config):
        """Create fetcher and converter instances.

        Args:
            api_client: The API client for fetching data
            state: Current connector state
            gti_config: GTI configuration

        Returns:
            tuple: (FetchAll instance, ConvertToSTIX instance)
        """
        fetcher = FetchAll(gti_config, api_client, state, self._logger)
        converter = ConvertToSTIX(
            tlp_level=self._config.connector_config.tlp_level.lower(),
            logger=self._logger,
        )
        return fetcher, converter

    def _handle_keyboard_interrupt(self, loop, fetch_task, work_id, converter):
        """Handle keyboard interrupt by processing partial data.

        Args:
            loop: Event loop
            fetch_task: The fetch task
            work_id: Work ID
            converter: STIX converter

        Returns:
            tuple: (error_flag, error_message) where error_flag is a bool and error_message is a string or None

        Raises:
            GTIAsyncError: If there's an error during async operation handling
        """
        error_message = "User interrupted the connector operation"
        self._logger.info(f"{LOG_PREFIX} Gracefully cancelling fetch operation...")
        fetch_task.cancel()
        try:

            try:

                if fetch_task.done() and not fetch_task.exception():
                    reports, related_entities, latest_modified_date = (
                        fetch_task.result()
                    )
                else:

                    reports, related_entities, latest_modified_date = (
                        loop.run_until_complete(
                            asyncio.wait_for(asyncio.shield(fetch_task), 2.0)
                        )
                    )

                if reports:
                    self._logger.info(
                        f"{LOG_PREFIX} Processing {len(reports)} reports fetched before cancellation"
                    )
                    self._process_fetched_data(
                        work_id,
                        reports,
                        related_entities,
                        latest_modified_date,
                        converter,
                    )
            except (asyncio.CancelledError, asyncio.TimeoutError) as err:
                error_message = f"Could not retrieve partial results: {str(err)}"
                self._logger.info(f"{LOG_PREFIX} {error_message}")
                raise GTIAsyncError(
                    error_message, "interrupt_handler", {"work_id": work_id}
                ) from err
        except (asyncio.CancelledError, asyncio.TimeoutError) as e:
            error_message = (
                f"Async operation failed during interrupt handling: {str(e)}"
            )
            raise GTIAsyncError(error_message, "interrupt_handler") from e
        except GTIAsyncError:

            raise
        except Exception as e:
            error_message = f"Unexpected error during interrupt handling: {str(e)}"
            raise GTIAsyncError(error_message, "interrupt_handler") from e
        return True, error_message

    def _try_process_partial_data(self, fetch_task, work_id, converter, source):
        """Try to process any data fetched before an error or cancellation.

        Args:
            fetch_task: The fetch task that might have partial results
            work_id: The work ID
            converter: STIX converter
            source: String describing the source of interruption ("cancellation" or "exception")

        Returns:
            str: Optional error message if an error occurred
        """
        error_message = None
        try:
            if fetch_task and fetch_task.done() and not fetch_task.exception():
                reports, related_entities, latest_modified_date = fetch_task.result()
                self._process_fetched_data(
                    work_id, reports, related_entities, latest_modified_date, converter
                )
        except Exception as process_err:
            error_message = (
                f"Error processing partial data after {source}: {str(process_err)}"
            )
            self._logger.error(
                f"{LOG_PREFIX} {error_message}",
                meta={"error": str(process_err)},
            )
            reports_count = len(reports) if "reports" in locals() else None
            raise GTIPartialDataProcessingError(
                str(process_err),
                work_id,
                source,
                reports_count,
                {"exception_type": type(process_err).__name__},
            ) from process_err
        return error_message

    def _cleanup_event_loop(self, loop):
        """Clean up the event loop by cancelling pending tasks and closing it.

        Args:
            loop: The event loop to clean up
        """
        pending = asyncio.all_tasks(loop=loop)
        for task in pending:
            task.cancel()

        if pending:
            try:
                loop.run_until_complete(asyncio.wait(pending, timeout=1.0))
            except (asyncio.CancelledError, Exception):
                pass

        loop.close()

    def _process_fetched_data(
        self, work_id, reports, related_entities, latest_modified_date, converter
    ):
        """Process fetched data by converting to STIX and sending to OpenCTI.

        Args:
            work_id: The ID of the current work
            reports: List of report data
            related_entities: Dictionary of related entities
            latest_modified_date: Latest modification date of reports
            converter: ConvertToSTIX instance

        Raises:
            GTIEntityConversionError: If there's an error converting data to STIX
            GTIWorkProcessingError: If there's an error processing the work
            GTIStateManagementError: If there's an error updating the state
        """
        if not reports:
            self._logger.info(f"{LOG_PREFIX} No reports to process")
            return

        try:
            self._logger.info(f"{LOG_PREFIX} Converting data to STIX format")
            stix_objects = converter.convert_all_data(reports, related_entities)

            self._logger.info(
                f"{LOG_PREFIX} Sending {len(stix_objects)} STIX objects to OpenCTI"
            )
            try:
                self.work_manager.send_bundle(work_id=work_id, bundle=stix_objects)
            except Exception as bundle_err:
                raise GTIWorkProcessingError(
                    f"Failed to send bundle: {str(bundle_err)}",
                    work_id,
                    {"stix_objects_count": len(stix_objects)},
                ) from bundle_err

            try:

                converter_latest_date = converter.get_latest_report_date()
                if converter_latest_date:
                    self.work_manager.update_state(
                        state_key="last_work_date", state_value=converter_latest_date
                    )

                elif latest_modified_date:
                    self.work_manager.update_state(
                        state_key="last_work_date", state_value=latest_modified_date
                    )
                else:
                    self.work_manager.update_state(state_key="last_work_date")
            except Exception as state_err:
                raise GTIStateManagementError(
                    f"Failed to update state: {str(state_err)}", "last_work_date"
                ) from state_err
        except GTIEntityConversionError:

            raise
        except Exception as e:
            if isinstance(e, (GTIWorkProcessingError, GTIStateManagementError)):

                raise

            raise GTIWorkProcessingError(
                f"Failed to process fetched data: {str(e)}",
                work_id,
                {"reports_count": len(reports)},
            ) from e
