"""Pipeline orchestration to fetch, process and ingest reports and related entities from Google Threat Intelligence."""

import asyncio
import logging
from typing import TYPE_CHECKING, Any, List, Optional
from uuid import uuid4

from connector.src.custom.exceptions.gti_batch_error import GTIBatchError
from connector.src.custom.exceptions.gti_fetching_error import GTIFetchingError
from connector.src.custom.exceptions.gti_processing_error import GTIProcessingError
from connector.src.custom.fetchers.gti_reports.fetch_reports import FetchReports
from connector.src.custom.interfaces.base_fetcher import BaseFetcher
from connector.src.custom.interfaces.base_processor import BaseProcessor
from connector.src.custom.meta.gti_reports.reports_meta import (
    EVENT_MAP,
    FINAL_BROKER,
    LAST_INGESTED_REPORT_MODIFICATION_DATE_STATE_KEY,
    LAST_WORK_START_DATE_STATE_KEY,
    SENTINEL,
)
from connector.src.custom.processors.gti_reports.process_malware_families import (
    ProcessMalwareFamilies,
)
from connector.src.custom.processors.gti_reports.process_reports import ProcessReports
from connector.src.custom.processors.gti_reports.process_threat_actors import (
    ProcessThreatActors,
)
from connector.src.octi.batch_collector import BatchCollector
from connector.src.octi.pubsub import broker
from connector.src.stix.octi.models.identity_organization_model import (
    OctiOrganizationModel,
)
from connector.src.stix.octi.models.tlp_marking_model import TLPMarkingModel
from connector.src.utils.api_engine.aio_http_client import AioHttpClient
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.circuit_breaker import CircuitBreaker
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError
from connector.src.utils.api_engine.retry_request_strategy import RetryRequestStrategy

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.custom.configs.gti_config import GTIConfig
    from connector.src.octi.work_manager import WorkManager

LOG_PREFIX = "[Pipeline Reports Orchestrator]"


class PipelineReportsOrchestrator:
    """Pipeline orchestration to fetch, process and ingest reports and related entities from Google Threat Intelligence."""

    def __init__(
        self,
        gti_config: "GTIConfig",
        work_manager: "WorkManager",
        tlp_level: str,
        batch_size: int,
        flush_interval: int,
        http_timeout: int = 60,
        max_failures: int = 5,
        cooldown_time: int = 60,
        max_requests: int = 10,
        period: int = 60,
        max_retries: int = 5,
        backoff: int = 2,
        logger: Optional["Logger"] = None,
        split_work: Optional[bool] = False,
    ) -> None:
        """Initialize the pipeline orchestration.

        Args:
            gti_config (GTIConfig): Configuration for Google Threat Intelligence.
            work_manager (WorkManager): Work manager instance.
            tlp_level (str): TLP level for the pipeline.
            batch_size (int): Batch size for processing.
            flush_interval (int): Interval for flushing data in seconds.
            http_timeout (int, optional): Timeout for HTTP requests. Defaults to 60.
            max_failures (int, optional): Maximum number of failures before circuit breaker trips. Defaults to 5.
            cooldown_time (int, optional): Cooldown time for circuit breaker. Defaults to 60.
            max_requests (int, optional): Maximum number of requests per period. Defaults to 10.
            period (int, optional): Period for rate limiting. Defaults to 60.
            max_retries (int, optional): Maximum number of retries for failed requests. Defaults to 5.
            backoff (int, optional): Backoff factor for retry strategy. Defaults to 2.
            logger (Optional[Logger], optional): Logger instance. Defaults to None.
            split_work (bool, optional): Whether to split work into smaller chunks. Defaults to False.

        """
        self._gti_config = gti_config
        self._work_manager = work_manager
        self.tlp_level = tlp_level
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.http_timeout = http_timeout
        self.max_failures = max_failures
        self.cooldown_time = cooldown_time
        self.max_requests = max_requests
        self.period = period
        self.max_retries = max_retries
        self.backoff = backoff
        self._logger = logger or logging.getLogger(__name__)
        self.split_work = split_work

        http_client = AioHttpClient(
            default_timeout=self.http_timeout, logger=self._logger
        )
        breaker = CircuitBreaker(
            max_failures=self.max_failures, cooldown_time=self.cooldown_time
        )
        limiter_config = {
            "key": f"gti-api-{uuid4()}",
            "max_requests": self.max_requests,
            "period": self.period,
        }
        retry_request_strategy = RetryRequestStrategy(
            http=http_client,
            breaker=breaker,
            limiter=limiter_config,
            hooks=None,
            max_retries=self.max_retries,
            backoff=self.backoff,
            logger=self._logger,
        )
        self.api_client = ApiClient(
            strategy=retry_request_strategy, logger=self._logger
        )
        self.work_counter = 0
        self._running_tasks: List[asyncio.Task] = []  # type: ignore[type-arg]

        if not self.split_work:
            self._logger.info(
                "Starting Google Threat Intel Feeds - Reports in a unique work."
            )
            self.work_id = self._work_manager.initiate_work(
                name="Google Threat Intel Feeds - Reports"
            )

    def _orchestration(self) -> None:
        """Manage the orchestration pipeline."""
        state = self._work_manager.get_state()
        self.fetchers: List[BaseFetcher] = [
            FetchReports(self._gti_config, self.api_client, state, self._logger)
        ]

        self.processors: List[BaseProcessor] = [
            ProcessReports(self.organization, self.tlp_marking, self._logger),
            ProcessMalwareFamilies(self.organization, self.tlp_marking, self._logger),
            ProcessThreatActors(self.organization, self.tlp_marking, self._logger),
            # ProcessAttackTechniques(),
            # ProcessVulnerabilities(),
            # ProcessIOCs(),
        ]

    def _setup_batch_collector(self) -> None:
        """Set the batch collector."""
        self.batch_collector = BatchCollector(
            topic=FINAL_BROKER,
            batch_size=self.batch_size,
            flush_interval=self.flush_interval,
            send_func=self.send_batch,
            sentinel_obj=SENTINEL,
        )

        flush_interval_str = ""
        interval = self.flush_interval
        if interval >= 86400:
            days = interval // 86400
            interval %= 86400
            flush_interval_str += f"{days} {'day' if days == 1 else 'days'}"
        if interval >= 3600:
            hours = interval // 3600
            interval %= 3600
            if flush_interval_str:
                flush_interval_str += " "
            flush_interval_str += f"{hours} {'hour' if hours == 1 else 'hours'}"
        if interval >= 60:
            minutes = interval // 60
            interval %= 60
            if flush_interval_str:
                flush_interval_str += " "
            flush_interval_str += f"{minutes} {'minute' if minutes == 1 else 'minutes'}"
        if interval > 0 or not flush_interval_str:
            if flush_interval_str:
                flush_interval_str += " "
            flush_interval_str += (
                f"{interval} {'second' if interval == 1 else 'seconds'}"
            )

        self._logger.info(
            f"{LOG_PREFIX} Batch collector setup complete, with batch size of {self.batch_size} reports or a flush interval of {flush_interval_str}."
        )

    async def _create_tlp_marking(self) -> bool:
        try:
            self.tlp_marking = TLPMarkingModel(
                level=self.tlp_level.lower()
            ).to_stix2_object()
            self._logger.info(
                f"{LOG_PREFIX} Create the TLP marking for Google TI Feeds."
            )
            await broker.publish(FINAL_BROKER, self.tlp_marking)
            return True
        except Exception as e:
            self._logger.error(f"{LOG_PREFIX} Failed to create TLP marking: {str(e)}")
            return False

    async def _create_organization(self) -> bool:
        try:
            name = "Google TI Feeds"
            self.organization = OctiOrganizationModel.create(
                name=name,
                description="Google Threat Intelligence Feeds.",
                contact_information="https://gtidocs.virustotal.com",
                organization_type="vendor",
                reliability=None,
                aliases=["GTI"],
            ).to_stix2_object()
            self._logger.info(
                f"{LOG_PREFIX} Create the organization entity for Google TI Feeds."
            )
            await broker.publish(FINAL_BROKER, self.organization)
            return True
        except Exception as e:
            self._logger.error(f"{LOG_PREFIX} Failed to create organization: {str(e)}")
            return False

    async def send_batch(self, batch: List[Any]) -> None:
        """Send a batch of entities for ingestion.

        Args:
            batch (List[Any]): The batch of entities to send for ingestion.

        """
        if not batch:
            self._logger.info(f"{LOG_PREFIX} No entities to send for ingestion.")
            return

        if self.split_work:
            self.work_counter += 1
            self._logger.info(
                f"{LOG_PREFIX} Send a batch of {len(batch)} entities for ingestion."
            )
            self.work_id = self._work_manager.initiate_work(
                name="Google Threat Intel Feeds - Reports ",
                work_counter=self.work_counter,
            )

        self._work_manager.send_bundle(work_id=self.work_id, bundle=batch)

        most_recent = None
        for entity in batch:
            if entity.get("type") == "report":
                if not most_recent or entity.get("modified", "") > most_recent:
                    most_recent = entity.get("modified")
                event = asyncio.Event()
                EVENT_MAP[entity["id"]] = event
                event.set()

        if most_recent:
            self._logger.info(
                f"{LOG_PREFIX} Updating state with most the most recent report modification date."
            )
            self._work_manager.update_state(
                state_key=LAST_INGESTED_REPORT_MODIFICATION_DATE_STATE_KEY,
                date_str=most_recent,
            )
        self._work_manager.update_state(state_key=LAST_WORK_START_DATE_STATE_KEY)

        if self.split_work:
            self._work_manager.work_to_process(work_id=self.work_id)
            self._logger.info(
                f"{LOG_PREFIX} Batch of entities sent in queue for ingestion."
            )

    async def shutdown(self, timeout: int = 60) -> None:
        """Gracefully shutdown the pipeline.

        Args:
            timeout (int): The maximum time in seconds to wait for the pipeline to shutdown.

        """
        self._logger.info(f"{LOG_PREFIX} Shutdown the pipeline.")

        phase_timeout = min(timeout // 2, 60)

        for task in self._running_tasks:
            if not task.done():
                task.cancel()

        try:
            done, pending = await asyncio.wait(
                [t for t in self._running_tasks if not t.done()],
                timeout=phase_timeout,
                return_when=asyncio.ALL_COMPLETED,
            )

            for task in pending:
                self._logger.warning(
                    f"{LOG_PREFIX} Task {task} did not complete within the timeout, cancelling."
                )
                if not task.done():
                    task.cancel()
        except Exception as e:
            self._logger.error(  # type: ignore[call-arg]
                f"{LOG_PREFIX} Error while waiting for tasks to complete: {str(e)}",
                meta={"error": str(e)},
            )

        try:
            await asyncio.wait_for(
                self.batch_collector.shutdown(), timeout=phase_timeout
            )
        except (asyncio.TimeoutError, Exception) as e:
            self._logger.error(  # type: ignore[call-arg]
                f"{LOG_PREFIX} Error or timeout shutting down batch collector: {str(e)}",
                meta={"error": str(e)},
            )

        self._logger.info(f"{LOG_PREFIX} Pipeline shutdown complete.")

        try:
            self._work_manager.process_all_remaining_works()
        except Exception as e:
            self._logger.error(  # type: ignore[call-arg]
                f"{LOG_PREFIX} Error processing remaining works: {str(e)}",
                meta={"error": str(e)},
            )

    async def run(self) -> bool:
        """Run the pipeline to fetch, process, ingest reports and related entities.

        Returns:
            Bool: False if no errors occurred during the pipeline execution.

        Raises:
            GTIBatchError: If batch processing failed.
            GTIFetchingError: If fetching failed.
            GTIProcessingError: If processing failed.
            ApiNetworkError: If a persistent network connectivity issue occurred.
            Exception: For any other unexpected errors during execution.

        """
        await self._initialize_pipeline()

        fetch_successes = await self._execute_fetch_tasks()

        await broker.publish(FINAL_BROKER, SENTINEL)
        batch_success = await self._running_tasks[0]

        proc_successes = await self._process_processor_results()

        return await self._validate_pipeline_success(
            batch_success, fetch_successes, proc_successes
        )

    async def _initialize_pipeline(self) -> None:
        """Initialize the pipeline components and create required tasks."""
        self._setup_batch_collector()
        batch_task = asyncio.create_task(self.batch_collector.run())
        self._running_tasks = [batch_task]

        await asyncio.sleep(0.5)

        self.org_success = await self._create_organization()
        self.tlp_success = await self._create_tlp_marking()
        self._orchestration()

        proc_tasks = [asyncio.create_task(p.process()) for p in self.processors]
        self._running_tasks.extend(proc_tasks)

        fetch_tasks = [asyncio.create_task(f.fetch()) for f in self.fetchers]
        self._running_tasks.extend(fetch_tasks)

    async def _execute_fetch_tasks(self) -> List[bool]:
        """Execute and monitor fetch tasks with timeout handling.

        Returns:
            List[bool]: List of fetch task success results

        Raises:
            GTIFetchingError: If fetching times out
            ApiNetworkError: If network connectivity issues are detected

        """
        fetch_tasks = self._running_tasks[1 + len(self.processors) :]

        try:
            done, pending = await asyncio.wait(
                fetch_tasks, return_when=asyncio.ALL_COMPLETED
            )

            for task in pending:
                self._logger.warning(
                    f"{LOG_PREFIX} Fetch task {task} didn't complete within timeout, cancelling."
                )
                task.cancel()

            fetch_results = [
                task.result() if not task.exception() else task.exception()
                for task in done
            ]

            for result in fetch_results:
                if isinstance(result, ApiNetworkError):
                    self._logger.error(
                        f"{LOG_PREFIX} Network connectivity issue detected: {str(result)}"
                    )
                    raise result

            return [
                result is True
                for result in fetch_results
                if not isinstance(result, Exception)
            ]
        except asyncio.TimeoutError:
            self._logger.error(
                f"{LOG_PREFIX} Fetch operations timed out after 600 seconds. This may indicate network issues."
            )
            for task in fetch_tasks:
                if not task.done():
                    task.cancel()
            raise GTIFetchingError(f"{LOG_PREFIX} Fetching timed out.") from None

    async def _process_processor_results(self) -> List[bool]:
        """Process the results from processor tasks.

        Returns:
            List[bool]: List of processor task success results

        """
        proc_tasks = self._running_tasks[1 : 1 + len(self.processors)]
        proc_results = await asyncio.gather(*proc_tasks, return_exceptions=True)

        return [
            result is True
            for result in proc_results
            if not isinstance(result, Exception)
        ]

    async def _validate_pipeline_success(
        self,
        batch_success: Any,
        fetch_successes: List[bool],
        proc_successes: List[bool],
    ) -> bool:
        """Validate the overall success of the pipeline and raise appropriate errors if needed.

        Args:
            batch_success: Result of the batch task
            fetch_successes: List of fetch task success results
            proc_successes: List of processor task success results

        Returns:
            bool: False if no errors occurred

        Raises:
            GTIBatchError: If batch processing failed
            GTIFetchingError: If fetching failed
            GTIProcessingError: If processing failed

        """
        all_success = (
            self.org_success
            and self.tlp_success
            and batch_success.success
            and all(fetch_successes)
            and all(proc_successes)
            and len(fetch_successes) == len(self.fetchers)
            and len(proc_successes) == len(self.processors)
        )

        if not all_success:
            if not batch_success.success:
                raise GTIBatchError(
                    f"{LOG_PREFIX} Batch processing failed. {batch_success.error}"
                ) from None
            elif not all(fetch_successes):
                raise GTIFetchingError(f"{LOG_PREFIX} Fetching failed.") from None
            elif not all(proc_successes):
                raise GTIProcessingError(f"{LOG_PREFIX} Processing failed.") from None

        return False
