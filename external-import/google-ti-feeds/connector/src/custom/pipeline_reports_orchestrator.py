"""Pipeline orchestration to fetch, process and ingest reports and related entities from Google Threat Intelligence."""
import asyncio
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import uuid4

from connector.src.custom.batch_collector import BatchCollector
from connector.src.custom.fetchers.fetch_reports import FetchReports
from connector.src.custom.interfaces.base_fetcher import BaseFetcher
from connector.src.custom.interfaces.base_processor import BaseProcessor
from connector.src.custom.pubsub import broker
from connector.src.custom.reports_constants import SENTINEL, PREFIX_BROKER
from connector.src.utils.api_engine.aio_http_client import AioHttpClient
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.circuit_breaker import CircuitBreaker
from connector.src.utils.api_engine.retry_request_strategy import RetryRequestStrategy
from connector.src.custom.processors.process_reports import ProcessReports

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.octi.work_manager import WorkManager


class PipelineReportsOrchestrator:
    """Pipeline orchestration to fetch, process and ingest reports and related entities from Google Threat Intelligence."""

    def __init__(self, gti_config: Dict[str, Any], work_manager: "WorkManager", http_timeout: int = 60, max_failures: int = 5, cooldown_time: int = 60, max_requests: int = 10, period: int = 60, max_retries: int = 5, backoff: int = 2, logger: Optional["Logger"] = None) -> None:
        """Initialize the pipeline orchestration.

        Args:
            gti_config (GTIConfig): Configuration for Google Threat Intelligence.
            work_manager (WorkManager): Work manager instance.
            http_timeout (int, optional): Timeout for HTTP requests. Defaults to 60.
            max_failures (int, optional): Maximum number of failures before circuit breaker trips. Defaults to 5.
            cooldown_time (int, optional): Cooldown time for circuit breaker. Defaults to 60.
            max_requests (int, optional): Maximum number of requests per period. Defaults to 10.
            period (int, optional): Period for rate limiting. Defaults to 60.
            max_retries (int, optional): Maximum number of retries for failed requests. Defaults to 5.
            backoff (int, optional): Backoff factor for retry strategy. Defaults to 2.
            logger (Optional[Logger], optional): Logger instance. Defaults to None.

        """
        self._gti_config = gti_config
        self._work_manager = work_manager
        self.http_timeout = http_timeout
        self.max_failures = max_failures
        self.cooldown_time = cooldown_time
        self.max_requests = max_requests
        self.period = period
        self.max_retries = max_retries
        self.backoff = backoff
        self._logger = logger or logging.getLogger(__name__)

        http_client = AioHttpClient(default_timeout=self.http_timeout, logger=self._logger)
        breaker = CircuitBreaker(max_failures=self.max_failures, cooldown_time=self.cooldown_time)
        limiter_config = {
            "key": f"gti-api-{uuid4()}",
            "max_requests": self.max_requests,
            "period": self.period
        }
        retry_request_strategy = RetryRequestStrategy(http=http_client, breaker=breaker, limiter=limiter_config, hooks= None, max_retries=self.max_retries, backoff=self.backoff, logger=self._logger)
        self.api_client = ApiClient(strategy=retry_request_strategy, logger=self._logger)

        self._orchestration()

    def _orchestration(self) -> None:
        """Manage the orchestration pipeline."""
        state = self._work_manager.get_state()
        self.fetchers: List[BaseFetcher] = [FetchReports(self._gti_config, self.api_client, state, self._logger)]

        self.processors: List[BaseProcessor] = [
            ProcessReports(self.organization, self.tlp_marking, self._logger),
            # ProcessMalwareFamilies(),
            # ProcessAttackTechniques(),
            # ProcessThreatActors(),
            # ProcessVulnerabilities(),
            # ProcessIOCs(),
        ]

        self.batch_collector = BatchCollector(
            topic=f"{PREFIX_BROKER}/final",
            batch_size=500,
            flush_interval=300.0,
            send_func=self.send_batch,
            sentinel_obj=SENTINEL
        )

    def _create_tlp_marking(self):
        # Create TLPMarking based on the connector configuration and publish it to PREFIX_BROKER/final
        # tlp_marking = TLPMarking(self._gti_config.tlp_marking)
        # await broker.publish(f"{PREFIX_BROKER}/final", tlp_marking)
        ...

    def _create_organization(self):
        # Create Organization based on the connector configuration and publish it to PREFIX_BROKER/final
        # organization = Organization("Google TI Feeds")
        # await broker.publish(f"{PREFIX_BROKER}/final", organization)
        ...

    async def send_batch(self, batch: List[Any]) -> None:
        """Send a batch of entities for ingestion.

        Args:
            batch (List[Any]): The batch of entities to send for ingestion.

        """
        ...

    async def run(self) -> None:
        """Run the pipeline to fetch, process, ingest reports and related entities."""
        batch_task = asyncio.create_task(self.batch_collector.run())
        proc_tasks = [asyncio.create_task(p.process()) for p in self.processors]
        fetch_tasks = [asyncio.create_task(f.fetch()) for f in self.fetchers]

        await asyncio.gather(*fetch_tasks)
        await broker.publish(f"{PREFIX_BROKER}/final", SENTINEL)
        await batch_task
        await asyncio.gather(*proc_tasks)


# TODO:    Main loop for the connector `_process_callback` function
# TODO:    Manage the pipeline for fetching and processing reports and related entities
# TODO:    Retrieve all entities to convert them into bundles and ingest them into the system

# Create Organization/identity based on the connector and publish it to PREFIX_BROKER/final
# Create TLPMarking based on the connector configuration and publish it to PREFIX_BROKER/final

# TODO:    Handle the work management of the pipeline

# TODO:    Scenario Outline: If connector_split_work is False init a unique work for the whole ingest jobs.
# TODO:    Scenario Outline: If connector_split_work is True init a work for each bundle.
# TODO:    Scenario Outline: Send STIX2.1 Bundle.
# TODO:    Scenario Outline: Wait for work to finish.
# TODO:    Scenario Outline: Finalize the work by setting the state with 'last_modification_date', so later on we have track on the last ingested to not restart from scratch if a crash occurs.
# TODO:    Scenario Outline: Finalize the work by calling 'to_processed'.
# TODO:    Scenario Outline: If error in work ingest, should finalize it cleanly.
# TODO:    Scenario Outline: If more massive error on the connector, or shutting down, should finalize all remaining work.
