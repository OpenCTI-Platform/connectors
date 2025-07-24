"""Client API - Main entry point that delegates to specialized client APIs."""

import logging
from typing import Any, AsyncGenerator, Dict, List, Optional
from uuid import uuid4

from connector.src.custom.client_api.client_api_shared import ClientAPIShared
from connector.src.custom.client_api.malware.client_api_malware import ClientAPIMalware
from connector.src.custom.client_api.report.client_api_report import ClientAPIReport
from connector.src.custom.client_api.threat_actor.client_api_threat_actor import (
    ClientAPIThreatActor,
)
from connector.src.custom.configs.fetcher_config import FETCHER_CONFIGS
from connector.src.utils.api_engine.aio_http_client import AioHttpClient
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.circuit_breaker import CircuitBreaker
from connector.src.utils.api_engine.retry_request_strategy import RetryRequestStrategy
from connector.src.utils.fetchers import GenericFetcherFactory

LOG_PREFIX = "[Fetcher]"


class ClientAPI:
    """Main client API that delegates to specialized client APIs."""

    def __init__(self, config: Any, logger: logging.Logger):
        """Initialize Client API with specialized client APIs."""
        self.config = config
        self.logger = logger

        self.logger.info(f"{LOG_PREFIX} Initializing client API")

        # Create shared API client and fetcher factory once
        self._shared_api_client = self._create_api_client()
        self._shared_fetcher_factory = self._create_fetcher_factory()

        # Pass shared instances to specialized clients
        if self.config.import_reports:
            self.report_client = ClientAPIReport(
                config, logger, self._shared_api_client, self._shared_fetcher_factory
            )
        if self.config.import_threat_actors:
            self.threat_actor_client = ClientAPIThreatActor(
                config, logger, self._shared_api_client, self._shared_fetcher_factory
            )
        if self.config.import_malware_families:
            self.malware_client = ClientAPIMalware(
                config, logger, self._shared_api_client, self._shared_fetcher_factory
            )
        self.shared_client = ClientAPIShared(
            config, logger, self._shared_api_client, self._shared_fetcher_factory
        )

    @property
    def real_total_reports(self) -> int:
        """Get the real total number of reports from the report client."""
        return self.report_client.real_total_reports

    @property
    def real_total_threat_actors(self) -> int:
        """Get the real total number of threat actors from the threat actor client."""
        return self.threat_actor_client.real_total_threat_actors

    @property
    def real_total_malware_families(self) -> int:
        """Get the real total number of malware families from the malware client."""
        return self.malware_client.real_total_malware_families

    async def fetch_reports(
        self, initial_state: Optional[Dict[str, Any]]
    ) -> AsyncGenerator[Dict[Any, Any], None]:
        """Fetch reports from the API.

        Args:
            initial_state (Optional[Dict[str, Any]]): The initial state of the fetcher.

        Yields:
            AsyncGenerator[Dict[str, Any], None]: The fetched reports.

        """
        self.logger.info(f"{LOG_PREFIX} Starting report fetching")
        async for report_data in self.report_client.fetch_reports(initial_state):
            yield report_data

    async def fetch_threat_actors(
        self, initial_state: Optional[Dict[str, Any]]
    ) -> AsyncGenerator[Dict[Any, Any], None]:
        """Fetch threat actors from the API.

        Args:
            initial_state (Optional[Dict[str, Any]]): The initial state of the fetcher.

        Yields:
            AsyncGenerator[Dict[str, Any], None]: The fetched threat actors.

        """
        self.logger.info(f"{LOG_PREFIX} Starting threat actor fetching")
        async for threat_actor_data in self.threat_actor_client.fetch_threat_actors(
            initial_state
        ):
            yield threat_actor_data

    async def fetch_malware_families(
        self, initial_state: Optional[Dict[str, Any]]
    ) -> AsyncGenerator[Dict[Any, Any], None]:
        """Fetch malware families from the API.

        Args:
            initial_state (Optional[Dict[str, Any]]): The initial state of the fetcher.

        Yields:
            AsyncGenerator[Dict[str, Any], None]: The fetched malware families.

        """
        self.logger.info(f"{LOG_PREFIX} Starting malware family fetching")
        async for malware_family_data in self.malware_client.fetch_malware_families(
            initial_state
        ):
            yield malware_family_data

    async def fetch_subentities_ids(
        self, entity_name: str, entity_id: str, subentity_types: list[str]
    ) -> Dict[str, List[str]]:
        """Fetch subentities IDs from the API.

        Args:
            entity_name (str): The name of the entity.
            entity_id (str): The ID of the entity.
            subentity_types (list[str]): The type of subentities to fetch.

        Returns:
            Dict[str, List[str]]: The fetched subentities IDs.

        """
        return await self.shared_client.fetch_subentities_ids(
            entity_name, entity_id, subentity_types
        )

    async def fetch_subentity_details(
        self, subentity_ids: Dict[str, List[str]]
    ) -> Dict[str, List[Any]]:
        """Fetch subentity details in parallel for multiple IDs.

        Args:
            subentity_ids: Dictionary mapping entity types to lists of IDs

        Returns:
            Dictionary mapping entity types to lists of fetched entities

        """
        return await self.shared_client.fetch_subentity_details(subentity_ids)

    def _create_fetcher_factory(self) -> GenericFetcherFactory:
        """Create and configure the fetcher factory with all configurations."""
        base_headers = {"X-Apikey": self.config.api_key, "accept": "application/json"}

        if hasattr(self.config, "api_url") and self.config.api_url:
            self.logger.info(f"[BaseFetcher] Using base API URL: {self.config.api_url}")
        else:
            self.logger.error(
                "[BaseFetcher] No API URL configured! Set config.api_url to make API calls work"
            )

        factory = GenericFetcherFactory(
            api_client=self._shared_api_client,
            base_headers=base_headers,
            logger=self.logger,
        )

        for entity_type, config in FETCHER_CONFIGS.items():
            factory.register_config(entity_type, config)
            self.logger.debug(
                f"[BaseFetcher] Registered fetcher config for {entity_type}"
            )

        return factory

    def _create_api_client(self) -> ApiClient:
        """Create and configure the API client for requests."""
        http_client = AioHttpClient(default_timeout=120, logger=self.logger)
        breaker = CircuitBreaker(max_failures=5, cooldown_time=60)
        limiter_config = {
            "key": f"api-{uuid4()}",
            "max_requests": 60 * 10,
            "period": 60,
        }
        retry_strategy = RetryRequestStrategy(
            http=http_client,
            breaker=breaker,
            limiter=limiter_config,
            hooks=None,
            max_retries=5,
            backoff=2,
            logger=self.logger,
        )
        api_client = ApiClient(strategy=retry_strategy, logger=self.logger)

        if hasattr(self.config, "api_url") and self.config.api_url:
            self.logger.info(
                f"[BaseFetcher] Created API client for {self.config.api_url}"
            )
        else:
            self.logger.warning(
                "[BaseFetcher] API URL not configured in config.api_url - API calls will likely fail"
            )

        return api_client
