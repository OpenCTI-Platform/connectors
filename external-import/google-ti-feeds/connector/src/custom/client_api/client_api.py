"""Client API - Main entry point that delegates to specialized client APIs."""

import logging
from collections.abc import AsyncGenerator
from typing import Any
from uuid import uuid4

from connector.src.custom.client_api.campaign.client_api_campaign import (
    ClientAPICampaign,
)
from connector.src.custom.client_api.client_api_shared import ClientAPIShared
from connector.src.custom.client_api.malware.client_api_malware import ClientAPIMalware
from connector.src.custom.client_api.report.client_api_report import ClientAPIReport
from connector.src.custom.client_api.threat_actor.client_api_threat_actor import (
    ClientAPIThreatActor,
)
from connector.src.custom.client_api.vulnerability.client_api_vulnerability import (
    ClientAPIVulnerability,
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

        self.logger.info("Initializing client API", {"prefix": LOG_PREFIX})

        self._shared_api_client = self._create_api_client()
        self._shared_fetcher_factory = self._create_fetcher_factory()

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
        if self.config.import_vulnerabilities:
            self.vulnerability_client = ClientAPIVulnerability(
                config, logger, self._shared_api_client, self._shared_fetcher_factory
            )
        if self.config.import_campaigns:
            self.campaign_client = ClientAPICampaign(
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

    @property
    def real_total_vulnerabilities(self) -> int:
        """Get the real total number of vulnerabilities from the vulnerability client."""
        return self.vulnerability_client.real_total_vulnerabilities

    @property
    def real_total_campaigns(self) -> int:
        """Get the real total number of campaigns from the campaign client."""
        return self.campaign_client.real_total_campaigns

    async def fetch_reports(
        self, initial_state: dict[str, Any] | None
    ) -> AsyncGenerator[dict[Any, Any], None]:
        """Fetch reports from the API.

        Args:
            initial_state (dict[str, Any] | None): The initial state of the fetcher.

        Yields:
            AsyncGenerator[dict[str, Any], None]: The fetched reports.

        """
        self.logger.info("Starting report fetching", {"prefix": LOG_PREFIX})
        async for report_data in self.report_client.fetch_reports(initial_state):
            yield report_data

    async def fetch_threat_actors(
        self, initial_state: dict[str, Any] | None
    ) -> AsyncGenerator[dict[Any, Any], None]:
        """Fetch threat actors from the API.

        Args:
            initial_state (dict[str, Any] | None): The initial state of the fetcher.

        Yields:
            AsyncGenerator[dict[str, Any], None]: The fetched threat actors.

        """
        self.logger.info("Starting threat actor fetching", {"prefix": LOG_PREFIX})
        async for threat_actor_data in self.threat_actor_client.fetch_threat_actors(
            initial_state
        ):
            yield threat_actor_data

    async def fetch_malware_families(
        self, initial_state: dict[str, Any] | None
    ) -> AsyncGenerator[dict[Any, Any], None]:
        """Fetch malware families from the API.

        Args:
            initial_state (dict[str, Any] | None): The initial state of the fetcher.

        Yields:
            AsyncGenerator[dict[str, Any], None]: The fetched malware families.

        """
        self.logger.info("Starting malware family fetching", {"prefix": LOG_PREFIX})
        async for malware_family_data in self.malware_client.fetch_malware_families(
            initial_state
        ):
            yield malware_family_data

    async def fetch_vulnerabilities(
        self, initial_state: dict[str, Any] | None = None
    ) -> AsyncGenerator[dict[Any, Any], None]:
        """Fetch vulnerabilities from the API.

        Args:
            initial_state (dict[str, Any] | None): The initial state of the fetcher.

        Yields:
            dict[str, Any]: The fetched vulnerabilities.

        """
        self.logger.info("Starting vulnerability fetching", {"prefix": LOG_PREFIX})
        async for vulnerability_data in self.vulnerability_client.fetch_vulnerabilities(
            initial_state
        ):
            yield vulnerability_data

    async def fetch_campaigns(
        self, initial_state: dict[str, Any] | None = None
    ) -> AsyncGenerator[dict[Any, Any], None]:
        """Fetch campaigns from the API.

        Args:
            initial_state (dict[str, Any] | None): The initial state of the fetcher.

        Yields:
            dict[str, Any]: The fetched campaigns.

        """
        self.logger.info("Starting campaign fetching", {"prefix": LOG_PREFIX})
        async for campaign_data in self.campaign_client.fetch_campaigns(initial_state):
            yield campaign_data

    async def fetch_subentities_ids(
        self, entity_name: str, entity_id: str, subentity_types: list[str]
    ) -> dict[str, list[str]]:
        """Fetch subentities IDs from the API.

        Args:
            entity_name (str): The name of the entity.
            entity_id (str): The ID of the entity.
            subentity_types (list[str]): The type of subentities to fetch.

        Returns:
            dict[str, list[str]]: The fetched subentities IDs.

        """
        return await self.shared_client.fetch_subentities_ids(
            entity_name, entity_id, subentity_types
        )

    async def fetch_subentity_details(
        self, subentity_ids: dict[str, list[str]]
    ) -> dict[str, list[Any]]:
        """Fetch subentity details in parallel for multiple IDs.

        Args:
            subentity_ids: dictionary mapping entity types to lists of IDs

        Returns:
            dictionary mapping entity types to lists of fetched entities

        """
        return await self.shared_client.fetch_subentity_details(subentity_ids)

    def _create_fetcher_factory(self) -> GenericFetcherFactory:
        """Create and configure the fetcher factory with all configurations."""
        base_headers = {
            "X-Apikey": self.config.api_key.get_secret_value(),
            "accept": "application/json",
        }

        if hasattr(self.config, "api_url") and self.config.api_url:
            self.logger.info(
                "Using base API URL",
                {"prefix": LOG_PREFIX, "api_url": self.config.api_url.unicode_string()},
            )
        else:
            self.logger.error(
                "No API URL configured! Set config.api_url to make API calls work",
                {"prefix": LOG_PREFIX},
            )

        factory = GenericFetcherFactory(
            api_client=self._shared_api_client,
            base_headers=base_headers,
            logger=self.logger,
        )

        for entity_type, config in FETCHER_CONFIGS.items():
            factory.register_config(entity_type, config)
            self.logger.debug(
                "Registered fetcher config",
                {"prefix": LOG_PREFIX, "entity_type": entity_type},
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
                "Created API client",
                {"prefix": LOG_PREFIX, "api_url": self.config.api_url.unicode_string()},
            )
        else:
            self.logger.warning(
                "API URL not configured in config.api_url - API calls will likely fail",
                {"prefix": LOG_PREFIX},
            )

        return api_client
