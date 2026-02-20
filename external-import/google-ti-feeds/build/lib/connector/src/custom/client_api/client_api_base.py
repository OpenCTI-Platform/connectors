"""Base client API class with common functionality."""

import logging
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from connector.src.custom.configs.fetcher_config import FETCHER_CONFIGS
from connector.src.utils.api_engine.aio_http_client import AioHttpClient
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.circuit_breaker import CircuitBreaker
from connector.src.utils.api_engine.retry_request_strategy import RetryRequestStrategy
from connector.src.utils.fetchers import GenericFetcherFactory

LOG_PREFIX = "[BaseFetcher]"


class BaseClientAPI:
    """Base client API class with common functionality."""

    def __init__(
        self,
        config: Any,
        logger: logging.Logger,
        api_client: ApiClient | None = None,
        fetcher_factory: GenericFetcherFactory | None = None,
    ):
        """Initialize Base Client API."""
        self.config = config
        self.logger = logger

        # Use provided instances or create new ones (for backward compatibility)
        self.api_client = (
            api_client if api_client is not None else self._create_api_client()
        )
        self.fetcher_factory = (
            fetcher_factory
            if fetcher_factory is not None
            else self._create_fetcher_factory()
        )

    def _parse_start_date(
        self,
        start_date_config: str,
        initial_state: dict[str, Any] | None = None,
        state_key: str = "next_cursor_start_date",
    ) -> Any:
        """Parse and calculate start date from configuration.

        Args:
            start_date_config: ISO 8601 duration string from config
            initial_state: Optional initial state for resuming processing
            state_key: Key to look for in initial_state for last modification date

        Returns:
            Formatted start date string

        """
        last_mod_date = initial_state.get(state_key) if initial_state else None

        if last_mod_date:
            self.logger.info(
                "Resuming from state",
                {"prefix": LOG_PREFIX, "last_mod_date": last_mod_date},
            )
            parsed_date = datetime.fromisoformat(last_mod_date) + timedelta(seconds=1)
            start_date = parsed_date.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S"
            )
            return start_date

        try:
            duration = start_date_config
            if isinstance(duration, timedelta):
                past_date = datetime.now(timezone.utc) - duration
                start_date = past_date.strftime("%Y-%m-%dT%H:%M:%S")
                self.logger.info(
                    "Calculated start date",
                    {
                        "prefix": LOG_PREFIX,
                        "start_date": start_date,
                        "duration": start_date_config,
                    },
                )
                return start_date
            else:
                self.logger.error(
                    "Could not parse duration",
                    {"prefix": LOG_PREFIX, "start_date_config": start_date_config},
                )
                return None
        except Exception as e:
            self.logger.error(
                "Error parsing start date config",
                {
                    "prefix": LOG_PREFIX,
                    "start_date_config": start_date_config,
                    "error": str(e),
                },
            )
            return None

    def _build_filter_configurations(
        self,
        collection_type: str,
        start_date: str,
        initial_state: dict[str, Any] | None = None,
        types: list[str] | None = None,
        origins: list[str] | None = None,
        entity_name: str = "items",
        cursor_key: str = "cursor",
    ) -> list[dict[str, Any]]:
        """Build filter configurations for a collection type.

        Args:
            collection_type: Type of collection (report, threat_actor, etc.)
            start_date: Start date for filtering
            initial_state: Optional initial state for resuming processing
            types: Optional list of types to filter by
            origins: Optional list of origins to filter by
            entity_name: Name of entities for logging (reports, threat_actors, etc.)
            cursor_key: Key to use for cursor in initial_state

        Returns:
            list of filter configurations with params and cursors

        """
        base_filters = (
            f"collection_type:{collection_type} last_modification_date:{start_date}+"
        )

        types = types or ["All"]
        origins = origins or ["All"]

        if "All" in types:
            types = ["All"]
        if "All" in origins:
            origins = ["All"]

        filter_configs = []

        for item_type in types:
            for origin in origins:
                current_filter = base_filters
                if item_type != "All":
                    current_filter += f" {collection_type}_type:'{item_type}'"
                if origin != "All":
                    current_filter += f" origin:'{origin}'"

                if item_type == "All" and origin == "All":
                    description = f"all {entity_name}"
                elif item_type == "All":
                    description = f"all types, origin={origin}"
                elif origin == "All":
                    description = f"type={item_type}, all origins"
                else:
                    description = f"type={item_type}, origin={origin}"

                config = {
                    "params": {
                        "filter": current_filter,
                        "limit": 40,
                        "order": "last_modification_date+",
                    },
                    "cursor": (
                        initial_state.get(cursor_key) if initial_state else None
                    ),
                    "description": description,
                }
                filter_configs.append(config)

                self.logger.info(
                    "Configured fetching",
                    {
                        "prefix": LOG_PREFIX,
                        "entity_name": entity_name,
                        "description": description,
                        "start_date": start_date,
                    },
                )

        return filter_configs

    def _create_fetcher_factory(self) -> GenericFetcherFactory:
        """Create and configure the fetcher factory with all configurations.

        Returns:
            Configured GenericFetcherFactory instance

        """
        base_headers = {"X-Apikey": self.config.api_key, "accept": "application/json"}

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
            api_client=self.api_client,
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
        """Create and configure the API client for requests.

        Returns:
            Configured ApiClient instance

        """
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

    def _extract_response_data(self, response: Any) -> tuple[Any, Any]:
        """Extract data and meta from response object."""
        if hasattr(response, "data") and hasattr(response, "meta"):
            return response.data, response.meta
        elif isinstance(response, dict) and "data" in response:
            return response["data"], response.get("meta")
        else:
            return response, None

    def _extract_meta_info(self, meta: Any) -> tuple[str | None, int | None]:
        """Extract cursor and count from meta object."""
        cursor = None
        count = None

        if not meta:
            return cursor, count

        if hasattr(meta, "cursor"):
            cursor = meta.cursor
        elif isinstance(meta, dict) and "cursor" in meta:
            cursor = meta["cursor"]

        if hasattr(meta, "count"):
            count = meta.count
        elif isinstance(meta, dict) and "count" in meta:
            count = meta["count"]

        return cursor, count

    def _calculate_pagination_info(
        self, count: int | None, params: dict[str, Any]
    ) -> Any | None:
        """Calculate total pages based on count and limit."""
        if count is None:
            return None
        limit = params.get("limit", 40)
        return (count + limit - 1) // limit

    def _build_log_message(
        self,
        data_count: int,
        entity_description: str,
        page_nb: int,
        total_pages: int | None,
        total_items: int | None,
        cursor: str | None,
    ) -> str:
        """Build pagination log message."""
        cursor_info = f" (cursor: {cursor[:6]}...)" if cursor else ""
        page_info = ""

        if total_pages and total_pages > 1:
            page_info = f" page {page_nb}/{total_pages}"
            if total_items:
                page_info += f" (total of {total_items} items)"
        elif total_items:
            page_info = f" (total of {total_items} items)"

        return f"Fetched {data_count} {entity_description} from API{page_info}{cursor_info}"

    async def _paginate_with_cursor(
        self,
        fetcher: Any,
        initial_params: dict[str, Any],
        entity_description: str = "items",
    ) -> AsyncGenerator[Any, None]:
        """Paginate helper that handles cursor-based pagination.

        Args:
            fetcher: The fetcher instance to use for API calls
            initial_params: Initial parameters for the API call
            entity_description: Description of what's being fetched for logging

        Yields:
            Data from each page of results

        """
        params = initial_params.copy()
        page_nb = 1
        total_items = None
        total_pages = None

        try:
            while True:
                response = await fetcher.fetch_single(**params)

                if response is None:
                    # Use the child class's LOG_PREFIX if available, otherwise use base LOG_PREFIX
                    prefix = getattr(self.__class__, "LOG_PREFIX", LOG_PREFIX)
                    self.logger.debug(
                        "No data returned",
                        {
                            "prefix": prefix,
                            "entity_description": entity_description,
                        },
                    )
                    break

                data, meta = self._extract_response_data(response)

                if not data:
                    break

                data_count = len(data) if isinstance(data, list) else 1
                cursor, count = self._extract_meta_info(meta)

                if count is not None:
                    total_items = count
                    total_pages = self._calculate_pagination_info(count, params)

                log_message = self._build_log_message(
                    data_count,
                    entity_description,
                    page_nb,
                    total_pages,
                    total_items,
                    cursor,
                )
                # Use the child class's LOG_PREFIX if available, otherwise use base LOG_PREFIX
                prefix = getattr(self.__class__, "LOG_PREFIX", LOG_PREFIX)
                self.logger.info(log_message, {"prefix": prefix})

                yield data

                if cursor:
                    params["cursor"] = cursor
                    page_nb += 1
                else:
                    break

        except Exception as e:
            self.logger.error(
                "Failed to fetch page",
                {
                    "prefix": LOG_PREFIX,
                    "entity_description": entity_description,
                    "error": str(e),
                },
            )
        finally:
            self.logger.debug(
                "Finished fetching",
                {"prefix": LOG_PREFIX, "entity_description": entity_description},
            )
