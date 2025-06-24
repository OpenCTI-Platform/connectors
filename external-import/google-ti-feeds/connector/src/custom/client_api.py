"""Client API - Extracted fetch-related methods from orchestrator."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional
from uuid import uuid4

import isodate  # type: ignore
from connector.src.custom.configs.fetcher_configs import FETCHER_CONFIGS
from connector.src.utils.api_engine.aio_http_client import AioHttpClient
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.circuit_breaker import CircuitBreaker
from connector.src.utils.api_engine.retry_request_strategy import RetryRequestStrategy
from connector.src.utils.fetchers import GenericFetcherFactory

LOG_PREFIX = "[Fetchers]"


class ClientAPI:
    """Client API for handling fetch operations."""

    def __init__(self, config: Any, logger: logging.Logger):
        """Initialize Client API."""
        self.config = config
        self.logger = logger
        self.api_client = self._create_api_client()
        self.fetcher_factory = self._create_fetcher_factory()

    def _build_filter_configurations(
        self, initial_state: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Build filter configurations based on config settings.

        Args:
            initial_state: Optional initial state for resuming processing

        Returns:
            List of filter configurations with params and cursors

        """
        try:
            start_date_iso_8601 = self.config.import_start_date
            duration = isodate.parse_duration(start_date_iso_8601)
            past_date = datetime.now(timezone.utc) - duration
            start_date = past_date.strftime("%Y-%m-%dT%H:%M:%S")

            last_mod_date = (
                initial_state.get("next_cursor_start_date") if initial_state else None
            )

            if last_mod_date:
                parsed_date = datetime.fromisoformat(last_mod_date) + timedelta(
                    seconds=1
                )
                start_date = parsed_date.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S"
                )
            else:
                pass

            base_filters = (
                f"collection_type:report last_modification_date:{start_date}+"
            )

            report_types = getattr(self.config, "report_types", ["All"])
            origins = getattr(self.config, "origins", ["All"])

            if "All" in report_types:
                report_types = ["All"]
            if "All" in origins:
                origins = ["All"]

            filter_configs = []

            for report_type in report_types:
                for origin in origins:
                    current_filter = base_filters
                    if report_type != "All":
                        current_filter += f" report_type:'{report_type}'"
                    if origin != "All":
                        current_filter += f" origin:'{origin}'"

                    if report_type == "All" and origin == "All":
                        description = "all reports"
                    elif report_type == "All":
                        description = f"all types, origin={origin}"
                    elif origin == "All":
                        description = f"type={report_type}, all origins"
                    else:
                        description = f"type={report_type}, origin={origin}"

                    config = {
                        "params": {
                            "filter": current_filter,
                            "limit": 40,
                            "order": "last_modification_date+",
                        },
                        "cursor": (
                            initial_state.get("cursor") if initial_state else None
                        ),
                        "description": description,
                    }
                    filter_configs.append(config)

                    self.logger.info(
                        f"{LOG_PREFIX} Configured fetching reports with {description} (from {start_date})"
                    )

            return filter_configs

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to build filter configurations: {str(e)}"
            )
            return [
                {
                    "params": {
                        "filter": "collection_type:report",
                        "limit": 40,
                        "order": "last_modification_date+",
                    },
                    "cursor": initial_state.get("cursor") if initial_state else None,
                    "description": "fallback all reports",
                }
            ]

    def _create_fetcher_factory(self) -> GenericFetcherFactory:
        """Create and configure the fetcher factory with all configurations.

        Returns:
            Configured GenericFetcherFactory instance

        """
        base_headers = {"X-Apikey": self.config.api_key, "accept": "application/json"}

        if hasattr(self.config, "api_url") and self.config.api_url:
            self.logger.info(f"{LOG_PREFIX} Using base API URL: {self.config.api_url}")
        else:
            self.logger.error(
                f"{LOG_PREFIX} No API URL configured! Set config.api_url to make API calls work"
            )

        factory = GenericFetcherFactory(
            api_client=self.api_client,
            base_headers=base_headers,
            logger=self.logger,
        )

        for entity_type, config in FETCHER_CONFIGS.items():
            factory.register_config(entity_type, config)
            self.logger.debug(
                f"{LOG_PREFIX} Registered fetcher config for {entity_type}"
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
                f"{LOG_PREFIX} Created API client for {self.config.api_url}"
            )
        else:
            self.logger.warning(
                f"{LOG_PREFIX} API URL not configured in config.api_url - API calls will likely fail"
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

    def _extract_meta_info(self, meta: Any) -> tuple[Optional[str], Optional[int]]:
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
        self, count: Optional[int], params: Dict[str, Any]
    ) -> Optional[Any]:
        """Calculate total pages based on count and limit."""
        if count is None:
            return None
        limit = params.get("limit", 10)
        return (count + limit - 1) // limit

    def _build_log_message(
        self,
        data_count: int,
        entity_description: str,
        page_nb: int,
        total_pages: Optional[int],
        total_items: Optional[int],
        cursor: Optional[str],
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

        if entity_description == "reports":
            self.real_total_reports = total_items

        return f"{LOG_PREFIX} Fetched {data_count} {entity_description} from API{page_info}{cursor_info}"

    async def _paginate_with_cursor(
        self,
        fetcher: Any,
        initial_params: Dict[str, Any],
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
                    self.logger.debug(
                        f"{LOG_PREFIX} No {entity_description} data returned"
                    )
                    break

                data, meta = self._extract_response_data(response)

                if not data:
                    break

                data_count = len(data) if isinstance(data, list) else 1
                cursor, count = self._extract_meta_info(meta)

                if total_items is None and count is not None:
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
                self.logger.info(log_message)

                yield data

                if cursor:
                    params["cursor"] = cursor
                    page_nb += 1
                else:
                    break

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to fetch {entity_description} page: {str(e)}"
            )
        finally:
            self.logger.debug(f"{LOG_PREFIX} Finished fetching {entity_description}")

    async def fetch_reports(
        self, initial_state: Optional[Dict[str, Any]]
    ) -> AsyncGenerator[Dict[Any, Any], None]:
        """Fetch reports from the API.

        Args:
            initial_state (Optional[Dict[str, Any]]): The initial state of the fetcher.

        Yields:
            AsyncGenerator[Dict[str, Any], None]: The fetched reports.

        """
        filter_configs = self._build_filter_configurations(initial_state)
        report_fetcher = self.fetcher_factory.create_fetcher_by_name(
            "reports", base_url=self.config.api_url
        )

        for filter_config in filter_configs:
            endpoint_params = filter_config.get("params", {})

            self.logger.info(
                f"{LOG_PREFIX} Fetching reports from endpoint 'reports' with filters: {endpoint_params}"
            )

            async for report_data in self._paginate_with_cursor(
                report_fetcher, endpoint_params, "reports"
            ):
                yield report_data

    async def fetch_subentities_ids(self, report_id: str) -> Dict[str, List[str]]:
        """Fetch subentities IDs from the API.

        Args:
            report_id (str): The ID of the report.

        Returns:
            Dict[str, List[str]]: The fetched subentities IDs.

        """
        subentity_types = [
            "malware_families",
            "threat_actors",
            "attack_techniques",
            "vulnerabilities",
            "domains",
            "files",
            "urls",
            "ip_addresses",
        ]

        subentities_ids = {}

        relationships_fetcher = self.fetcher_factory.create_fetcher_by_name(
            "relationships", base_url=self.config.api_url
        )
        try:
            for subentity_type in subentity_types:
                all_ids = []

                params = {"report_id": report_id, "entity_type": subentity_type}

                try:
                    async for page_data in self._paginate_with_cursor(
                        relationships_fetcher, params, f"{subentity_type} relationships"
                    ):
                        if isinstance(page_data, list):
                            all_ids.extend(
                                [
                                    item["id"]
                                    for item in page_data
                                    if isinstance(item, dict) and item.get("id")
                                ]
                            )
                        elif isinstance(page_data, dict) and "data" in page_data:
                            data = page_data["data"]
                            if isinstance(data, list):
                                all_ids.extend(
                                    [
                                        item["id"]
                                        for item in data
                                        if isinstance(item, dict) and item.get("id")
                                    ]
                                )

                except Exception as e:
                    self.logger.debug(
                        f"{LOG_PREFIX} Error fetching {subentity_type} relationships: {str(e)}"
                    )

                if all_ids:
                    self.logger.info(
                        f"{LOG_PREFIX} Retrieved {len(all_ids)} {subentity_type} relationship IDs for report {report_id}"
                    )
                    subentities_ids[subentity_type] = all_ids
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} No {subentity_type} relationship IDs found for report {report_id}"
                    )

            return subentities_ids
        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Failed to gather relationships for report {report_id}: {str(e)}"
            )
            return {entity_type: [] for entity_type in subentity_types}
        finally:
            self.logger.info(
                f"{LOG_PREFIX} Finished gathering relationships for report {report_id}"
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
        subentities: Dict[str, List[Any]] = {}
        total_to_fetch = sum(len(ids) for ids in subentity_ids.values())

        if total_to_fetch > 0:
            self.logger.info(
                f"{LOG_PREFIX} Fetching details for {total_to_fetch} subentities..."
            )

        for entity_type, ids in subentity_ids.items():
            if not ids:
                subentities[entity_type] = []
                continue

            try:
                fetcher = self.fetcher_factory.create_fetcher_by_name(
                    entity_type, base_url=self.config.api_url
                )
                entities = await fetcher.fetch_multiple(ids)
                subentities[entity_type] = entities
                self.logger.debug(
                    f"{LOG_PREFIX} Fetched {len(entities)} {entity_type} entities"
                )

            except Exception as e:
                self.logger.error(
                    f"{LOG_PREFIX} Failed to fetch {entity_type} details: {str(e)}"
                )
                subentities[entity_type] = []

        if total_to_fetch > 0:
            fetched_summary = ", ".join(
                [f"{k}: {len(v)}" for k, v in subentities.items() if len(v) > 0]
            )
            if fetched_summary:
                self.logger.info(f"{LOG_PREFIX} Fetched details {{{fetched_summary}}}")

        return subentities
