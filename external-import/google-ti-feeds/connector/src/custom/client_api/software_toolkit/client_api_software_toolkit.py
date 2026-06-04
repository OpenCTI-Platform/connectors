"""Software toolkit-specific client API for fetching and processing software toolkit data."""

import logging
from collections.abc import AsyncGenerator
from typing import Any

from connector.src.custom.client_api.client_api_base import BaseClientAPI


class ClientAPISoftwareToolkit(BaseClientAPI):
    """Software toolkit-specific client API for fetching and processing software toolkit data."""

    LOG_PREFIX = "[FetcherSoftwareToolkit]"

    def __init__(
        self,
        config: Any,
        logger: logging.Logger,
        api_client: Any = None,
        fetcher_factory: Any = None,
    ):
        """Initialize Software Toolkit Client API."""
        super().__init__(config, logger, api_client, fetcher_factory)
        self.real_total_software_toolkits = 0

    def _build_filter_configurations(
        self,
        collection_type: str,
        start_date: str,
        initial_state: dict[str, Any] | None = None,
        types: list[str] | None = None,
        origins: list[str] | None = None,
        entity_name: str = "software_toolkits",
        cursor_key: str = "cursor",
        extra_filters: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Build software toolkit filter configurations based on config settings.

        Args:
            collection_type: Type of collection (should be "software-toolkit")
            start_date: Start date for filtering
            initial_state: Optional initial state for resuming processing
            types: Optional list of types to filter by
            origins: Optional list of origins to filter by
            entity_name: Name of entities for logging
            cursor_key: Key to use for cursor in initial_state
            extra_filters: Optional list of additional filters to include in the query

        Returns:
            list of filter configurations with params and cursors

        """
        try:
            if origins is None:
                origins = getattr(
                    self.config,
                    "software_toolkit_origins",
                    ["google threat intelligence"],
                )

            if extra_filters is None:
                extra_filters = getattr(
                    self.config, "software_toolkit_extra_filters", []
                )

            return super()._build_filter_configurations(
                collection_type=collection_type,
                start_date=start_date,
                initial_state=initial_state,
                types=types,
                origins=origins,
                entity_name=entity_name,
                cursor_key=cursor_key,
                extra_filters=extra_filters,
            )

        except Exception as e:
            self.logger.error(
                "Failed to build software toolkit filter configurations",
                {"prefix": self.LOG_PREFIX, "error": str(e)},
            )
            return [
                {
                    "params": {
                        "filter": "collection_type:software-toolkit",
                        "limit": 40,
                        "order": "last_modification_date+",
                    },
                    "cursor": initial_state.get("cursor") if initial_state else None,
                    "description": "fallback all software_toolkits",
                }
            ]

    def _build_log_message(
        self,
        data_count: int,
        entity_description: str,
        page_nb: int,
        total_pages: int | None,
        total_items: int | None,
        cursor: str | None,
    ) -> str:
        """Build pagination log message and update total count."""
        if entity_description == "software_toolkits" and total_items:
            self.real_total_software_toolkits = total_items

        cursor_info = f" (cursor: {cursor[:6]}...)" if cursor else ""
        page_info = ""

        if total_pages and total_pages > 1:
            page_info = f" page {page_nb}/{total_pages}"
            if total_items:
                page_info += f" (total of {total_items} items)"
        elif total_items:
            page_info = f" (total of {total_items} items)"

        return f"Fetched {data_count} {entity_description} from API{page_info}{cursor_info}"

    async def fetch_software_toolkits(
        self, initial_state: dict[str, Any] | None
    ) -> AsyncGenerator[dict[Any, Any], None]:
        """Fetch software toolkits from the API.

        Args:
            initial_state (dict[str, Any] | None): The initial state of the fetcher.

        Yields:
            AsyncGenerator[dict[str, Any], None]: The fetched software toolkits.

        """
        start_date = self._parse_start_date(
            self.config.software_toolkit_import_start_date,
            initial_state,
            "software_toolkit_next_cursor_start_date",
        )
        filter_configs = self._build_filter_configurations(
            collection_type="software-toolkit",
            start_date=start_date,
            initial_state=initial_state,
        )
        software_toolkit_fetcher = self.fetcher_factory.create_fetcher_by_name(
            "main_software_toolkits", base_url=self.config.api_url.unicode_string()
        )

        for filter_config in filter_configs:
            endpoint_params = filter_config.get("params", {})

            self.logger.info(
                "Fetching software toolkits from endpoint 'software_toolkits'",
                {
                    "prefix": self.LOG_PREFIX,
                    "endpoint": "software_toolkits",
                    "filters": endpoint_params,
                },
            )

            async for software_toolkit_data in self._paginate_with_cursor(
                software_toolkit_fetcher, endpoint_params, "software_toolkits"
            ):
                yield software_toolkit_data
