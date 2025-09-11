"""Campaign-specific client API for fetching and processing campaign data."""

import logging
from typing import Any, AsyncGenerator, Dict, List, Optional

from connector.src.custom.client_api.client_api_base import BaseClientAPI


class ClientAPICampaign(BaseClientAPI):
    """Campaign-specific client API for fetching and processing campaign data."""

    LOG_PREFIX = "[FetcherCampaign]"

    def __init__(
        self,
        config: Any,
        logger: logging.Logger,
        api_client: Any = None,
        fetcher_factory: Any = None,
    ):
        """Initialize Campaign Client API."""
        super().__init__(config, logger, api_client, fetcher_factory)
        self.real_total_campaigns = 0

    def _build_filter_configurations(
        self,
        collection_type: str,
        start_date: str,
        initial_state: Optional[Dict[str, Any]] = None,
        types: Optional[List[str]] = None,
        origins: Optional[List[str]] = None,
        entity_name: str = "campaigns",
        cursor_key: str = "cursor",
    ) -> List[Dict[str, Any]]:
        """Build campaign filter configurations based on config settings.

        Args:
            collection_type: Type of collection (should be "campaign")
            start_date: Start date for filtering
            initial_state: Optional initial state for resuming processing
            types: Optional list of types to filter by
            origins: Optional list of origins to filter by
            entity_name: Name of entities for logging
            cursor_key: Key to use for cursor in initial_state

        Returns:
            List of filter configurations with params and cursors

        """
        try:
            if origins is None:
                origins = getattr(self.config, "campaign_origins", ["All"])

            return super()._build_filter_configurations(
                collection_type=collection_type,
                start_date=start_date,
                initial_state=initial_state,
                types=types,
                origins=origins,
                entity_name=entity_name,
                cursor_key=cursor_key,
            )

        except Exception as e:
            self.logger.error(
                "Failed to build campaign filter configurations",
                {"prefix": self.LOG_PREFIX, "error": str(e)},
            )
            return [
                {
                    "params": {
                        "filter": "collection_type:campaign",
                        "limit": 40,
                        "order": "last_modification_date+",
                    },
                    "cursor": initial_state.get("cursor") if initial_state else None,
                    "description": "fallback all campaigns",
                }
            ]

    def _build_log_message(
        self,
        data_count: int,
        entity_description: str,
        page_nb: int,
        total_pages: Optional[int],
        total_items: Optional[int],
        cursor: Optional[str],
    ) -> str:
        """Build pagination log message and update total count."""
        if entity_description == "campaigns" and total_items:
            self.real_total_campaigns = total_items

        cursor_info = f" (cursor: {cursor[:6]}...)" if cursor else ""
        page_info = ""

        if total_pages and total_pages > 1:
            page_info = f" page {page_nb}/{total_pages}"
            if total_items:
                page_info += f" (total of {total_items} items)"
        elif total_items:
            page_info = f" (total of {total_items} items)"

        return f"Fetched {data_count} {entity_description} from API{page_info}{cursor_info}"

    async def fetch_campaigns(
        self, initial_state: Optional[Dict[str, Any]]
    ) -> AsyncGenerator[Dict[Any, Any], None]:
        """Fetch campaigns from the API.

        Args:
            initial_state (Optional[Dict[str, Any]]): The initial state of the fetcher.

        Yields:
            AsyncGenerator[Dict[str, Any], None]: The fetched campaigns.

        """
        start_date = self._parse_start_date(
            self.config.campaign_import_start_date,
            initial_state,
            "campaign_next_cursor_start_date",
        )
        filter_configs = self._build_filter_configurations(
            collection_type="campaign",
            start_date=start_date,
            initial_state=initial_state,
        )
        campaign_fetcher = self.fetcher_factory.create_fetcher_by_name(
            "main_campaigns", base_url=self.config.api_url.unicode_string()
        )

        for filter_config in filter_configs:
            endpoint_params = filter_config.get("params", {})

            self.logger.info(
                "Fetching campaigns from endpoint 'campaigns'",
                {
                    "prefix": self.LOG_PREFIX,
                    "endpoint": "campaigns",
                    "filters": endpoint_params,
                },
            )

            async for campaign_data in self._paginate_with_cursor(
                campaign_fetcher, endpoint_params, "campaigns"
            ):
                yield campaign_data
