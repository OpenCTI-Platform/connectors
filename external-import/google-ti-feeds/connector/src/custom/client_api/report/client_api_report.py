"""Report-specific client API for fetching and processing report data."""

import logging
from collections.abc import AsyncGenerator
from typing import Any

from aiohttp import ClientSession, ClientTimeout
from connector.src.custom.client_api.client_api_base import BaseClientAPI


class ClientAPIReport(BaseClientAPI):
    """Report-specific client API for fetching and processing report data."""

    LOG_PREFIX = "[FetcherReport]"

    def __init__(
        self,
        config: Any,
        logger: logging.Logger,
        api_client: Any = None,
        fetcher_factory: Any = None,
    ):
        """Initialize Report Client API."""
        super().__init__(config, logger, api_client, fetcher_factory)
        self.real_total_reports = 0

    def _build_filter_configurations(
        self,
        collection_type: str,
        start_date: str,
        initial_state: dict[str, Any] | None = None,
        types: list[str] | None = None,
        origins: list[str] | None = None,
        entity_name: str = "reports",
        cursor_key: str = "cursor",
        extra_filters: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Build filter configurations based on config settings.

        Args:
            collection_type: Type of collection (should be "report")
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
            if types is None:
                types = getattr(self.config, "report_types", ["All"])
            if origins is None:
                origins = getattr(self.config, "report_origins", ["All"])
            if extra_filters is None:
                extra_filters = getattr(self.config, "report_extra_filters", [])

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
                "Failed to build filter configurations",
                {"prefix": self.LOG_PREFIX, "error": str(e)},
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
        if entity_description == "reports" and total_items:
            self.real_total_reports = total_items

        cursor_info = f" (cursor: {cursor[:6]}...)" if cursor else ""
        page_info = ""

        if total_pages and total_pages > 1:
            page_info = f" page {page_nb}/{total_pages}"
            if total_items:
                page_info += f" (total of {total_items} items)"
        elif total_items:
            page_info = f" (total of {total_items} items)"

        return f"Fetched {data_count} {entity_description} from API{page_info}{cursor_info}"

    async def fetch_reports(
        self, initial_state: dict[str, Any] | None
    ) -> AsyncGenerator[dict[Any, Any], None]:
        """Fetch reports from the API.

        Args:
            initial_state (dict[str, Any] | None): The initial state of the fetcher.

        Yields:
            AsyncGenerator[dict[str, Any], None]: The fetched reports.

        """
        start_date = self._parse_start_date(
            self.config.report_import_start_date,
            initial_state,
            "report_next_cursor_start_date",
        )
        filter_configs = self._build_filter_configurations(
            collection_type="report",
            start_date=start_date,
            initial_state=initial_state,
        )
        report_fetcher = self.fetcher_factory.create_fetcher_by_name(
            "main_reports", base_url=self.config.api_url.unicode_string()
        )

        for filter_config in filter_configs:
            endpoint_params = filter_config.get("params", {})

            self.logger.info(
                "Fetching reports from endpoint 'reports'",
                {
                    "prefix": self.LOG_PREFIX,
                    "endpoint": "reports",
                    "filters": endpoint_params,
                },
            )

            async for report_data in self._paginate_with_cursor(
                report_fetcher, endpoint_params, "reports"
            ):
                yield report_data

    async def download_report_pdf(self, report_id: str) -> bytes | None:
        """Download a report PDF from the GTI API.

        The GTI API returns a JSON response containing a URL to the actual PDF file.
        This method first fetches that URL, then downloads the PDF binary content.

        Args:
            report_id: The ID of the report to download the PDF for.

        Returns:
            The PDF content as bytes, or None if the download failed.

        """
        url = f"{self.config.api_url.unicode_string().rstrip('/')}/collections/{report_id}/download_report"
        headers = {
            "X-Apikey": self.config.api_key.get_secret_value(),
            "accept": "application/json",
        }

        try:
            response = await self.api_client.call_api(
                url=url,
                method="GET",
                headers=headers,
            )

            pdf_url = response.get("data") if isinstance(response, dict) else None

            if not pdf_url:
                self.logger.warning(
                    "No PDF URL found in download_report response",
                    {"prefix": self.LOG_PREFIX, "report_id": report_id},
                )
                return None

            if not pdf_url.startswith("https://"):
                self.logger.warning(
                    "PDF URL does not use HTTPS, skipping download",
                    {"prefix": self.LOG_PREFIX, "report_id": report_id},
                )
                return None

            self.logger.info(
                "Downloading report PDF",
                {"prefix": self.LOG_PREFIX, "report_id": report_id},
            )

            async with ClientSession(
                timeout=ClientTimeout(total=120), trust_env=True
            ) as session:
                async with session.get(pdf_url) as pdf_response:
                    if pdf_response.status >= 400:
                        self.logger.warning(
                            "Failed to download report PDF",
                            {
                                "prefix": self.LOG_PREFIX,
                                "report_id": report_id,
                                "status": pdf_response.status,
                            },
                        )
                        return None
                    return await pdf_response.read()

        except Exception as e:
            self.logger.warning(
                "Error downloading report PDF",
                {
                    "prefix": self.LOG_PREFIX,
                    "report_id": report_id,
                    "error": str(e),
                },
            )
            return None
