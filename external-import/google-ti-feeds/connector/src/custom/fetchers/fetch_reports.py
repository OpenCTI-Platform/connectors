"""Fetcher to gather information about reports from Google TI feeds.

This class is responsible for fetching reports from Google TI feeds.
It inherits from the BaseFetcher class and implements the fetch method.

It will also orchestrate the fetching process for the sub entities related to reports.
"""

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import isodate  # type: ignore[import-untyped]
from connector.src.custom.interfaces.base_fetcher import BaseFetcher
from connector.src.custom.models.gti_report_model import (
    GTIReportData,
    GTIReportResponse,
)
from connector.src.custom.pubsub import broker
from connector.src.custom.reports_constants import (
    LAST_WORK_START_DATE_STATE_KEY,
    PREFIX_BROKER,
    SENTINEL,
)

if TYPE_CHECKING:
    from datetime import timedelta
    from logging import Logger

    from connector.src.utils.api_engine.api_client import ApiClient

class FetchReports(BaseFetcher):
    """Fetcher to gather information about reports from Google TI feeds.

    This class is responsible for fetching reports from Google TI feeds.
    It inherits from the BaseFetcher class and implements the fetch method.
    """

    def __init__(self, gti_config: Dict[str, Any], api_client: "ApiClient", state: Dict[str, str], logger: Optional["Logger"] = None) -> None:
        """Initialize the FetchReports class.

        Args:
            gti_config (GTIConfig): The configuration object for the Google TI feeds.
            api_client (ApiClient): The API client for making requests.
            state (Dict[str, str]): The state object for storing the last fetched report ID.
            logger (Optional[Logger], optional): The logger object for logging. Defaults to None.

        """
        self._gti_config = gti_config
        self._api_client = api_client
        self._state = state
        self._logger = logger or logging.getLogger(__name__)

    async def fetch(self) -> None:
        """Fetch reports from Google TI feeds."""
        await self._fetch_reports()
        await self._publish_sentinels()

    async def _fetch_reports(self) -> None:
        """Fetch reports from Google TI feeds using the API key and URL provided in the configuration.
        It converts the fetched reports into a validate pydantic model.
        It pushes the fetched reports into the pubsub broker for further processing.
        """
        last_work_start_date: Optional[str] = self._state.get(LAST_WORK_START_DATE_STATE_KEY)
        start_date_iso_8601: Optional[str] = self._gti_config.get("import_start_date")
        duration: timedelta = isodate.parse_duration(start_date_iso_8601)
        past_date: datetime = datetime.now() - duration
        start_date: str = past_date.strftime("%Y-%m-%d")

        if last_work_start_date is not None:
            start_date = last_work_start_date

        base_url = self._gti_config.get("api_url")
        endpoint = f"{base_url}/collections"
        self._logger.info(f"[Fetcher Reports] Fetching reports from endpoint: {endpoint}")

        headers = {
            "X-Apikey": self._gti_config.get("api_key"),
            "accept": "application/json"
        }

        filters = f"collection_type:report last_modification_date:{start_date}+"
        self._logger.debug(f"[Fetcher Reports] Fetching reports with filter: {filters}")

        report_types: List[str] = self._gti_config.get("report_types")  # type: ignore[assignment]
        if report_types and 'All' not in report_types:
            filters += f" report_type:{','.join(report_types)}"

        origins: List[str] = self._gti_config.get("origins")  # type: ignore[assignment]
        if origins and 'All' not in origins:
            filters += f" origin:{','.join(origins)}"

        query_params = { "filter": filters, "limit": 40, "order": "last_modification_date+" }
        current_url: Optional[str] = endpoint
        page_params: Optional[Dict[str, Any]] = query_params
        retrieved_reports_count = 0
        total_reports_count = 0
        while current_url:
            gti_response: GTIReportResponse = await self._api_client.call_api(
                url=current_url,
                headers=headers,
                params=page_params,
                model=GTIReportResponse,
                timeout=60
            )
            page_params = None

            if not gti_response:
                self._logger.error(f"[Fetcher Reports] API call to {endpoint} did not return a valid GTIReportResponse object. Stopping pagination.")
                break

            if gti_response.data:
                total_reports_count = gti_response.meta.count
                retrieved_reports_count += len(gti_response.data)
                self._logger.info(f"[Fetcher Reports] Fetched {len(gti_response.data)} reports from current page, {retrieved_reports_count}/{total_reports_count} reports.")

                last_report_in_page = gti_response.data[-1]
                last_modification_timestamp = last_report_in_page.attributes.last_modification_date
                date_from_timestamp = datetime.fromtimestamp(last_modification_timestamp)
                self._logger.info(f"[Fetcher Reports] Last report in page: {last_report_in_page.id.strip()}, last modification date: {date_from_timestamp}")

                await self._publish_reports(last_modification_timestamp, gti_response.data)
                await self._orchestrate_subfetches(gti_response.data)
            else:
                self._logger.info(f"[Fetcher Reports] No report data in the current page from {endpoint}.")

            if gti_response.meta and gti_response.meta.cursor and gti_response.links and gti_response.links.next:
                current_url = gti_response.links.next
                self._logger.info("[Fetcher Reports] Preparing to fetch next page.")
            else:
                self._logger.info("[Fetcher Reports] No more pages to fetch (cursor/next link criteria not met or end of data).")
                current_url = None

    async def _publish_reports(self, last_modification_timestamp: int, reports: List[GTIReportData]) -> None:
        """Publish the fetched reports into the pubsub broker for further processing."""
        await broker.publish(f"{PREFIX_BROKER}/reports", (last_modification_timestamp, reports))
        self._logger.info(f"[Fetcher Reports] {len(reports)} reports published to broker for processing.")

    async def _publish_sentinels(self) -> None:
        """Publish the fetched sentinels into the pubsub broker to signal the end of the fetch."""
        await broker.publish(f"{PREFIX_BROKER}/reports", SENTINEL)
        self._logger.info("[Fetcher Reports] Ends of data fetched, Sentinels published to broker.")

    async def _orchestrate_subfetches(self, reports: List[GTIReportData]) -> None:
        """Orchestrate the subfetches of the reports."""
        pass
