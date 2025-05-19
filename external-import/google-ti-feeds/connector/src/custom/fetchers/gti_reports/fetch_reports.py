"""Fetcher to gather information about reports from Google TI feeds.

This class is responsible for fetching reports from Google TI feeds.
It inherits from the BaseFetcher class and implements the fetch method.

It will also orchestrate the fetching process for the sub entities related to reports.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Dict, List, Optional

import isodate  # type: ignore[import-untyped]
from connector.src.custom.fetchers.gti_reports.fetch_malware_families import (
    FetchMalwareFamilies,
)
from connector.src.custom.fetchers.gti_reports.fetch_threat_actors import (
    FetchThreatActors,
)
from connector.src.custom.interfaces.base_fetcher import BaseFetcher
from connector.src.custom.meta.gti_reports.reports_meta import (
    LAST_INGESTED_REPORT_MODIFICATION_DATE_STATE_KEY,
    LAST_WORK_START_DATE_STATE_KEY,
    MALWARE_FAMILIES_BROKER,
    REPORTS_BROKER,
    SENTINEL,
)
from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    GTIReportResponse,
)
from connector.src.custom.utils.paginate_helper import _fetch_paginated_data
from connector.src.octi.pubsub import broker
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.custom.configs.gti_config import GTIConfig
    from connector.src.utils.api_engine.api_client import ApiClient

LOG_PREFIX = "[Fetch Reports]"


class FetchReports(BaseFetcher):
    """Fetcher to gather information about reports from Google TI feeds.

    This class is responsible for fetching reports from Google TI feeds.
    It inherits from the BaseFetcher class and implements the fetch method.
    """

    def __init__(
        self,
        gti_config: "GTIConfig",
        api_client: "ApiClient",
        state: Dict[str, str],
        logger: Optional["Logger"] = None,
    ) -> None:
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

    async def fetch(self) -> bool:
        """Fetch reports from Google TI feeds."""
        try:
            await self._fetch_reports()
            await self._publish_sentinels()
        except ApiNetworkError as e:
            self._logger.error(
                f"{LOG_PREFIX} Network connectivity issue during fetch. Please check your internet connection: {str(e)}",
                meta={"error": str(e), "is_network_error": True},
            )  # type: ignore[call-arg]
            raise

        except Exception as e:
            self._logger.error(f"{LOG_PREFIX} Error fetching reports.", meta={"error": str(e)})  # type: ignore[call-arg]
            return False
        return True

    async def _fetch_reports(self) -> None:
        """Fetch reports from Google TI feeds using the API key and URL provided in the configuration.
        It converts the fetched reports into a validate pydantic model.
        It pushes the fetched reports into the pubsub broker for further processing.

        Raises:
            ApiNetworkError: If a network connectivity issue occurs.
            Exception: For any other errors during fetching.

        """
        last_work_start_date: Optional[str] = self._state.get(
            LAST_WORK_START_DATE_STATE_KEY
        )
        last_ingested_report_modification_date: Optional[str] = self._state.get(
            LAST_INGESTED_REPORT_MODIFICATION_DATE_STATE_KEY
        )

        start_date_iso_8601: Optional[str] = self._gti_config.import_start_date
        duration: timedelta = isodate.parse_duration(start_date_iso_8601)
        past_date: datetime = datetime.now() - duration
        start_date: str = past_date.strftime("%Y-%m-%d")

        if (
            last_work_start_date is not None
            and last_ingested_report_modification_date is not None
        ):
            last_date = datetime.fromisoformat(last_ingested_report_modification_date)
            start_date = last_date.strftime("%Y-%m-%d")

        base_url = self._gti_config.api_url
        endpoint = f"{base_url}/collections"
        self._logger.info(
            f"{LOG_PREFIX} Fetching reports from endpoint: {endpoint} since {start_date}."
        )

        headers = {"X-Apikey": self._gti_config.api_key, "accept": "application/json"}

        filters = f"collection_type:report last_modification_date:{start_date}+"
        self._logger.debug(f"{LOG_PREFIX} Fetching reports with filter: {filters}")

        report_types: List[str] | str = self._gti_config.report_types
        if report_types and "All" not in report_types:
            filters += f" report_type:{','.join(report_types)}"

        origins: List[str] | str = self._gti_config.origins
        if origins and "All" not in origins:
            filters += f" origin:{','.join(origins)}"

        query_params = {
            "filter": filters,
            "limit": 40,
            "order": "last_modification_date+",
        }

        await _fetch_paginated_data(
            api_client=self._api_client,
            model=GTIReportResponse,
            url=endpoint,
            headers=headers,
            params=query_params,
            data_processor=self.process_report_data,
            logger=self._logger,
        )

    async def process_report_data(
        self,
        gti_response: GTIReportResponse,
        retrieved_reports_count: int,
        total_reports_count: int,
    ) -> None:
        """Process the report data from the GTI API response.

        Args:
            gti_response (GTIReportResponse): The response from the GTI API.
            retrieved_reports_count (int): The count of retrieved reports.
            total_reports_count (int): The total count of reports.

        """
        self._logger.info(
            f"{LOG_PREFIX} Fetched {len(gti_response.data)} reports from current page, {retrieved_reports_count}/{total_reports_count} reports."
        )

        await self._publish_reports(gti_response.data)
        await self._orchestrate_subfetches(gti_response.data)

    async def _publish_reports(self, reports: List[GTIReportData]) -> None:
        """Publish the fetched reports into the pubsub broker for further processing."""
        await broker.publish(REPORTS_BROKER, reports)
        self._logger.info(
            f"{LOG_PREFIX} {len(reports)} reports published to broker for processing."
        )

    async def _publish_sentinels(self) -> None:
        """Publish the fetched sentinels into the pubsub broker to signal the end of the fetch."""
        await broker.publish(REPORTS_BROKER, SENTINEL)
        await broker.publish(MALWARE_FAMILIES_BROKER, SENTINEL)
        self._logger.info(
            f"{LOG_PREFIX} Ends of data fetched, Sentinels published to broker."
        )

    async def _orchestrate_subfetches(self, reports: List[GTIReportData]) -> None:
        """Orchestrate the subfetches of the reports."""
        tasks = []
        for report in reports:
            tasks.append(
                FetchMalwareFamilies(
                    gti_config=self._gti_config,
                    api_client=self._api_client,
                    report=report,
                    logger=self._logger,
                ).fetch()
            )
            tasks.append(
                FetchThreatActors(
                    gti_config=self._gti_config,
                    api_client=self._api_client,
                    report=report,
                    logger=self._logger,
                ).fetch()
            )
        await asyncio.gather(*tasks)
