"""Report fetcher for Google Threat Intelligence API.

This module provides functionality to fetch reports from the Google Threat Intelligence API
with pagination support and batch processing capabilities.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import isodate  # type: ignore[import-untyped]
from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions import (
    GTIApiError,
    GTIPaginationError,
    GTIParsingError,
    GTIReportFetchError,
)
from connector.src.custom.fetchers.base_fetcher import BaseFetcher
from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    GTIReportResponse,
)
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError


class ReportFetcher(BaseFetcher):
    """Fetcher for report entities with pagination support."""

    def __init__(
        self,
        gti_config: GTIConfig,
        api_client: ApiClient,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the report fetcher.

        Args:
            gti_config: Configuration for accessing the GTI API
            api_client: Client for making API requests
            logger: Logger for logging messages

        """
        super().__init__(gti_config, api_client, logger)
        self.current_page_reports: List[GTIReportData] = []
        self.latest_modified_date: Optional[str] = None

    async def fetch_reports_in_batches(
        self, state: Dict[str, str], process_func: Callable[[Any], Any]
    ) -> None:
        """Fetch reports from the GTI API in batches and process them.

        Args:
            state: Dictionary containing state information (e.g., last_report_date)
            process_func: Function to process each page of reports

        Raises:
            GTIReportFetchError: If there's an error fetching reports

        """
        try:
            start_date_iso_8601 = self.config.import_start_date
            duration = isodate.parse_duration(start_date_iso_8601)
            past_date = datetime.now() - duration
            start_date = past_date.strftime("%Y-%m-%dT%H:%M:%S")

            last_mod_date = state.get("last_report_date")
            if last_mod_date:
                start_date = datetime.fromisoformat(last_mod_date).strftime(
                    "%Y-%m-%dT%H:%M:%S"
                )

            filters = f"collection_type:report last_modification_date:{start_date}+"

            report_types = self.config.report_types
            origins = self.config.origins

            if (not report_types or "All" in report_types) and (
                not origins or "All" in origins
            ):
                params = {
                    "filter": filters,
                    "limit": 40,
                    "order": "last_modification_date+",
                }
                self.logger.info(
                    f"Fetching all reports from GTI API (from {start_date})"
                )
                await self._fetch_paginated_data(
                    endpoint=f"{self.config.api_url}/collections",
                    params=params,
                    model=GTIReportResponse,
                    process_func=process_func,
                )
            else:
                for report_type in report_types:
                    for origin in origins:
                        if origin == "All":
                            report_filter = f'{filters} report_type:"{report_type}"'
                        else:
                            report_filter = (
                                f'{filters} report_type:"{report_type}" origin:{origin}'
                            )
                        params = {
                            "filter": report_filter,
                            "limit": 40,
                            "order": "last_modification_date+",
                        }

                        self.logger.info(
                            f"Fetching reports with type={report_type}, origin={origin} (from {start_date})"
                        )

                        await self._fetch_paginated_data(
                            endpoint=f"{self.config.api_url}/collections",
                            params=params,
                            model=GTIReportResponse,
                            process_func=process_func,
                        )

        except ApiNetworkError as e:
            raise GTIReportFetchError(
                f"Network error fetching reports: {str(e)}",
                endpoint=f"{self.config.api_url}/collections",
            ) from e
        except GTIReportFetchError:
            raise
        except Exception as e:
            raise GTIReportFetchError(
                f"Failed to fetch reports: {str(e)}",
                endpoint=f"{self.config.api_url}/collections",
            ) from e

    async def process_report_page(
        self, response: GTIReportResponse
    ) -> List[GTIReportData]:
        """Process a page of report data.

        Args:
            response: The API response containing report data

        Returns:
            List of processed reports from the current page

        Raises:
            GTIParsingError: If there's an error parsing the report data

        """
        try:
            if not hasattr(response, "data") or not response.data:
                self.logger.warning("Received empty response data")
                return []

            items_in_page = len(response.data)
            current_page_reports = []

            for report in response.data:
                current_page_reports.append(report)

                if (
                    hasattr(report, "last_modification_date")
                    and report.last_modification_date
                ):
                    try:
                        report_date = datetime.fromisoformat(
                            report.last_modification_date.replace("Z", "+00:00")
                        )

                        if (
                            not self.latest_modified_date
                            or report_date
                            > datetime.fromisoformat(
                                self.latest_modified_date.replace("Z", "+00:00")
                            )
                        ):
                            self.latest_modified_date = report_date.astimezone(
                                timezone.utc
                            ).isoformat()
                    except ValueError as ve:
                        raise GTIParsingError(
                            f"Invalid date format: {report.last_modification_date}",
                            entity_type="report",
                            data_sample=report.last_modification_date,
                        ) from ve

            self.current_page_reports = current_page_reports

            self.logger.info(f"Processed page with {items_in_page} reports")
            return current_page_reports
        except GTIParsingError:
            raise
        except Exception as e:
            raise GTIParsingError(
                f"Failed to process report page: {str(e)}",
                entity_type="report",
                endpoint="/collections",
            ) from e

    async def _fetch_paginated_data(
        self,
        endpoint: str,
        params: Dict[str, Any],
        model: Any,
        process_func: Callable[[Any], Any],
    ) -> None:
        """Fetch paginated data from the API.

        Args:
            endpoint: API endpoint to fetch data from
            params: Query parameters
            model: Model class for response data
            process_func: Function to process each page of data

        Raises:
            GTIPaginationError: If there's an error with pagination
            GTIApiError: If there's an error with the API call
            GTIParsingError: If there's an error parsing the response

        """
        current_url = endpoint
        current_params = params

        page_count = 0
        start_time = datetime.now()
        endpoint_name = self._extract_endpoint_name(endpoint)
        self.logger.info(f"Starting paginated data fetch from {endpoint_name}")

        while current_url:
            page_count += 1

            elapsed = datetime.now() - start_time
            self.logger.info(
                f"Fetching page {page_count} from {endpoint_name} (elapsed: {elapsed})"
            )

            try:
                response = await self.api_client.call_api(
                    url=current_url,
                    headers=self.headers,
                    params=current_params,
                    model=model,
                    timeout=60,
                )

                items_count = 0
                if hasattr(response, "data"):
                    if isinstance(response.data, list):
                        items_count = len(response.data)
                    elif isinstance(response.data, dict) and "data" in response.data:
                        items_count = len(response.data["data"])
                elif isinstance(response, dict) and "data" in response:
                    if isinstance(response["data"], list):
                        items_count = len(response["data"])

                current_endpoint = self._extract_endpoint_name(current_url)
                self.logger.info(
                    f"Processing page {page_count} with {items_count} items (endpoint: {current_endpoint})"
                )

                try:
                    await process_func(response)
                except GTIParsingError:
                    raise
                except Exception as proc_err:
                    sample_data = str(response)[:200] if str(response) else ""
                    raise GTIParsingError(
                        f"Error processing page {page_count}: {str(proc_err)}",
                        endpoint=current_url,
                        data_sample=sample_data,
                    ) from proc_err

                try:
                    if (
                        hasattr(response, "links")
                        and hasattr(response.links, "next")
                        and response.links.next
                    ):
                        current_url = response.links.next
                        current_params = {}
                    else:
                        break
                except Exception as link_err:
                    raise GTIPaginationError(
                        f"Error extracting next page link: {str(link_err)}",
                        endpoint=current_url,
                        page=page_count,
                    ) from link_err

            except asyncio.CancelledError:
                self.logger.info(f"Pagination fetch cancelled for {current_url}")
                raise
            except ApiNetworkError as net_err:
                self._log_error(
                    f"Network error fetching data from {current_url}: {str(net_err)}",
                    error=net_err,
                )
                raise GTIApiError(
                    f"Network error: {str(net_err)}", endpoint=current_url
                ) from net_err
            except GTIPaginationError:
                raise
            except GTIApiError:
                raise
            except Exception as e:
                self._log_error(
                    f"Error fetching data from {current_url}: {str(e)}", error=e
                )

                if (
                    "page" in str(e).lower()
                    or "next" in str(e).lower()
                    or "link" in str(e).lower()
                ):
                    raise GTIPaginationError(
                        f"Pagination error: {str(e)}",
                        endpoint=current_url,
                        page=page_count,
                    ) from e
                else:
                    raise GTIApiError(
                        f"API error: {str(e)}", endpoint=current_url
                    ) from e

    def get_latest_modified_date(self) -> Optional[str]:
        """Get the latest modification date from processed reports.

        Returns:
            Latest modification date in ISO format, or None if no reports processed

        """
        return self.latest_modified_date

    def get_current_page_reports(self) -> List[GTIReportData]:
        """Get the current page of reports.

        Returns:
            List of reports from the current page

        """
        return self.current_page_reports
