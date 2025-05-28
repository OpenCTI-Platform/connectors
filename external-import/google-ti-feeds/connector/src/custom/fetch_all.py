"""Simple orchestrator for Google Threat Intelligence data fetching.

This module provides an orchestrator approach to fetching data from the Google Threat Intelligence API.
It coordinates multiple specialized fetchers to fetch reports and their related entities efficiently.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from connector.src.custom.batch_processor import BatchProcessor
from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions import (
    GTIApiError,
    GTIFetchingError,
    GTIParsingError,
)
from connector.src.custom.fetchers.entity_fetcher import EntityFetcher
from connector.src.custom.fetchers.report_fetcher import ReportFetcher
from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    GTIReportResponse,
)
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError


class FetchAll:
    """Orchestrator for Google Threat Intelligence data fetching.

    This class coordinates the fetching of reports and their related entities
    using specialized fetchers for different entity types. It maintains the
    same batch processing workflow but delegates the actual fetching to
    specialized classes.
    """

    def __init__(
        self,
        gti_config: GTIConfig,
        api_client: ApiClient,
        state: Optional[Dict[str, str]] = None,
        logger: Optional[logging.Logger] = None,
        batch_processor: Optional[BatchProcessor] = None,
    ):
        """Initialize the GTI data orchestrator.

        Args:
            gti_config: Configuration for accessing the GTI API
            api_client: Client for making API requests
            state: Dictionary for storing state between runs
            batch_processor: Optional processor for handling batches of data
            logger: Logger for logging messages

        """
        self.stix_converter = None
        self.config = gti_config
        self.api_client = api_client
        self.state = state or {}
        self.logger = logger or logging.getLogger(__name__)
        self.batch_processor = batch_processor

        self.report_fetcher = ReportFetcher(gti_config, api_client, logger)
        self.entity_fetcher = EntityFetcher(gti_config, api_client, logger)

        self.reports: List[GTIReportData] = []
        self.report_related_entities: Dict[str, Dict[str, List[Any]]] = {}
        self.reports_with_complete_entities: set[str] = set()
        self.current_page_reports: List[GTIReportData] = []
        self.all_stix_objects: List[Any] = []
        self.latest_modified_date: Optional[str] = None

    def _prepare_partial_results(
        self, source: str
    ) -> Tuple[List[GTIReportData], Dict[str, Dict[str, List[Any]]], Optional[str]]:
        """Prepare partial results when processing is interrupted.

        Args:
            source: Description of why partial results are being returned

        Returns:
            Tuple containing filtered reports, related entities, and latest modified date

        """
        complete_reports = [
            report
            for report in self.reports
            if report.id in self.reports_with_complete_entities
        ]
        self.logger.info(
            f"[{source}] Returning {len(complete_reports)} complete reports out of {len(self.reports)} total fetched"
        )

        complete_related_entities = {
            report_id: entities
            for report_id, entities in self.report_related_entities.items()
            if report_id in self.reports_with_complete_entities
        }

        if complete_reports:
            try:
                complete_reports.sort(
                    key=lambda x: (
                        x.last_modification_date
                        if hasattr(x, "last_modification_date")
                        and x.last_modification_date
                        else ""
                    ),
                    reverse=True,
                )
            except Exception as sort_err:
                self.logger.warning(f"Could not sort reports: {str(sort_err)}")

        return complete_reports, complete_related_entities, self.latest_modified_date

    async def fetch_all_data(
        self,
    ) -> Tuple[List[Any], Dict[str, Dict[str, List[Any]]], Optional[str]]:
        """Fetch all GTI data using a batch processing workflow.

        This method orchestrates the fetching process:
        1. Fetches reports in batches using ReportFetcher
        2. For each batch, fetches related entities using EntityFetcher
        3. Converts each batch to STIX if needed
        4. Continues to the next batch

        Returns:
            Tuple containing:
                - List of reports
                - Dictionary mapping report IDs to their related entities
                - Latest modification date (ISO format) of successfully processed reports

        Raises:
            GTIFetchingError: Base class for all fetching errors
            GTIApiError: If an API error occurs
            GTIParsingError: If there's an error parsing API responses
            ApiNetworkError: If a network connectivity issue occurs
            asyncio.CancelledError: If the operation is cancelled

        """
        try:
            self.logger.info("Starting to fetch GTI data using orchestrated fetchers")

            self.reports = []
            self.report_related_entities = {}
            self.reports_with_complete_entities = set()
            self.current_page_reports = []
            self.all_stix_objects = []
            self.latest_modified_date = None

            if not self.batch_processor:
                from .convert_to_stix import ConvertToSTIX

                self.stix_converter = ConvertToSTIX(
                    tlp_level="amber", logger=self.logger
                )

            await self._fetch_reports_in_batches()

            self.logger.info(
                f"Total reports processed: {len(self.reports_with_complete_entities)}"
            )

            self.reports.sort(
                key=lambda x: (
                    x.last_modification_date
                    if hasattr(x, "last_modification_date") and x.last_modification_date
                    else ""
                ),
                reverse=True,
            )
            return self.reports, self.report_related_entities, self.latest_modified_date

        except asyncio.CancelledError:
            self.logger.info("Fetch operation was cancelled")
            return self._prepare_partial_results("Cancelled")
        except ApiNetworkError as e:
            self.logger.error(f"Network connectivity issue: {str(e)}")
            GTIApiError(f"Network connectivity issue: {str(e)}", endpoint="multiple")
            return self._prepare_partial_results("Network error")
        except GTIFetchingError as e:
            self.logger.error(f"GTI fetch error: {str(e)}")
            return self._prepare_partial_results("Fetch error")
        except Exception as e:
            self.logger.error(f"Error fetching GTI data: {str(e)}")
            GTIFetchingError(f"Unexpected error fetching GTI data: {str(e)}")
            return self._prepare_partial_results("Exception")

    async def _fetch_reports_in_batches(self) -> None:
        """Orchestrate the batch fetching of reports.

        This method uses the ReportFetcher to handle the pagination and
        calls the processing function for each page of reports.
        """
        try:
            await self.report_fetcher.fetch_reports_in_batches(
                state=self.state, process_func=self._process_report_page
            )

            total_reports = len(
                [r for r in self.reports if r.id in self.reports_with_complete_entities]
            )
            self.logger.info(f"Fetched and processed {total_reports} reports")

        except Exception as e:
            self.logger.error(f"Error in batch report fetching: {str(e)}")
            raise

    async def _process_report_page(self, response: GTIReportResponse) -> None:
        """Process a page of report data and trigger entity fetching.

        Args:
            response: The API response containing report data

        Raises:
            GTIParsingError: If there's an error parsing the report data

        """
        try:
            current_page_reports = await self.report_fetcher.process_report_page(
                response
            )

            if not current_page_reports:
                return

            fetcher_latest_date = self.report_fetcher.get_latest_modified_date()
            if fetcher_latest_date:
                if (
                    not self.latest_modified_date
                    or fetcher_latest_date > self.latest_modified_date
                ):
                    self.latest_modified_date = fetcher_latest_date

            self.current_page_reports = current_page_reports

            await self._process_current_page_reports()

        except GTIParsingError:
            raise
        except Exception as e:
            raise GTIParsingError(
                f"Failed to process report page: {str(e)}",
                entity_type="report",
                endpoint="/collections",
            ) from e

    async def _process_current_page_reports(self) -> None:
        """Process the current page of reports.

        This method implements the batch processing workflow using the EntityFetcher:
        1. Process a page of reports (typically 40 reports)
        2. Fetch all sub-entities for those reports using EntityFetcher
        3. Convert those reports and their sub-entities to STIX
        4. Move to the next page and repeat until all data is processed
        """
        if not self.current_page_reports:
            return

        self.logger.info(
            f"Processing batch of {len(self.current_page_reports)} reports"
        )
        page_start_time = datetime.now()
        batch_reports = []
        batch_report_related_entities = {}

        for i, report in enumerate(self.current_page_reports):
            await asyncio.sleep(0.01)
            report_id = report.id

            self.logger.info(
                f"Processing report {i + 1}/{len(self.current_page_reports)} in batch - ID: {report_id}"
            )

            self.report_related_entities[report_id] = {
                "malware_families": [],
                "threat_actors": [],
                "attack_techniques": [],
                "vulnerabilities": [],
            }

            try:
                related_entities = (
                    await self.entity_fetcher.fetch_report_related_entities(
                        report, i + 1, len(self.current_page_reports)
                    )
                )

                self.report_related_entities[report_id].update(related_entities)
                batch_report_related_entities[report_id] = related_entities.copy()

                self.reports_with_complete_entities.add(report_id)
                batch_reports.append(report)

            except Exception as e:
                self.logger.error(
                    f"Failed to fetch entities for report {report_id}: {str(e)}"
                )
                continue

        if self.batch_processor:
            self.logger.info(f"Using batch processor for {len(batch_reports)} reports")

            if self.latest_modified_date:
                self.batch_processor.set_latest_modified_date(self.latest_modified_date)

            self.batch_processor.process_batch(
                reports=batch_reports, related_entities=batch_report_related_entities
            )

            latest_date = self.batch_processor.get_latest_modified_date()
            if latest_date:
                if (
                    not self.latest_modified_date
                    or latest_date > self.latest_modified_date
                ):
                    self.latest_modified_date = latest_date
        else:
            self.logger.info(
                f"Converting batch of {len(batch_reports)} reports to STIX"
            )
            stix_objects = self.stix_converter.convert_all_data(
                reports=batch_reports, related_entities=batch_report_related_entities
            )
            self.all_stix_objects.extend(stix_objects)
            self.logger.info(
                f"Generated {len(stix_objects)} STIX objects for the batch"
            )

        for report in batch_reports:
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
                except ValueError:
                    self.logger.warning(
                        f"Invalid date format in report: {report.last_modification_date}"
                    )

        self.reports.extend(batch_reports)

        if self.latest_modified_date:
            self.logger.info(
                f"Current latest modification date: {self.latest_modified_date}"
            )

        batch_elapsed = datetime.now() - page_start_time
        self.logger.info(f"Completed batch processing in {batch_elapsed}")

        self.current_page_reports = []
