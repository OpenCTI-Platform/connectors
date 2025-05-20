"""Simple fetcher for Google Threat Intelligence data.

This module provides a simpler approach to fetching data from the Google Threat Intelligence API.
Instead of multiple specialized fetchers, it uses a single class to fetch all types of data.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import isodate

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions import (
    GTIActorFetchError,
    GTIApiError,
    GTIFetchingError,
    GTIMalwareFetchError,
    GTIPaginationError,
    GTIParsingError,
    GTIRelationshipFetchError,
    GTIReportFetchError,
    GTITechniqueFetchError,
    GTIVulnerabilityFetchError,
)
from connector.src.custom.models.gti_reports.gti_attack_technique_model import (
    GTIAttackTechniqueResponse,
)
from connector.src.custom.models.gti_reports.gti_malware_family_model import (
    GTIMalwareFamilyResponse,
)
from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    GTIReportResponse,
)
from connector.src.custom.models.gti_reports.gti_threat_actor_model import GTIThreatActorResponse
from connector.src.custom.models.gti_reports.gti_vulnerability_model import GTIVulnerabilityResponse
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError


class FetchAll:
    """A simple fetcher for Google Threat Intelligence data.

    This class fetches reports and their related entities (threat actors, malware families,
    attack techniques, vulnerabilities) from the Google Threat Intelligence API.
    """

    def __init__(
        self,
        gti_config: GTIConfig,
        api_client: ApiClient,
        state: Dict[str, str] = None,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the GTI data fetcher.

        Args:
            gti_config: Configuration for accessing the GTI API
            api_client: Client for making API requests
            state: Dictionary for storing state between runs
            logger: Logger for logging messages

        """
        self.config = gti_config
        self.api_client = api_client
        self.state = state or {}
        self.logger = logger or logging.getLogger(__name__)
        self.headers = {
            "X-Apikey": self.config.api_key,
            "accept": "application/json",
        }

        self.reports = []
        self.report_related_entities = {}
        self.reports_with_complete_entities = set()
        self.latest_modified_date = None

    def _extract_endpoint_name(self, url: str) -> str:
        """Extract a readable endpoint name from a URL.

        Args:
            url: The URL to extract from

        Returns:
            A simplified endpoint name for logging

        """
        try:
            parts = url.split("/")
            if len(parts) > 0:
                last_part = parts[-1]

                if "?" in last_part:
                    last_part = last_part.split("?")[0]
                return last_part
            return url
        except Exception:
            return url

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
            report for report in self.reports if report.id in self.reports_with_complete_entities
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
                    key=lambda x: x.last_modification_date
                    if hasattr(x, "last_modification_date") and x.last_modification_date
                    else "",
                    reverse=True,
                )
            except Exception as sort_err:
                self.logger.warning(f"Could not sort reports: {str(sort_err)}")

        return complete_reports, complete_related_entities, self.latest_modified_date

    async def fetch_all_data(
        self,
    ) -> Tuple[List[GTIReportData], Dict[str, Dict[str, List[Any]]], Optional[str]]:
        """Fetch all GTI data.

        Returns:
            Tuple containing:
                - List of reports
                - Dictionary mapping report IDs to their related entities
                - Latest modification date (ISO format) of successfully processed reports

        Raises:
            GTIFetchingError: Base class for all fetching errors
            GTIApiError: If an API error occurs
            GTIReportFetchError: If there's an error fetching reports
            GTIParsingError: If there's an error parsing API responses
            GTIPaginationError: If there's an error with pagination
            ApiNetworkError: If a network connectivity issue occurs
            asyncio.CancelledError: If the operation is cancelled

        """
        try:
            self.logger.info("Starting to fetch GTI data")

            self.reports = []
            self.report_related_entities = {}
            self.reports_with_complete_entities = set()

            await self._fetch_reports()

            total_reports = len(self.reports)

            self.reports.sort(
                key=lambda x: x.last_modification_date
                if hasattr(x, "last_modification_date") and x.last_modification_date
                else "",
                reverse=True,
            )

            for i, report in enumerate(self.reports):
                await asyncio.sleep(0.01)

                if i % 5 == 0 or i == 0 or i == total_reports - 1:
                    self.logger.info(
                        f"Processing report {i + 1}/{total_reports} ({(i + 1) / total_reports * 100:.1f}%) - ID: {report.id}..."
                    )

                report_id = report.id
                self.report_related_entities[report_id] = {
                    "malware_families": [],
                    "threat_actors": [],
                    "attack_techniques": [],
                    "vulnerabilities": [],
                }

                await self._fetch_report_related_entities(report, i + 1, total_reports)

                self.reports_with_complete_entities.add(report.id)
                self.logger.info(
                    f"Marked report {report.id}... as complete ({i + 1}/{total_reports}) - {(i + 1) / total_reports * 100:.1f}% done"
                )

                if i % 10 == 9 or i == total_reports - 1:
                    self.logger.info(
                        f"Progress checkpoint: {len(self.reports_with_complete_entities)} complete reports out of {len(self.reports)} total fetched"
                    )
                    self.logger.info(
                        f"Overall progress: {i + 1}/{total_reports} reports processed ({(i + 1) / total_reports * 100:.1f}%)"
                    )

            return self.reports, self.report_related_entities, self.latest_modified_date

        except asyncio.CancelledError:
            self.logger.info("Fetch operation was cancelled")
            return self._prepare_partial_results("Cancelled")
        except ApiNetworkError as e:
            self.logger.error(f"Network connectivity issue: {str(e)}", meta={"error": str(e)})

            GTIApiError(f"Network connectivity issue: {str(e)}", endpoint="multiple")
            return self._prepare_partial_results("Network error")
        except GTIFetchingError as e:
            self.logger.error(f"GTI fetch error: {str(e)}", meta={"error": str(e)})
            return self._prepare_partial_results("Fetch error")
        except Exception as e:
            self.logger.error(f"Error fetching GTI data: {str(e)}", meta={"error": str(e)})

            GTIFetchingError(f"Unexpected error fetching GTI data: {str(e)}")
            return self._prepare_partial_results("Exception")

    async def _fetch_reports(self) -> None:
        """Fetch reports from the GTI API.

        Raises:
            GTIReportFetchError: If there's an error fetching reports

        """
        try:
            start_date_iso_8601 = self.config.import_start_date
            duration = isodate.parse_duration(start_date_iso_8601)
            past_date = datetime.now() - duration
            start_date = past_date.strftime("%Y-%m-%dT%H:%M:%S")

            last_mod_date = self.state.get("last_work_date")
            if last_mod_date:
                start_date = datetime.fromisoformat(last_mod_date).strftime("%Y-%m-%dT%H:%M:%S")

            filters = f"collection_type:report last_modification_date:{start_date}+"

            report_types = self.config.report_types
            if report_types and "All" not in report_types:
                filters += f" report_type:{','.join(report_types)}"

            origins = self.config.origins
            if origins and "All" not in origins:
                filters += f" origin:{','.join(origins)}"

            params = {
                "filter": filters,
                "limit": 40,
                "order": "last_modification_date+",
            }

            self.logger.info(f"Fetching reports from GTI API (from {start_date})")

            await self._fetch_paginated_data(
                endpoint=f"{self.config.api_url}/collections",
                params=params,
                model=GTIReportResponse,
                process_func=self._process_report_page,
            )

            self.logger.info(f"Fetched {len(self.reports)} reports (from {start_date}).")
        except ApiNetworkError as e:
            raise GTIReportFetchError(
                f"Network error fetching reports: {str(e)}",
                endpoint=f"{self.config.api_url}/collections",
            ) from e
        except GTIReportFetchError:
            raise
        except Exception as e:
            raise GTIReportFetchError(
                f"Failed to fetch reports: {str(e)}", endpoint=f"{self.config.api_url}/collections"
            ) from e

    async def _process_report_page(self, response: GTIReportResponse) -> None:
        """Process a page of report data.

        Args:
            response: The API response containing report data

        Raises:
            GTIParsingError: If there's an error parsing the report data

        """
        try:
            if not hasattr(response, "data") or not response.data:
                self.logger.warning("Received empty response data")
                return

            items_in_page = len(response.data)
            self.reports.extend(response.data)

            for report in response.data:
                if hasattr(report, "last_modification_date") and report.last_modification_date:
                    try:
                        report_date = datetime.fromisoformat(
                            report.last_modification_date.replace("Z", "+00:00")
                        )

                        if not self.latest_modified_date or report_date > datetime.fromisoformat(
                            self.latest_modified_date.replace("Z", "+00:00")
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

            self.logger.info(
                f"Processed page with {items_in_page} reports, total reports so far: {len(self.reports)}"
            )
        except GTIParsingError:
            raise
        except Exception as e:
            raise GTIParsingError(
                f"Failed to process report page: {str(e)}",
                entity_type="report",
                endpoint="/collections",
            ) from e

    async def _fetch_report_related_entities(
        self, report: GTIReportData, report_index: int = 0, total_reports: int = 0
    ) -> None:
        """Fetch entities related to a specific report.

        Args:
            report: The report for which to fetch related entities
            report_index: Current report index (for progress tracking)
            total_reports: Total number of reports (for progress tracking)

        Raises:
            GTIRelationshipFetchError: If there's an error fetching related entities

        """
        report_id = report.id
        progress_info = f"({report_index}/{total_reports} reports) " if total_reports > 0 else ""
        self.logger.info(f"{progress_info}Fetching related entities for report {report_id}...")

        try:
            await asyncio.sleep(0)
            await self._fetch_malware_families(report)

            await asyncio.sleep(0)
            await self._fetch_threat_actors(report)

            await asyncio.sleep(0)
            await self._fetch_attack_techniques(report)

            await asyncio.sleep(0)
            await self._fetch_vulnerabilities(report)

            self.logger.info(f"Successfully fetched all related entities for report {report_id}...")

        except asyncio.CancelledError:
            self.logger.info(f"Entity fetch cancelled for report {report_id}...")
            raise
        except GTIFetchingError as e:
            self.logger.error(
                f"Error fetching related entities for report {report_id}: {str(e)}",
                meta={"error": str(e), "report_id": report_id},
            )
            raise GTIRelationshipFetchError(
                str(e), source_id=report_id, relationship_type="report_entities"
            ) from e
        except Exception as e:
            self.logger.error(
                f"Unexpected error fetching related entities for report {report_id}: {str(e)}",
                meta={"error": str(e), "report_id": report_id},
            )
            raise GTIRelationshipFetchError(
                f"Unexpected error: {str(e)}",
                source_id=report_id,
                relationship_type="report_entities",
            ) from e

            raise
        except Exception as e:
            self.logger.error(f"Entity fetch failed for report {report_id}...: {str(e)}")

            raise

    async def _fetch_malware_families(self, report: GTIReportData) -> None:
        """Fetch malware families related to a report.

        Args:
            report: The report for which to fetch malware families

        Raises:
            GTIMalwareFetchError: If there's an error fetching malware families

        """
        report_id = report.id
        self.logger.info(f"Fetching malware families for report {report_id}...")

        try:
            malware_ids = await self._fetch_relationship_ids(
                report_id=report_id, relationship_type="malware_families"
            )

            for malware_id in malware_ids:
                try:
                    endpoint = f"{self.config.api_url}/collections/{malware_id}"
                    response = await self.api_client.call_api(
                        url=endpoint,
                        headers=self.headers,
                        model=GTIMalwareFamilyResponse,
                        timeout=60,
                    )

                    if response and hasattr(response, "data"):
                        self.report_related_entities[report_id]["malware_families"].append(
                            response.data
                        )
                except ApiNetworkError as net_err:
                    raise GTIMalwareFetchError(
                        f"Network error: {str(net_err)}", malware_id=malware_id, endpoint=endpoint
                    ) from net_err
                except Exception as e:
                    self.logger.error(
                        f"Error fetching malware family {malware_id}: {str(e)}",
                        meta={"error": str(e)},
                    )

            malware_count = len(self.report_related_entities[report_id]["malware_families"])
            if malware_count > 0:
                self.logger.info(f"Fetched {malware_count} malware families")
            else:
                self.logger.debug(f"No malware families found for report {report_id}")
        except GTIRelationshipFetchError as rel_err:
            raise GTIMalwareFetchError(
                f"Failed to fetch malware relationship IDs: {str(rel_err)}",
                endpoint=f"{self.config.api_url}/collections/{report_id}/malware_families",
            ) from rel_err
        except (ApiNetworkError, GTIMalwareFetchError):
            raise
        except Exception as e:
            raise GTIMalwareFetchError(
                f"Unexpected error fetching malware families: {str(e)}",
                endpoint=f"{self.config.api_url}/collections/{report_id}/malware_families",
            ) from e

    async def _fetch_threat_actors(self, report: GTIReportData) -> None:
        """Fetch threat actors related to a report.

        Args:
            report: The report for which to fetch threat actors

        Raises:
            GTIActorFetchError: If there's an error fetching threat actors

        """
        report_id = report.id
        self.logger.info(f"Fetching threat actors for report {report_id}...")

        try:
            actor_ids = await self._fetch_relationship_ids(
                report_id=report_id, relationship_type="threat_actors"
            )

            for actor_id in actor_ids:
                try:
                    endpoint = f"{self.config.api_url}/collections/{actor_id}"
                    response = await self.api_client.call_api(
                        url=endpoint,
                        headers=self.headers,
                        model=GTIThreatActorResponse,
                        timeout=60,
                    )

                    if response and hasattr(response, "data"):
                        self.report_related_entities[report_id]["threat_actors"].append(
                            response.data
                        )
                except ApiNetworkError as net_err:
                    raise GTIActorFetchError(
                        f"Network error: {str(net_err)}", actor_id=actor_id, endpoint=endpoint
                    ) from net_err
                except Exception as e:
                    self.logger.error(
                        f"Error fetching threat actor {actor_id}: {str(e)}", meta={"error": str(e)}
                    )

            actor_count = len(self.report_related_entities[report_id]["threat_actors"])
            if actor_count > 0:
                self.logger.info(f"Fetched {actor_count} threat actors")
            else:
                self.logger.debug(f"No threat actors found for report {report_id}")
        except GTIRelationshipFetchError as rel_err:
            raise GTIActorFetchError(
                f"Failed to fetch threat actor relationship IDs: {str(rel_err)}",
                endpoint=f"{self.config.api_url}/collections/{report_id}/threat_actors",
            ) from rel_err
        except (ApiNetworkError, GTIActorFetchError):
            raise
        except Exception as e:
            raise GTIActorFetchError(
                f"Unexpected error fetching threat actors: {str(e)}",
                endpoint=f"{self.config.api_url}/collections/{report_id}/threat_actors",
            ) from e

    async def _fetch_attack_techniques(self, report: GTIReportData) -> None:
        """Fetch attack techniques related to a report.

        Args:
            report: The report for which to fetch attack techniques

        Raises:
            GTITechniqueFetchError: If there's an error fetching attack techniques

        """
        report_id = report.id
        self.logger.info(f"Fetching attack techniques for report {report_id}...")

        try:
            technique_ids = await self._fetch_relationship_ids(
                report_id=report_id, relationship_type="attack_techniques"
            )

            for technique_id in technique_ids:
                try:
                    endpoint = f"{self.config.api_url}/collections/{technique_id}"
                    response = await self.api_client.call_api(
                        url=endpoint,
                        headers=self.headers,
                        model=GTIAttackTechniqueResponse,
                        timeout=60,
                    )

                    if response and hasattr(response, "data"):
                        self.report_related_entities[report_id]["attack_techniques"].append(
                            response.data
                        )
                except ApiNetworkError as net_err:
                    raise GTITechniqueFetchError(
                        f"Network error: {str(net_err)}",
                        technique_id=technique_id,
                        endpoint=endpoint,
                    ) from net_err
                except Exception as e:
                    self.logger.error(
                        f"Error fetching attack technique {technique_id}: {str(e)}",
                        meta={"error": str(e)},
                    )

            technique_count = len(self.report_related_entities[report_id]["attack_techniques"])
            if technique_count > 0:
                self.logger.info(f"Fetched {technique_count} attack techniques")
            else:
                self.logger.debug(f"No attack techniques found for report {report_id}")
        except GTIRelationshipFetchError as rel_err:
            raise GTITechniqueFetchError(
                f"Failed to fetch attack technique relationship IDs: {str(rel_err)}",
                endpoint=f"{self.config.api_url}/collections/{report_id}/attack_techniques",
            ) from rel_err
        except (ApiNetworkError, GTITechniqueFetchError):
            raise
        except Exception as e:
            raise GTITechniqueFetchError(
                f"Unexpected error fetching attack techniques: {str(e)}",
                endpoint=f"{self.config.api_url}/collections/{report_id}/attack_techniques",
            ) from e

    async def _fetch_vulnerabilities(self, report: GTIReportData) -> None:
        """Fetch vulnerabilities related to a report.

        Args:
            report: The report for which to fetch vulnerabilities

        Raises:
            GTIVulnerabilityFetchError: If there's an error fetching vulnerabilities

        """
        report_id = report.id
        self.logger.info(f"Fetching vulnerabilities for report {report_id}...")

        try:
            vulnerability_ids = await self._fetch_relationship_ids(
                report_id=report_id, relationship_type="vulnerabilities"
            )

            for vuln_id in vulnerability_ids:
                try:
                    endpoint = f"{self.config.api_url}/collections/{vuln_id}"
                    response = await self.api_client.call_api(
                        url=endpoint,
                        headers=self.headers,
                        model=GTIVulnerabilityResponse,
                        timeout=60,
                    )

                    if response and hasattr(response, "data"):
                        self.report_related_entities[report_id]["vulnerabilities"].append(
                            response.data
                        )
                except ApiNetworkError as net_err:
                    raise GTIVulnerabilityFetchError(
                        f"Network error: {str(net_err)}",
                        vulnerability_id=vuln_id,
                        endpoint=endpoint,
                    ) from net_err
                except Exception as e:
                    self.logger.error(
                        f"Error fetching vulnerability {vuln_id}: {str(e)}", meta={"error": str(e)}
                    )

            vulnerability_count = len(self.report_related_entities[report_id]["vulnerabilities"])
            if vulnerability_count > 0:
                self.logger.info(f"Fetched {vulnerability_count} vulnerabilities")
            else:
                self.logger.debug(f"No vulnerabilities found for report {report_id}")
        except GTIRelationshipFetchError as rel_err:
            raise GTIVulnerabilityFetchError(
                f"Failed to fetch vulnerability relationship IDs: {str(rel_err)}",
                endpoint=f"{self.config.api_url}/collections/{report_id}/vulnerabilities",
            ) from rel_err
        except (ApiNetworkError, GTIVulnerabilityFetchError):
            raise
        except Exception as e:
            raise GTIVulnerabilityFetchError(
                f"Unexpected error fetching vulnerabilities: {str(e)}",
                endpoint=f"{self.config.api_url}/collections/{report_id}/vulnerabilities",
            ) from e

    async def _fetch_relationship_ids(self, report_id: str, relationship_type: str) -> List[str]:
        """Fetch IDs of entities related to a report through a specific relationship.

        Args:
            report_id: ID of the report
            relationship_type: Type of relationship (e.g., "malware_families")

        Returns:
            List of entity IDs

        Raises:
            GTIRelationshipFetchError: If there's an error fetching relationship IDs

        """
        entity_ids = []
        endpoint = (
            f"{self.config.api_url}/collections/{report_id}/relationships/{relationship_type}"
        )

        try:
            response = await self.api_client.call_api(
                url=endpoint,
                headers=self.headers,
                params={"limit": 40},
                timeout=60,
            )

            if response and isinstance(response, dict) and "data" in response:
                for item in response["data"]:
                    if isinstance(item, dict) and "id" in item:
                        entity_ids.append(item["id"])

                if len(entity_ids) > 0:
                    self.logger.info(
                        f"Found {len(entity_ids)} {relationship_type} for report {report_id}..."
                    )
                return entity_ids
        except ApiNetworkError as net_err:
            self.logger.error(
                f"Network error fetching {relationship_type} IDs for report {report_id}: {str(net_err)}",
                meta={"error": str(net_err)},
            )
            raise GTIRelationshipFetchError(
                f"Network error: {str(net_err)}",
                source_id=report_id,
                relationship_type=relationship_type,
                endpoint=endpoint,
            ) from net_err
        except Exception as e:
            self.logger.error(
                f"Error fetching {relationship_type} IDs for report {report_id}: {str(e)}",
                meta={"error": str(e)},
            )
            raise GTIRelationshipFetchError(
                f"Failed to fetch relationship IDs: {str(e)}",
                source_id=report_id,
                relationship_type=relationship_type,
                endpoint=endpoint,
            ) from e

    async def _fetch_paginated_data(
        self, endpoint: str, params: Dict, model: Any, process_func: callable
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
            await asyncio.sleep(0)

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
                    raise GTIParsingError(
                        f"Error processing page {page_count}: {str(proc_err)}",
                        endpoint=current_url,
                        data_sample=str(response)[:200] if str(response) else None,
                    ) from proc_err

                try:
                    if (
                        hasattr(response, "links")
                        and hasattr(response.links, "next")
                        and response.links.next
                    ):
                        current_url = response.links.next
                        current_params = None
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
                self.logger.error(
                    f"Network error fetching data from {current_url}: {str(net_err)}",
                    meta={"error": str(net_err)},
                )
                raise GTIApiError(
                    f"Network error: {str(net_err)}", endpoint=current_url
                ) from net_err
            except GTIApiError:
                raise
            except GTIPaginationError:
                raise
            except Exception as e:
                self.logger.error(
                    f"Error fetching data from {current_url}: {str(e)}", meta={"error": str(e)}
                )

                if "page" in str(e).lower() or "next" in str(e).lower() or "link" in str(e).lower():
                    raise GTIPaginationError(
                        f"Pagination error: {str(e)}", endpoint=current_url, page=page_count
                    ) from e
                else:
                    raise GTIApiError(f"API error: {str(e)}", endpoint=current_url) from e
