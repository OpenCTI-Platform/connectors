"""Generic entity fetcher for Google Threat Intelligence API.
This module provides a generic implementation for fetching entities
related to reports from the Google Threat Intelligence API. It replaces
the specialized fetchers with a configurable generic approach.
"""

import logging
from typing import Any, List, Optional

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions import GTIRelationshipFetchError
from connector.src.custom.fetchers.base_fetcher import BaseFetcher
from connector.src.custom.fetchers.entity_config import EntityFetcherConfig
from connector.src.custom.fetchers.relationship_fetcher import RelationshipFetcher
from connector.src.custom.models.gti_reports.gti_report_model import GTIReportData
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError


class GenericEntityFetcher(BaseFetcher):
    """Generic fetcher for any type of entity related to reports."""

    def __init__(
        self,
        config: EntityFetcherConfig,
        gti_config: GTIConfig,
        api_client: ApiClient,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the generic entity fetcher.

        Args:
            config: Configuration specifying entity type, endpoints, models, etc.
            gti_config: Configuration for accessing the GTI API
            api_client: Client for making API requests
            logger: Logger for logging messages

        """
        super().__init__(gti_config, api_client, logger)
        self.entity_config = config
        self.relationship_fetcher = RelationshipFetcher(gti_config, api_client, logger)

    async def fetch_entities(self, report: GTIReportData) -> List[Any]:
        """Fetch entities of the configured type related to a report.

        Args:
            report: The report for which to fetch entities
        Returns:
            List of entity objects
        Raises:
            Configured exception class: If there's an error fetching entities

        """
        report_id = report.id
        entities = []
        self._log_fetch_start(self.entity_config.display_name, report_id=report_id)
        try:
            self.logger.info(
                f"Fetching {self.entity_config.entity_type} IDs with relationship_type={self.entity_config.relationship_type} for report {report_id}"
            )
            entity_ids = await self.relationship_fetcher.fetch_relationship_ids(
                report_id=report_id,
                relationship_type=self.entity_config.relationship_type,
            )

            if entity_ids:
                self.logger.info(
                    f"Got {len(entity_ids)} {self.entity_config.entity_type} IDs to fetch: {entity_ids}"
                )
                self.logger.info(
                    f"Starting sequential API requests for {len(entity_ids)} {self.entity_config.entity_type} entities"
                )
                for idx, entity_id in enumerate(entity_ids):
                    try:
                        result = await self._fetch_single_entity(entity_id)
                        if result is not None:
                            self.logger.debug(
                                f"Successfully fetched {self.entity_config.entity_type} #{idx + 1}/{len(entity_ids)}: {entity_id}"
                            )
                            entities.append(result)
                        else:
                            self.logger.warning(
                                f"No data returned for {self.entity_config.display_name_singular} {entity_id}"
                            )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to fetch {self.entity_config.display_name_singular} {entity_id}: {e}"
                        )
            self._log_fetch_result(
                self.entity_config.display_name, len(entities), report_id
            )
            self.logger.info(
                f"Completed fetching {self.entity_config.entity_type} - Success: {len(entities)}/{len(entity_ids) if entity_ids else 0} entities"
            )
            return entities
        except GTIRelationshipFetchError as rel_err:
            endpoint = f"{self.config.api_url}/collections/{report_id}/{self.entity_config.entity_type}"
            error_msg = f"Failed to fetch {self.entity_config.display_name_singular} relationship IDs: {str(rel_err)}"

            try:
                exception = self.entity_config.exception_class(
                    error_msg, endpoint=endpoint
                )
                raise exception from rel_err
            except TypeError:
                exception = self.entity_config.exception_class(error_msg)
                raise exception from rel_err
        except (ApiNetworkError, self.entity_config.exception_class):
            raise
        except Exception as e:
            endpoint = f"{self.config.api_url}/collections/{report_id}/{self.entity_config.entity_type}"
            error_msg = (
                f"Unexpected error fetching {self.entity_config.display_name}: {str(e)}"
            )

            try:
                exception = self.entity_config.exception_class(
                    error_msg, endpoint=endpoint
                )
                raise exception from e
            except TypeError:
                exception = self.entity_config.exception_class(error_msg)
                raise exception from e

    async def _fetch_single_entity(self, entity_id: str) -> Optional[Any]:
        """Fetch a single entity by ID.

        Args:
            entity_id: ID of the entity to fetch
        Returns:
            Entity data or None if fetch fails
        Raises:
            Configured exception class: If there's an error fetching the entity

        """
        try:
            endpoint = f"{self.config.api_url}{self.entity_config.endpoint_template.format(entity_id=entity_id)}"
            self.logger.debug(
                f"Fetching {self.entity_config.entity_type} entity {entity_id} from {endpoint}"
            )
            response = await self.api_client.call_api(
                url=endpoint,
                headers=self.headers,
                model=self.entity_config.response_model,
                timeout=60,
            )
            if response and hasattr(response, "data"):
                self.logger.debug(
                    f"Successfully fetched {self.entity_config.entity_type} data for {entity_id}"
                )
                return response.data
            self.logger.warning(
                f"Empty or invalid response for {self.entity_config.entity_type} {entity_id}"
            )
            return None
        except ApiNetworkError as net_err:
            error_msg = f"Network error fetching {self.entity_config.entity_type} {entity_id}: {str(net_err)}"
            self.logger.error(
                f"Network error at {endpoint} for {self.entity_config.entity_type} {entity_id}: {str(net_err)}"
            )

            exception = self.entity_config.exception_class(error_msg)
            raise exception from net_err
        except Exception as e:
            error_msg = f"Error fetching {self.entity_config.display_name_singular} {entity_id}: {str(e)}"
            self._log_error(
                error_msg,
                entity_type=self.entity_config.entity_type.rstrip("s"),
                entity_id=entity_id,
                error=e,
            )
            self.logger.error(
                f"Failed to fetch {self.entity_config.entity_type} {entity_id} from {endpoint}: {str(e)}"
            )
            return None
