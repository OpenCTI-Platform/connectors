"""Entity fetcher orchestrator for Google Threat Intelligence API.
This module provides a unified interface for fetching all types of entities
related to reports by using the factory pattern efficiently.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions import GTIRelationshipFetchError
from connector.src.custom.fetchers.base_fetcher import BaseFetcher
from connector.src.custom.fetchers.fetcher_factory import FetcherFactory
from connector.src.custom.models.gti_reports.gti_report_model import GTIReportData
from connector.src.utils.api_engine.api_client import ApiClient


class EntityFetcher(BaseFetcher):
    """Orchestrator for fetching all types of entities related to reports."""

    def __init__(
        self,
        gti_config: GTIConfig,
        api_client: ApiClient,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the entity fetcher with all generic fetchers via factory."""
        super().__init__(gti_config, api_client, logger)

        self.entity_fetchers = FetcherFactory.create_all_entity_fetchers(
            gti_config, api_client, logger
        )

    async def fetch_report_related_entities(
        self, report: GTIReportData, report_index: int = 0, total_reports: int = 0
    ) -> Dict[str, List[Any]]:
        """Fetch all entities related to a specific report.

        Args:
            report: The report for which to fetch related entities
            report_index: Current report index (for progress tracking)
            total_reports: Total number of reports (for progress tracking)

        Returns:
            Dictionary containing all related entities organized by type
        Raises:
            GTIRelationshipFetchError: If there's an error fetching related entities

        """
        report_id = report.id
        progress_info = (
            f"({report_index}/{total_reports} reports) " if total_reports > 0 else ""
        )
        self.logger.info(
            f"{progress_info}Fetching related entities for report {report_id}..."
        )

        related_entities: Dict[str, List[Any]] = {
            entity_type: [] for entity_type in self.entity_fetchers.keys()
        }
        try:
            self.logger.info(
                f"Processing {len(self.entity_fetchers)} entity types for report {report_id}"
            )
            related_entities = {
                entity_type: [] for entity_type in self.entity_fetchers.keys()
            }

            for entity_type, fetcher in self.entity_fetchers.items():
                self.logger.info(f"Fetching {entity_type} for report {report_id}")
                try:
                    result = await fetcher.fetch_entities(report)
                    related_entities[entity_type] = result
                    self.logger.info(
                        f"Success: {entity_type} for report {report_id} - got {len(result)} entities"
                    )
                except Exception as fetch_ex:
                    self.logger.error(
                        f"Failed to fetch {entity_type} for report {report_id}: {fetch_ex}"
                    )
                    related_entities[entity_type] = []

            total_entities = sum(
                len(entities) for entities in related_entities.values()
            )
            summary_parts = [
                f"{entity_type.replace('_', ' ')}: {len(entities)}"
                for entity_type, entities in related_entities.items()
            ]
            summary = ", ".join(summary_parts)
            self.logger.info(
                f"Successfully fetched {total_entities} related entities for report {report_id} "
                f"({summary})"
            )
            return related_entities
        except asyncio.CancelledError:
            self.logger.info(f"Entity fetch cancelled for report {report_id}")
            raise
        except Exception as e:
            self._log_error(
                f"Error fetching related entities for report {report_id}: {str(e)}",
                entity_type="report_entities",
                entity_id=report_id,
                error=e,
            )
            raise GTIRelationshipFetchError(
                f"Failed to fetch related entities: {str(e)}",
                source_id=report_id,
                relationship_type="report_entities",
            ) from e

    def get_supported_entity_types(self) -> List[str]:
        """Get list of supported entity types.

        Returns:
            List of entity type names that this fetcher supports

        """
        return list(self.entity_fetchers.keys())

    async def fetch_specific_entity_types(
        self, report: GTIReportData, entity_types: List[str]
    ) -> Dict[str, List[Any]]:
        """Fetch only specific types of entities for a report.

        Args:
            report: The report for which to fetch entities
            entity_types: List of entity types to fetch
        Returns:
            Dictionary containing requested entities organized by type
        Raises:
            ValueError: If any requested entity type is not supported
            GTIRelationshipFetchError: If there's an error fetching entities

        """
        unsupported_types = set(entity_types) - set(self.entity_fetchers.keys())
        if unsupported_types:
            raise ValueError(
                f"Unsupported entity types: {unsupported_types}. "
                f"Supported types: {list(self.entity_fetchers.keys())}"
            )
        report_id = report.id
        self.logger.info(
            f"Fetching specific entity types {entity_types} for report {report_id}..."
        )

        related_entities: Dict[str, List[Any]] = {
            entity_type: [] for entity_type in entity_types
        }
        try:
            for entity_type in entity_types:
                try:
                    self.logger.info(f"Fetching {entity_type} for report {report_id}")
                    result = await self.entity_fetchers[entity_type].fetch_entities(
                        report
                    )
                    related_entities[entity_type] = result
                    self.logger.info(
                        f"Success: {entity_type} for report {report_id} - got {len(result)} entities"
                    )
                except Exception as fetch_ex:
                    self.logger.error(
                        f"Failed to fetch {entity_type} for report {report_id}: {fetch_ex}"
                    )
                    related_entities[entity_type] = []

            total_entities = sum(
                len(entities) for entities in related_entities.values()
            )
            self.logger.info(
                f"Fetched {total_entities} entities of requested types for report {report_id}"
            )
            return related_entities
        except asyncio.CancelledError:
            self.logger.info(f"Specific entity fetch cancelled for report {report_id}")
            raise
        except Exception as e:
            self._log_error(
                f"Error fetching specific entity types {entity_types} for report {report_id}: {str(e)}",
                entity_type="specific_entities",
                entity_id=report_id,
                error=e,
            )
            raise GTIRelationshipFetchError(
                f"Failed to fetch specific entity types: {str(e)}",
                source_id=report_id,
                relationship_type=f"specific_entities_{entity_types}",
            ) from e
