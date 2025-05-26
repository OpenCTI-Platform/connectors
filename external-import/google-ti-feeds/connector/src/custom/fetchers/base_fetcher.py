"""Base fetcher class with common functionality for Google Threat Intelligence API.

This module provides a base class that contains shared functionality for all
specialized fetchers, including API client management, headers, logging, and
common utility methods.
"""

import logging
from typing import Optional

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.utils.api_engine.api_client import ApiClient


class BaseFetcher:
    """Base class for all GTI data fetchers.

    This class provides common functionality shared across all specialized fetchers:
    - API client and headers management
    - Configuration access
    - Logging utilities
    - Common helper methods
    """

    def __init__(
        self,
        gti_config: GTIConfig,
        api_client: ApiClient,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the base fetcher.

        Args:
            gti_config: Configuration for accessing the GTI API
            api_client: Client for making API requests
            logger: Logger for logging messages

        """
        self.config = gti_config
        self.api_client = api_client
        self.logger = logger or logging.getLogger(__name__)
        self.headers = {
            "X-Apikey": self.config.api_key,
            "accept": "application/json",
        }

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

    def _log_fetch_start(
        self,
        entity_type: str,
        entity_id: Optional[str] = None,
        report_id: Optional[str] = None,
    ) -> None:
        """Log the start of a fetch operation.

        Args:
            entity_type: Type of entity being fetched
            entity_id: ID of the specific entity (optional)
            report_id: ID of the related report (optional)

        """
        if report_id:
            self.logger.info(f"Fetching {entity_type} for report {report_id}...")
        elif entity_id:
            self.logger.info(f"Fetching {entity_type} {entity_id}...")
        else:
            self.logger.info(f"Fetching {entity_type}...")

    def _log_fetch_result(
        self, entity_type: str, count: int, report_id: Optional[str] = None
    ) -> None:
        """Log the result of a fetch operation.

        Args:
            entity_type: Type of entity that was fetched
            count: Number of entities fetched
            report_id: ID of the related report (optional)

        """
        if count > 0:
            if report_id:
                self.logger.info(
                    f"Fetched {count} {entity_type} for report {report_id}"
                )
            else:
                self.logger.info(f"Fetched {count} {entity_type}")
        else:
            if report_id:
                self.logger.debug(f"No {entity_type} found for report {report_id}")
            else:
                self.logger.debug(f"No {entity_type} found")

    def _log_error(
        self,
        message: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        error: Optional[Exception] = None,
    ) -> None:
        """Log an error with appropriate context.

        Args:
            message: Error message
            entity_type: Type of entity related to the error (optional)
            entity_id: ID of the entity related to the error (optional)
            error: The exception that occurred (optional)

        """
        meta = {}
        if error:
            meta["error"] = str(error)
        if entity_id:
            meta["entity_id"] = entity_id
        if entity_type:
            meta["entity_type"] = entity_type

        self.logger.error(message, meta=meta if meta else None)  # type: ignore[call-arg]
