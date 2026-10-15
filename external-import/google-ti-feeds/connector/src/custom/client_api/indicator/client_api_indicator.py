"""Client API for fetching IOC delta packages from GTI."""

import io
import json
import logging
import tarfile
from typing import Any

from connector.src.custom.client_api.client_api_base import BaseClientAPI
from connector.src.custom.exceptions import (
    GTIIndicatorFetchError,
    GTIIndicatorPackageUnavailableError,
)

LOG_PREFIX = "[ClientAPIIndicator]"

# The API answers 400 for a package that has not been published yet.
PACKAGE_NOT_READY_STATUS = 400
RATE_LIMITED_STATUS = 429
FIRST_SERVER_ERROR_STATUS = 500
LAST_SERVER_ERROR_STATUS = 599
# GenericFetcher.fetch_bytes reports an empty API client result as status 0.
TRANSPORT_FAILURE_STATUS = 0


class ClientAPIIndicator(BaseClientAPI):
    """Client for fetching IOC delta packages from GTI Steady-State IOC Deltas API."""

    def __init__(
        self,
        config: Any,
        logger: logging.Logger,
        api_client: Any = None,
        fetcher_factory: Any = None,
    ):
        """Initialize Indicator Client API."""
        super().__init__(config, logger, api_client, fetcher_factory)

    async def fetch_ioc_delta_package(
        self, package_id: str, ioc_type: str
    ) -> list[dict[str, Any]] | None:
        """Fetch an IOC delta package for a given package_id and ioc_type.

        Returns:
            The parsed entries, or None when the package does not exist (404) or
            the API returned another non-retryable status.

        Raises:
            GTIIndicatorPackageUnavailableError: The package is not published yet
                (400), or the request was rate limited, failed server-side or never
                completed. The package must be retried on a later run.

        """
        fetcher = self.fetcher_factory.create_fetcher_by_name(
            "ioc_deltas",
            base_url=self.config.api_url.unicode_string(),
        )

        log_metadata = {
            "prefix": LOG_PREFIX,
            "package_id": package_id,
            "ioc_type": ioc_type,
        }

        self.logger.debug(
            "Fetching IOC delta package",
            log_metadata,
        )

        try:
            status, content = await fetcher.fetch_bytes(
                package_id=package_id,
                ioc_type=ioc_type,
            )
        except GTIIndicatorFetchError as err:
            # The fetcher raises its configured exception on network and client
            # failures rather than returning a status.
            self.logger.warning(
                "IOC delta package request failed",
                {**log_metadata, "error": str(err)},
            )
            raise GTIIndicatorPackageUnavailableError(
                message="package request failed",
                package_id=package_id,
            ) from err

        if status == 404:
            self.logger.debug(
                "IOC delta package not found (404)",
                {
                    **log_metadata,
                    "status": status,
                },
            )
            return None
        if status == PACKAGE_NOT_READY_STATUS:
            self.logger.debug(
                "IOC delta package not available yet (400)",
                {
                    **log_metadata,
                    "status": status,
                    "body": content[:200].decode("utf-8", errors="replace"),
                },
            )
            raise GTIIndicatorPackageUnavailableError(
                message="package not available yet",
                package_id=package_id,
                status_code=str(status),
            )
        if status in (RATE_LIMITED_STATUS, TRANSPORT_FAILURE_STATUS) or (
            FIRST_SERVER_ERROR_STATUS <= status <= LAST_SERVER_ERROR_STATUS
        ):
            self.logger.warning(
                "IOC delta package temporarily unavailable",
                {
                    **log_metadata,
                    "status": status,
                    "body": content[:200].decode("utf-8", errors="replace"),
                },
            )
            raise GTIIndicatorPackageUnavailableError(
                message="package temporarily unavailable",
                package_id=package_id,
                status_code=str(status),
            )
        if status != 200:
            self.logger.warning(
                "Unexpected HTTP status for IOC delta package",
                {
                    **log_metadata,
                    "status": status,
                    "body": content[:200].decode("utf-8", errors="replace"),
                },
            )
            return None

        return self._parse_tar_bz2(content, package_id, ioc_type)

    def _parse_tar_bz2(
        self, content: bytes, package_id: str, ioc_type: str
    ) -> list[dict[str, Any]]:
        """Parse tar.bz2 content containing NDJSON files."""
        results: list[dict[str, Any]] = []

        log_metadata = {
            "prefix": LOG_PREFIX,
            "package_id": package_id,
            "ioc_type": ioc_type,
        }

        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:bz2") as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue

                    f = tar.extractfile(member)
                    if f is None:
                        continue

                    raw = f.read().decode("utf-8", errors="replace")
                    for line in raw.splitlines():
                        if not (line := line.strip()):
                            continue

                        try:
                            obj = json.loads(line)
                            results.append(obj)
                        except json.JSONDecodeError as e:
                            self.logger.debug(
                                "Failed to parse NDJSON line",
                                {
                                    **log_metadata,
                                    "error": str(e),
                                },
                            )

        except tarfile.TarError as e:
            self.logger.warning(
                "Failed to parse tar.bz2 archive",
                {
                    **log_metadata,
                    "error": str(e),
                },
            )
            return []

        self.logger.info(
            "Parsed IOC delta package",
            {
                **log_metadata,
                "count": len(results),
            },
        )
        return results
