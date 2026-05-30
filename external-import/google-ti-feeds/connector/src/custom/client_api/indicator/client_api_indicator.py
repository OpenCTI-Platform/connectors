"""Client API for fetching IOC delta packages from GTI."""

import io
import json
import logging
import tarfile
from typing import Any

from connector.src.custom.client_api.client_api_base import BaseClientAPI

LOG_PREFIX = "[ClientAPIIndicator]"


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
        """Fetch an IOC delta package for a given package_id and ioc_type."""
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

        status, content = await fetcher.fetch_bytes(
            package_id=package_id,
            ioc_type=ioc_type,
        )

        if status == 404:
            self.logger.debug(
                "IOC delta package not found (404)",
                {
                    **log_metadata,
                    "status": status,
                },
            )
            return None
        if status == 400:
            self.logger.debug(
                "IOC delta package not available yet (400)",
                {
                    **log_metadata,
                    "status": status,
                    "body": content[:200].decode("utf-8", errors="replace"),
                },
            )
            return None
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
