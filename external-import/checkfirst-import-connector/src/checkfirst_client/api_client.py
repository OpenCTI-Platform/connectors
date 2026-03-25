from datetime import datetime
from json import JSONDecodeError
from typing import Any, Generator

import requests
from checkfirst_client.api_models import Article
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl, ValidationError
from requests.adapters import HTTPAdapter, Retry
from utils.run_reporter import SkipReason, run_reporter

# Timeout of 5 minutes: the CheckFirst infrastructure can be slow to respond
# on large pages, so a generous timeout avoids spurious errors.
TIMEOUT_SECONDS = 300
RETRY_BACKOFF_SECONDS = 5
MAX_RETRIES = 3


class CheckfirstAPIError(Exception):
    """Raised when Checkfirst API requests fail."""


def get_skip_reason_from_validation_error(err: ValidationError) -> SkipReason | None:
    """Determine the appropriate SkipReason based on the ValidationError details."""
    for error in err.errors():
        if error.get("type") == "missing":
            return SkipReason.ROW_MISSING_REQUIRED_FIELDS
        elif error.get("loc"):
            loc = error["loc"]
            field_name = loc[0] if isinstance(loc, tuple) else loc
            if field_name == "published_date":
                return SkipReason.ROW_INVALID_PUBLICATION_DATE
    return None


class CheckfirstClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str,
    ):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `api_key`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (str): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
        """
        self.helper = helper
        self.logger = self.helper.connector_logger

        self.base_url = base_url
        self.api_key = api_key

    def fetch_paginated_data(
        self,
        api_endpoint: str,
        start_page: int = 1,
        since: datetime | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Fetch paginated data from the API endpoint.

        Args:
            api_endpoint: Endpoint path (e.g., "/v1/articles")
            start_page: Starting page number for pagination (default: 1)
            since: Only fetch articles published on or after this ISO 8601 date

        Yields:
            Dictionary objects representing each row/article from the API

        Raises:
            CheckfirstAPIError: If the API request fails or returns invalid data
        """
        base_url = str(self.base_url).rstrip("/")
        endpoint = api_endpoint if api_endpoint.startswith("/") else f"/{api_endpoint}"
        endpoint_url = f"{base_url}{endpoint}"

        retry_strategy = Retry(
            allowed_methods=["GET"],
            status_forcelist=[429, 500, 502, 503, 504],
            total=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF_SECONDS,
            respect_retry_after_header=True,
        )
        http_adapter = HTTPAdapter(max_retries=retry_strategy)

        session = requests.Session()
        session.mount(endpoint_url, http_adapter)
        session.headers.update({"Api-Key": self.api_key, "Accept": "application/json"})

        current_page = start_page
        has_more = True
        while has_more:
            params = {"page": current_page}
            if since:
                params["since"] = since.isoformat(timespec="seconds").replace(
                    "+00:00", "Z"
                )

            try:
                self.logger.debug(
                    f"[API] Fetching {endpoint_url}",
                    {"params": {"page": current_page, "since": since}},
                )

                response = session.get(
                    endpoint_url,
                    params=params,
                    timeout=TIMEOUT_SECONDS,
                )
                response.raise_for_status()

                data = response.json()

                if "data" not in data:
                    raise CheckfirstAPIError(
                        f"Unrecognized API response format: {list(data.keys())}"
                    )

                items = data["data"]
                if not items:
                    has_more = False

                yield from items  # one page contains 1_000 items

                has_more = data.get("pagination", {}).get("has_next", False)
                current_page += 1
            except requests.HTTPError as err:
                raise CheckfirstAPIError(
                    f"HTTP error {err.response.status_code} when fetching page "
                    f"{current_page}: {err.response.reason}"
                ) from err
            except JSONDecodeError as err:
                raise CheckfirstAPIError(
                    f"Invalid JSON response from API on page {current_page}"
                ) from err
            except requests.RequestException as err:  # fallback
                raise CheckfirstAPIError(
                    f"Error when fetching page {current_page}: {err}"
                ) from err

    def iter_api_rows(
        self,
        api_endpoint: str,
        start_page: int = 1,
        since: datetime | None = None,
        max_row_bytes: int | None = None,
    ) -> Generator[Article, None, None]:
        """Iterate over validated rows from the API endpoint.

        Args:
            api_endpoint: API endpoint path
            start_page: Starting page number for pagination
            since: Only fetch articles published on or after this ISO 8601 date
            max_row_bytes: Skip any API row larger than this approximate number of bytes

        Yields:
            Article objects with validated data
        """
        row_number = 0

        for item in self.fetch_paginated_data(
            api_endpoint=api_endpoint,
            start_page=start_page,
            since=since,
        ):
            row_number += 1

            # Basic row-size guard (approximate)
            if max_row_bytes is not None:
                approx = sum(len(str(v or "")) for v in item.values())
                if approx > max_row_bytes:
                    run_reporter.skip(SkipReason.ROW_TOO_LARGE)
                    continue

            try:
                yield Article(**item, row_number=row_number)
            except ValidationError as err:
                skip_reason = get_skip_reason_from_validation_error(err)
                if skip_reason:
                    run_reporter.skip(skip_reason)
                    continue
                else:
                    raise CheckfirstAPIError(
                        f"Data validation error for row {row_number}: {err}"
                    ) from err
