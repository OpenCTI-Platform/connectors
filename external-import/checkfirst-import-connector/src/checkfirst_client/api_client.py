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
        # Highest `_id` observed from the API this walk, including rows later
        # skipped by validation / size checks. Used as a resume watermark so
        # bad rows cannot pin the connector forever.
        self.last_seen_id: str | None = None

    def fetch_paginated_data(
        self,
        api_endpoint: str,
        after: str | None = None,
        since: datetime | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Fetch keyset-paginated data from the API endpoint.

        Walks `/v1/articles` with `after` / `next_cursor` on `_id` ascending.
        Omit `after` to start from the beginning; pass the last processed
        article `_id` to resume.

        Args:
            api_endpoint: Endpoint path (e.g., "/v1/articles")
            after: Exclusive `_id` cursor; only documents with `_id` greater
                than this value are returned
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

        cursor = after
        has_more = True
        while has_more:
            params: dict[str, Any] = {}
            if cursor:
                params["after"] = cursor
            if since:
                params["since"] = since.isoformat(timespec="seconds").replace(
                    "+00:00", "Z"
                )

            try:
                self.logger.debug(
                    f"[API] Fetching {endpoint_url}",
                    {"params": {"after": cursor, "since": since}},
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
                run_reporter.pages_fetched += 1

                if not items:
                    break

                yield from items

                pagination = data.get("pagination", {})
                has_more = bool(pagination.get("has_next", False))
                # Prefer the API cursor; fall back to the last item `_id` so a
                # missing next_cursor cannot stall a has_next=true response.
                next_cursor = pagination.get("next_cursor") or items[-1].get("_id")
                if not has_more or not next_cursor:
                    break
                cursor = str(next_cursor)
            except requests.HTTPError as err:
                raise CheckfirstAPIError(
                    f"HTTP error {err.response.status_code} when fetching after "
                    f"{cursor!r}: {err.response.reason}"
                ) from err
            except JSONDecodeError as err:
                raise CheckfirstAPIError(
                    f"Invalid JSON response from API after cursor {cursor!r}"
                ) from err
            except requests.RequestException as err:  # fallback
                raise CheckfirstAPIError(
                    f"Error when fetching after cursor {cursor!r}: {err}"
                ) from err

    def iter_api_rows(
        self,
        api_endpoint: str,
        after: str | None = None,
        since: datetime | None = None,
        max_row_bytes: int | None = None,
    ) -> Generator[Article, None, None]:
        """Iterate over validated rows from the API endpoint.

        Args:
            api_endpoint: API endpoint path
            after: Exclusive `_id` cursor to resume from
            since: Only fetch articles published on or after this ISO 8601 date
            max_row_bytes: Skip any API row larger than this approximate number of bytes

        Yields:
            Article objects with validated data
        """
        row_number = 0
        self.last_seen_id = None

        for item in self.fetch_paginated_data(
            api_endpoint=api_endpoint,
            after=after,
            since=since,
        ):
            row_number += 1
            item_id = item.get("_id")
            if item_id is not None:
                self.last_seen_id = str(item_id)

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
