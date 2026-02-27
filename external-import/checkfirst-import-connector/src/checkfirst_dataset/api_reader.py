"""API data reader.

This module reads Checkfirst data from a remote API endpoint
and yields validated rows as `DatasetRow` objects.
"""

from typing import Iterator

from checkfirst_dataset.api_client import fetch_paginated_data
from checkfirst_dataset.dataset_reader import DatasetRow
from checkfirst_dataset.reporting import RunReport, SkipReason
from checkfirst_dataset.types import CheckfirstConfigLike


def iter_api_rows(
    *,
    config: CheckfirstConfigLike,
    api_url: str,
    api_key: str,
    api_endpoint: str,
    start_page: int = 1,
    since: str | None = None,
    report: RunReport | None = None,
) -> Iterator[DatasetRow]:
    """Iterate over validated rows from the API endpoint.

    Args:
        config: Connector configuration
        api_url: Base URL of the API
        api_key: API key for authentication
        api_endpoint: API endpoint path
        start_page: Starting page number for pagination
        since: Only fetch articles published on or after this ISO 8601 date
        report: Optional RunReport for tracking skipped rows

    Yields:
        DatasetRow objects with validated data
    """
    row_number = 0

    try:
        for item in fetch_paginated_data(
            api_url=api_url,
            api_key=api_key,
            api_endpoint=api_endpoint,
            start_page=start_page,
            since=since,
        ):
            row_number += 1

            # Basic row-size guard (approximate)
            if config.max_row_bytes is not None:
                approx = sum(len(str(v or "")) for v in item.values())
                if approx > config.max_row_bytes:
                    if report is not None:
                        report.skip(SkipReason.ROW_TOO_LARGE)
                    continue

            # Extract fields directly from API response
            # API returns lowercase/snake_case field names
            url = str(item.get("url", "")).strip() if item.get("url") else ""
            source_title = (
                str(item.get("source_title", "")).strip()
                if item.get("source_title")
                else ""
            )
            source_url = (
                str(item.get("source_url", "")).strip()
                if item.get("source_url")
                else ""
            )
            publication_date = (
                str(item.get("published_date", "")).strip()
                if item.get("published_date")
                else ""
            )

            # Validate required fields
            if not url or not source_title or not source_url or not publication_date:
                if report is not None:
                    report.skip(SkipReason.ROW_MISSING_REQUIRED_FIELDS)
                continue

            # Extract optional fields
            canonical = (
                str(item.get("canonical_url", "")).strip()
                if item.get("canonical_url")
                else None
            )
            og_title = str(item.get("title", "")).strip() if item.get("title") else None
            og_description = (
                str(item.get("og_description", "")).strip()
                if item.get("og_description")
                else None
            )

            # Handle alternates_urls array - convert to comma-separated string
            alternates = None
            if item.get("alternates_urls") and isinstance(
                item["alternates_urls"], list
            ):
                alt_urls = [
                    alt.get("url", "")
                    for alt in item["alternates_urls"]
                    if alt.get("url")
                ]
                if alt_urls:
                    alternates = ",".join(alt_urls)

            yield DatasetRow(
                source_file="api",
                row_number=row_number,
                url=url,
                source_title=source_title,
                source_url=source_url,
                canonical=canonical,
                og_title=og_title,
                og_description=og_description,
                alternates=alternates,
                publication_date=publication_date,
            )

    except Exception as exc:
        raise RuntimeError(f"Error fetching data from API: {exc}") from exc
