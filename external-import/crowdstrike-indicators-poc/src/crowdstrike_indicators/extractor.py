"""Extraction of CrowdStrike Falcon Intelligence indicators."""

import calendar
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from crowdstrike_indicators.errors import CrowdStrikeAPIError, IndicatorValidationError
from crowdstrike_indicators.models import CrowdStrikeIndicator
from pydantic import ValidationError

from shared.extractor import AbstractExtractor

LOGGER = logging.getLogger(__name__)

# Same page size as the existing CrowdStrike importer: bounded payloads and
# regular progress logs. The API accepts up to 10000.
PAGE_SIZE = 1000
NO_ERROR_MESSAGE = "no error message returned by CrowdStrike API"

type RawPageCallback = Callable[[dict[str, Any]], None]


class IndicatorsClient(Protocol):
    """The part of FalconPy's ``Intel`` service class the extractor uses.

    ``query_indicator_entities`` is the ``QueryIntelIndicatorEntities``
    operation (``GET /intel/combined/indicators/v1``). It returns FalconPy's
    response dict: ``{"status_code": ..., "headers": ..., "body": ...}``.
    """

    def query_indicator_entities(self, **kwargs: Any) -> dict[str, Any]: ...


def marker_datetime(marker: str) -> datetime:
    """Return the UTC instant given by the 10-digit prefix of a ``_marker``."""
    return datetime.fromtimestamp(int(marker[:10]), tz=UTC)


def first_marker_cursor(from_date: datetime) -> str:
    """Return the ``_marker`` cursor that includes ``from_date``.

    Every marker of a second sorts after the bare 10-digit timestamp of that
    second, so ``_marker:>='<ts>'`` includes the whole second ``ts``. A
    ``from_date`` with a fraction of a second is rounded up: markers of its
    own second pair with a datetime earlier than ``from_date``.
    """
    seconds = calendar.timegm(from_date.utctimetuple())
    if from_date.microsecond:
        seconds += 1
    return str(seconds)


def api_error_message(body: Any) -> str:
    """Extract the first error message of a CrowdStrike response body.

    The upstream shape is not guaranteed: ``body`` or ``errors`` may be
    missing, ``None``, not a list, or hold a non-dict entry.
    """
    errors = body.get("errors") if isinstance(body, dict) else None
    if not isinstance(errors, list | tuple) or not errors:
        return NO_ERROR_MESSAGE
    first_error = errors[0]
    message = first_error.get("message") if isinstance(first_error, dict) else None
    return str(message) if message else NO_ERROR_MESSAGE


def validate_indicator(raw: Any) -> CrowdStrikeIndicator:
    """Validate one raw API indicator.

    :raises IndicatorValidationError: with the id, the JSON-safe validation
        errors and the raw indicator.
    """
    try:
        return CrowdStrikeIndicator.model_validate(raw)
    except ValidationError as error:
        raw_id = raw.get("id") if isinstance(raw, dict) else None
        raise IndicatorValidationError(
            indicator_id=raw_id if isinstance(raw_id, str) else None,
            errors=json.loads(error.json(include_url=False)),
            raw=raw,
        ) from error


class CrowdStrikeIndicatorExtractor(AbstractExtractor[CrowdStrikeIndicator]):
    """Extract indicators with marker-based deep pagination.

    Pages are requested in ascending ``_marker`` order with the filter
    ``_marker:>='<cursor>'``. That filter includes the cursor, so every page
    after the first repeats the last row of the previous one. Rows are
    therefore deduplicated by ``id``, and every request asks for a full page:
    a page that brings no new row then really means nothing is left. Once at
    least ``max_element_count`` rows are collected, the result is cut to the
    earliest ``max_element_count``.
    """

    def __init__(
        self,
        client: IndicatorsClient,
        *,
        on_raw_page: RawPageCallback | None = None,
        page_size: int = PAGE_SIZE,
    ) -> None:
        self.client = client
        self.on_raw_page = on_raw_page
        self.page_size = page_size

    def extract(
        self, from_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, CrowdStrikeIndicator]]:
        self.check_arguments(from_date, max_element_count)

        collected: list[tuple[datetime, CrowdStrikeIndicator]] = []
        seen_ids: set[str] = set()
        cursor = first_marker_cursor(from_date)

        while len(collected) < max_element_count:
            body = self._fetch_page(cursor)
            resources = body.get("resources") or []

            new_count = 0
            for raw in resources:
                raw_id = raw.get("id") if isinstance(raw, dict) else None
                if isinstance(raw_id, str) and raw_id in seen_ids:
                    continue
                indicator = validate_indicator(raw)
                seen_ids.add(indicator.id)
                collected.append((marker_datetime(indicator.marker), indicator))
                new_count += 1

            LOGGER.info(
                "Fetched indicator page: %d rows, %d new, %d collected, cursor %s",
                len(resources),
                new_count,
                len(collected),
                cursor,
            )
            if new_count == 0:
                break
            cursor = collected[-1][1].marker

        return collected[:max_element_count]

    def _fetch_page(self, cursor: str) -> dict[str, Any]:
        response = self.client.query_indicator_entities(
            limit=self.page_size,
            sort="_marker.asc",
            filter=f"_marker:>='{cursor}'",
        )
        status_code = response.get("status_code")
        body = response.get("body")
        if not isinstance(status_code, int):
            # Unexpected FalconPy shape: never read it as an empty success.
            raise CrowdStrikeAPIError(0, api_error_message(body))
        if status_code >= 400:
            raise CrowdStrikeAPIError(status_code, api_error_message(body))
        if not isinstance(body, dict):
            body = {}
        if self.on_raw_page is not None:
            self.on_raw_page(body)
        return body
