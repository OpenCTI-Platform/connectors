"""Extraction of CrowdStrike Falcon Intelligence indicators."""

import calendar
import json
import logging
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from crowdstrike_indicators.api import (  # noqa: F401 - re-exported
    NO_ERROR_MESSAGE,
    api_error_message,
    response_body,
)
from crowdstrike_indicators.errors import IndicatorValidationError
from crowdstrike_indicators.models import (
    CrowdStrikeActor,
    CrowdStrikeIndicator,
    EnrichedCrowdStrikeIndicator,
)
from pydantic import ValidationError

from shared.enricher import AbstractEnricher
from shared.extractor import AbstractExtractor

LOGGER = logging.getLogger(__name__)

# Same page size as the existing CrowdStrike importer: bounded payloads and
# regular progress logs. The API accepts up to 10000.
PAGE_SIZE = 1000

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

    Markers compare as strings, so the cursor always has 10 digits: a date
    before 2001-09-09T01:46:40Z, whose timestamp is shorter, is padded with
    zeros (``0946684800`` for 2000-01-01), and a date before 1970 starts at
    ``0000000000``. Unpadded, ``946684800`` would sort after every marker.
    """
    seconds = calendar.timegm(from_date.utctimetuple())
    if from_date.microsecond:
        seconds += 1
    return f"{max(seconds, 0):010d}"


def validate_indicator(
    raw: Any, model: type[CrowdStrikeIndicator] = CrowdStrikeIndicator
) -> CrowdStrikeIndicator:
    """Validate one raw indicator as ``model``, a raw API indicator by default.

    :raises IndicatorValidationError: with the id, the JSON-safe validation
        errors and the raw indicator.
    """
    try:
        return model.model_validate(raw)
    except ValidationError as error:
        raw_id = raw.get("id") if isinstance(raw, dict) else None
        raise IndicatorValidationError(
            indicator_id=raw_id if isinstance(raw_id, str) else None,
            errors=json.loads(error.json(include_url=False)),
            raw=raw,
        ) from error


class CrowdStrikeIndicatorExtractor(AbstractExtractor[EnrichedCrowdStrikeIndicator]):
    """Extract indicators with marker-based deep pagination, with their actors.

    Pages are requested in ascending ``_marker`` order with the filter
    ``_marker:>='<cursor>'``. That filter includes the cursor, so every page
    after the first repeats the last row of the previous one. Rows are
    therefore deduplicated by ``id``, and every request asks for a full page:
    a page that brings no new row then really means nothing is left. Once at
    least ``max_element_count`` rows are collected, the result is cut to the
    earliest ``max_element_count``.

    Only then are the actors of the kept indicators looked up through
    ``actor_enricher``, whose cache is emptied at the start of every
    extraction. A missing actor never fails the extraction: a name that
    resolves to nothing, or whose lookup raises, is logged and left out of
    ``actor_objects_list``. ``on_raw_page`` receives indicator pages only.
    """

    def __init__(
        self,
        client: IndicatorsClient,
        actor_enricher: AbstractEnricher[CrowdStrikeActor],
        *,
        on_raw_page: RawPageCallback | None = None,
        page_size: int = PAGE_SIZE,
    ) -> None:
        self.client = client
        self.actor_enricher = actor_enricher
        self.on_raw_page = on_raw_page
        self.page_size = page_size

    def extract(
        self, from_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, EnrichedCrowdStrikeIndicator]]:
        self.check_arguments(from_date, max_element_count)
        self.actor_enricher.reset_cache()
        collected = self._collect(from_date, max_element_count)[:max_element_count]

        stats: Counter[str] = Counter()
        enriched = [(dt, self._enrich(indicator, stats)) for dt, indicator in collected]
        if stats["looked_up"]:
            LOGGER.log(
                logging.WARNING if stats["failed"] else logging.INFO,
                "Looked up %d actor name(s): %d resolved, %d unresolved, %d failed",
                stats["looked_up"],
                stats["resolved"],
                stats["unresolved"],
                stats["failed"],
            )
        return enriched

    def _collect(
        self, from_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, CrowdStrikeIndicator]]:
        """Paginate until ``max_element_count`` rows or nothing new."""
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

        return collected

    def _enrich(
        self, indicator: CrowdStrikeIndicator, stats: Counter[str]
    ) -> EnrichedCrowdStrikeIndicator:
        """Return ``indicator`` with the actors its names resolve to."""
        actors: list[CrowdStrikeActor] = []
        actor_ids: set[int] = set()
        for name in dict.fromkeys(indicator.actors or []):
            stats["looked_up"] += 1
            try:
                actor = self.actor_enricher.extract(name)
            except Exception as error:  # a missing actor never fails extraction
                stats["failed"] += 1
                LOGGER.warning(
                    "Actor %s of indicator %s could not be looked up: %s",
                    name,
                    indicator.id,
                    error,
                )
                continue
            if actor is None:
                stats["unresolved"] += 1
                LOGGER.info(
                    "Actor %s of indicator %s did not resolve", name, indicator.id
                )
                continue
            stats["resolved"] += 1
            if actor.id not in actor_ids:
                actor_ids.add(actor.id)
                actors.append(actor)
        return EnrichedCrowdStrikeIndicator.model_validate(
            {
                **indicator.model_dump(by_alias=True, exclude_unset=True),
                "actor_objects_list": actors,
            }
        )

    def _fetch_page(self, cursor: str) -> dict[str, Any]:
        response = self.client.query_indicator_entities(
            limit=self.page_size,
            sort="_marker.asc",
            filter=f"_marker:>='{cursor}'",
        )
        body = response_body(response)
        if self.on_raw_page is not None:
            self.on_raw_page(body)
        return body
