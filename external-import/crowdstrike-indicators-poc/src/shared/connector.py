"""Generic connector: extract, transform and load on a schedule."""

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, NoReturn

from stix2.v21 import Bundle

from shared.extractor import AbstractExtractor
from shared.loader import AbstractLoader
from shared.transformer import AbstractTransformer
from shared.type_arguments import declared_types

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CycleResult:
    """What one cycle did, and where the next one starts."""

    extracted: int
    loaded: int
    skipped: int
    next_from_date: datetime


def _type_name(value: Any) -> str:
    return getattr(value, "__name__", None) or repr(value)


class Connector:
    """Run an extractor, a chain of transformers and a loader on a schedule.

    Construction checks that the components fit: the extractor's item type is
    the first transformer's input type, each output type is the next input
    type, and the last output type is ``stix2.v21.Bundle``, the loader's input.

    Each cycle extracts items from a cursor, passes each one through the
    transformers and loads the result. A transformer failure skips the item;
    an extraction or loading failure aborts the cycle without moving the
    cursor. :meth:`run` repeats cycles forever, draining backlogs without
    waiting and waiting ``run_frequency`` otherwise.
    """

    def __init__(
        self,
        extractor: AbstractExtractor[Any],
        transformers: Sequence[AbstractTransformer[Any, Any]],
        loader: AbstractLoader,
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Assemble the connector.

        :raises TypeError: if the components do not fit together, or if a
            component's declared types cannot be read.
        """
        self.extractor = extractor
        self.transformers = list(transformers)
        self.loader = loader
        self._sleep = sleep
        self._check_chain()

    def _check_chain(self) -> None:
        (expected,) = declared_types(self.extractor, AbstractExtractor)
        source = f"extractor ({type(self.extractor).__name__})"
        for position, transformer in enumerate(self.transformers, start=1):
            input_type, output_type = declared_types(transformer, AbstractTransformer)
            if input_type != expected:
                raise TypeError(
                    f"transformer {position} ({type(transformer).__name__}) expects "
                    f"{_type_name(input_type)} but {source} produces "
                    f"{_type_name(expected)}"
                )
            expected = output_type
            source = f"transformer {position} ({type(transformer).__name__})"
        if expected is not Bundle:
            raise TypeError(
                f"loader ({type(self.loader).__name__}) expects "
                f"{_type_name(Bundle)} but {source} produces {_type_name(expected)}"
            )

    def run_once(self, from_date: datetime, max_element_count: int) -> CycleResult:
        """Run one cycle from ``from_date``.

        :raises Exception: whatever the extractor or the loader raises; the
            cycle then stops and the caller keeps its cursor.
        """
        pairs = self.extractor.extract(from_date, max_element_count)
        loaded = skipped = 0
        for _, item in pairs:
            try:
                value = item
                for transformer in self.transformers:
                    value = transformer.convert(value)
            except Exception:
                skipped += 1
                LOGGER.warning(
                    "Skipping item that failed to convert: %r", item, exc_info=True
                )
                continue
            self.loader.load(value)
            loaded += 1
        next_from_date = max((dt for dt, _ in pairs), default=from_date)
        result = CycleResult(len(pairs), loaded, skipped, next_from_date)
        LOGGER.info(
            "Cycle from %s: %d extracted, %d loaded, %d skipped, next from %s",
            from_date.isoformat(),
            result.extracted,
            result.loaded,
            result.skipped,
            next_from_date.isoformat(),
        )
        return result

    def run(
        self, from_date: datetime, run_frequency: timedelta, max_element_count: int
    ) -> NoReturn:
        """Run cycles forever, starting from ``from_date``.

        :raises ValueError: before any extraction, if ``run_frequency`` is not
            positive or the extraction arguments are invalid.
        """
        if run_frequency <= timedelta(0):
            raise ValueError(f"run_frequency must be positive, got {run_frequency}")
        AbstractExtractor.check_arguments(from_date, max_element_count)
        wait = run_frequency.total_seconds()
        cursor = from_date
        while True:
            try:
                result = self.run_once(cursor, max_element_count)
            except Exception:
                LOGGER.exception(
                    "Cycle from %s failed; retrying in %s",
                    cursor.isoformat(),
                    run_frequency,
                )
                self._sleep(wait)
                continue
            full = result.extracted == max_element_count
            moved = result.next_from_date > cursor
            if full and not moved:
                LOGGER.warning(
                    "Cursor stalled at %s: %d items share it; waiting %s",
                    cursor.isoformat(),
                    max_element_count,
                    run_frequency,
                )
            cursor = result.next_from_date
            if not (full and moved):
                self._sleep(wait)
