"""Extraction contract shared by every connector source."""

from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel


class AbstractExtractor[T: BaseModel](ABC):
    """Extract validated items from a source, each paired with its datetime.

    Contract every implementation honours:

    * Only items whose datetime is strictly later than ``after_date`` are
      returned.
    * Pairs are sorted by ascending datetime, so the datetime of any pair is
      a checkpoint covering every pair before it.
    * At most ``max_element_count`` pairs are returned; when fewer items
      exist after ``after_date``, all of them are returned.
    * An empty list means the source holds no item after ``after_date``. It
      never reports an error: errors are raised.
    * Items are instances of ``T``, already validated.
    * Returned datetimes are timezone-aware.
    * ``after_date`` must be timezone-aware and ``max_element_count`` at
      least 1, checked before the source is contacted (see
      :meth:`check_arguments`).
    """

    @abstractmethod
    def extract(
        self, after_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, T]]:
        """Return up to ``max_element_count`` items later than ``after_date``."""

    @staticmethod
    def check_arguments(after_date: datetime, max_element_count: int) -> None:
        """Validate the arguments of :meth:`extract`.

        Implementations call this first, before any I/O.

        :raises ValueError: if ``after_date`` has no timezone or
            ``max_element_count`` is lower than 1.
        """
        if after_date.tzinfo is None or after_date.utcoffset() is None:
            raise ValueError(f"after_date must be timezone-aware, got {after_date!r}")
        if max_element_count < 1:
            raise ValueError(
                f"max_element_count must be at least 1, got {max_element_count}"
            )
