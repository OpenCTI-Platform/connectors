"""Extraction contract shared by every connector source."""

from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel


class AbstractExtractor[T: BaseModel](ABC):
    """Extract validated items from a source, each paired with its datetime.

    Contract every implementation honours:

    * Only items whose datetime is equal to or later than ``from_date`` are
      returned.
    * Pairs are sorted by ascending datetime. A caller resumes by passing the
      latest returned datetime as the next ``from_date``: items sharing that
      datetime come back again, and no later item is skipped.
    * At most ``max_element_count`` pairs are returned, the earliest ones;
      when fewer items exist at or after ``from_date``, all of them are
      returned.
    * An empty list means the source holds no item at or after
      ``from_date``. It never reports an error: errors are raised.
    * Items are instances of ``T``, already validated.
    * Returned datetimes are timezone-aware.
    * ``from_date`` must be timezone-aware and ``max_element_count`` at
      least 1, checked before the source is contacted (see
      :meth:`check_arguments`).
    """

    @abstractmethod
    def extract(
        self, from_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, T]]:
        """Return up to ``max_element_count`` items at or after ``from_date``."""

    @staticmethod
    def check_arguments(from_date: datetime, max_element_count: int) -> None:
        """Validate the arguments of :meth:`extract`.

        Implementations call this first, before any I/O.

        :raises ValueError: if ``from_date`` has no timezone or
            ``max_element_count`` is lower than 1.
        """
        if from_date.tzinfo is None or from_date.utcoffset() is None:
            raise ValueError(f"from_date must be timezone-aware, got {from_date!r}")
        if max_element_count < 1:
            raise ValueError(
                f"max_element_count must be at least 1, got {max_element_count}"
            )
