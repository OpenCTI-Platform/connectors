"""AbstractDateRangeProvider and AbstractByIdProvider."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Generic, TypeVar

from connectors_sdk.logger._class_logger import _ClassLoggerMixin
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

DATE_RANGE_PROVIDER_NAME_SUFFIX = "DateRangeProvider"
BY_ID_PROVIDER_NAME_SUFFIX = "ByIdProvider"


def _check_provider_name(cls: type, suffix: str) -> None:
    """Reject a concrete provider whose name does not end with ``suffix``.

    Args:
        cls: The provider class being defined.
        suffix: The expected name suffix.

    Raises:
        TypeError: If a concrete provider is wrongly named.
    """
    # ABCMeta computes `__abstractmethods__` after `__init_subclass__` runs,
    # so abstractness has to be computed here.
    is_abstract = any(
        getattr(getattr(cls, name, None), "__isabstractmethod__", False)
        for name in dir(cls)
    )
    if not is_abstract and not cls.__name__.endswith(suffix):
        raise TypeError(
            f"Provider class '{cls.__name__}' must be named "
            f"'<Provider><Payload>{suffix}'."
        )


class AbstractDateRangeProvider(_ClassLoggerMixin, ABC, Generic[T]):
    """Fetch the items of a source dated on or after a given date.

    A date range provider is named ``<Provider><Payload>DateRangeProvider`` and
    declares as its type parameter the input model of the converter it feeds,
    so the provider and the converter can be chained.

    ``get_data`` makes one list request to the source, passes ``limit`` to it
    and never follows pagination. Extra per-item requests needed to build an
    item are allowed. The date is the one the source uses to report changes
    (e.g. a last modification date).

    Examples:
        >>> from datetime import timezone
        >>> class Payload(BaseModel):
        ...     name: str
        >>> class ExampleItemDateRangeProvider(AbstractDateRangeProvider[Payload]):
        ...     def get_data(self, since, limit):
        ...         return {datetime(2026, 1, 1, tzinfo=timezone.utc): [Payload(name="a")]}
        >>> result = ExampleItemDateRangeProvider().get_data(
        ...     since=datetime(2025, 1, 1, tzinfo=timezone.utc), limit=10
        ... )
        >>> max(result).year  # the `since` of the next call
        2026
    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Reject a concrete provider whose name does not end with ``DateRangeProvider``."""
        super().__init_subclass__(**kwargs)
        _check_provider_name(cls, DATE_RANGE_PROVIDER_NAME_SUFFIX)

    @abstractmethod
    def get_data(self, since: datetime, limit: int) -> dict[datetime, list[T]]:
        """Fetch the items dated on or after ``since``, grouped by date.

        ``since`` is inclusive: items dated exactly at ``since`` are returned
        again, so that items sharing the checkpoint date are never lost.

        Args:
            since: The timezone-aware start date, inclusive.
            limit: The maximum number of items requested from the source.

        Returns:
            The items keyed by their timezone-aware date, each key holding every
            returned item with that date. The latest key is the ``since`` of the
            next call. Empty when the source has nothing new.

        Raises:
            DataRetrievalError: If the source fails.
        """


class AbstractByIdProvider(_ClassLoggerMixin, ABC, Generic[T]):
    """Fetch the item of each given id from a source.

    A by id provider is named ``<Provider><Payload>ByIdProvider`` and declares as
    its type parameter the input model of the converter it feeds, so the
    provider and the converter can be chained.

    Examples:
        >>> class Payload(BaseModel):
        ...     name: str
        >>> class ExampleItemByIdProvider(AbstractByIdProvider[Payload]):
        ...     def get_data(self, ids):
        ...         return {id: Payload(name=id) for id in ids if id != "unknown"}
        >>> sorted(ExampleItemByIdProvider().get_data(["a", "unknown"]))
        ['a']
    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Reject a concrete provider whose name does not end with ``ByIdProvider``."""
        super().__init_subclass__(**kwargs)
        _check_provider_name(cls, BY_ID_PROVIDER_NAME_SUFFIX)

    @abstractmethod
    def get_data(self, ids: list[str]) -> dict[str, T]:
        """Fetch the item of each id.

        Args:
            ids: The ids to fetch.

        Returns:
            The item of each id, keyed by id. An id the source has no data for
            is absent.

        Raises:
            DataRetrievalError: If the source fails, for any of the ids.
        """
