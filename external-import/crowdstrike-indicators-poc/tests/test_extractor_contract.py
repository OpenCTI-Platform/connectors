"""Tests for the source-independent extraction contract."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel

from shared.extractor import AbstractExtractor


class Item(BaseModel):
    name: str


class InMemoryExtractor(AbstractExtractor[Item]):
    """Minimal implementation over a list of ``(datetime, Item)`` pairs."""

    def __init__(self, data: list[tuple[datetime, Item]]) -> None:
        self.data = sorted(data, key=lambda pair: pair[0])
        self.calls = 0

    def extract(
        self, after_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, Item]]:
        self.check_arguments(after_date, max_element_count)
        self.calls += 1
        return [pair for pair in self.data if pair[0] > after_date][:max_element_count]


T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _source(count: int) -> InMemoryExtractor:
    return InMemoryExtractor(
        [(T0 + timedelta(seconds=i), Item(name=f"item-{i}")) for i in range(count)]
    )


def test_abstract_extractor_cannot_be_instantiated():
    with pytest.raises(TypeError):
        AbstractExtractor()  # type: ignore[abstract]


def test_rejects_non_positive_cap_before_touching_the_source():
    source = _source(3)
    with pytest.raises(ValueError, match="max_element_count"):
        source.extract(T0, 0)
    assert source.calls == 0


def test_rejects_naive_datetime_before_touching_the_source():
    source = _source(3)
    with pytest.raises(ValueError, match="timezone-aware"):
        source.extract(datetime(2026, 1, 1), 10)
    assert source.calls == 0


def test_valid_call_returns_validated_items_with_aware_ascending_datetimes():
    result = _source(5).extract(T0, 10)

    # The item at T0 equals after_date and is excluded.
    assert [item.name for _, item in result] == [f"item-{i}" for i in range(1, 5)]
    assert all(isinstance(item, Item) for _, item in result)
    assert all(dt.tzinfo is not None for dt, _ in result)
    assert [dt for dt, _ in result] == sorted(dt for dt, _ in result)


def test_cap_is_a_hard_upper_bound():
    assert len(_source(10).extract(T0, 3)) == 3


def test_empty_result_when_nothing_after_date():
    assert _source(3).extract(T0 + timedelta(days=1), 10) == []
