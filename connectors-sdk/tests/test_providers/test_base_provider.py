# pragma: no cover # Do not compute coverage on test files
"""Offer tests for AbstractDateRangeProvider and AbstractByIdProvider."""

import importlib
import sys
from abc import abstractmethod
from datetime import datetime, timezone

import connectors_sdk.providers as providers
import pytest
from connectors_sdk.converters import AbstractConverter
from connectors_sdk.models import BaseIdentifiedObject, OrganizationAuthor, Sector
from connectors_sdk.providers import AbstractByIdProvider, AbstractDateRangeProvider
from pydantic import BaseModel

D1 = datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc)
D2 = datetime(2026, 10, 21, 14, 12, 9, tzinfo=timezone.utc)


class SectorPayload(BaseModel):
    """A dated sector, as a source would return it."""

    name: str
    modified: datetime


class DummySectorDateRangeProvider(AbstractDateRangeProvider[SectorPayload]):
    """Dummy provider over an in-memory source."""

    def __init__(self, source: list[SectorPayload]) -> None:
        """Keep the source."""
        self.source = source

    def get_data(
        self, since: datetime, limit: int
    ) -> dict[datetime, list[SectorPayload]]:
        """Return up to `limit` items dated on or after `since`, grouped by date."""
        result: dict[datetime, list[SectorPayload]] = {}
        items = sorted(self.source, key=lambda item: item.modified)
        for item in [item for item in items if item.modified >= since][:limit]:
            result.setdefault(item.modified, []).append(item)
        return result


class DummySectorByIdProvider(AbstractByIdProvider[SectorPayload]):
    """Dummy provider returning a sector per known id."""

    def get_data(self, ids: list[str]) -> dict[str, SectorPayload]:
        """Return the sector of each known id."""
        return {
            id: SectorPayload(name=id, modified=D1) for id in ids if id != "unknown"
        }


class DummySectorConverter(AbstractConverter[SectorPayload]):
    """Dummy converter of the provider items."""

    def transform(self, input: SectorPayload) -> list[BaseIdentifiedObject]:
        """Convert a payload into a sector."""
        return [Sector(name=input.name, author=self.author, markings=self.markings)]


SOURCE = [
    SectorPayload(name="Energy", modified=D1),
    SectorPayload(name="Finance", modified=D1),
    SectorPayload(name="Health", modified=D2),
]


def test_public_api_is_present() -> None:
    """Test that features are not removed by mistake."""
    assert set(providers.__all__) == {
        "AbstractByIdProvider",
        "AbstractDateRangeProvider",
    }


def test_providers_import_without_provider_libraries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that importing the package does not need falconpy."""
    monkeypatch.setitem(sys.modules, "falconpy", None)  # type: ignore[arg-type]
    for name in [n for n in sys.modules if n.startswith("connectors_sdk.providers")]:
        monkeypatch.delitem(sys.modules, name)

    module = importlib.import_module("connectors_sdk.providers")

    assert module.AbstractDateRangeProvider.__name__ == "AbstractDateRangeProvider"


@pytest.mark.parametrize("provider", [AbstractDateRangeProvider, AbstractByIdProvider])
def test_abstract_providers_cannot_be_instantiated(provider: type) -> None:
    """Test that the contracts cannot be instantiated."""
    with pytest.raises(TypeError):
        provider()


def test_date_range_groups_items_by_date() -> None:
    """Test that items sharing a date are grouped, and the next checkpoint."""
    result = DummySectorDateRangeProvider(SOURCE).get_data(since=D1, limit=10)

    assert [item.name for item in result[D1]] == ["Energy", "Finance"]
    assert max(result) == D2


def test_date_range_since_is_inclusive() -> None:
    """Test that items dated exactly at `since` are returned."""
    result = DummySectorDateRangeProvider(SOURCE).get_data(since=D2, limit=10)

    assert list(result) == [D2]


def test_date_range_nothing_new() -> None:
    """Test that nothing after `since` gives an empty result."""
    later = datetime(2027, 1, 1, tzinfo=timezone.utc)

    assert DummySectorDateRangeProvider(SOURCE).get_data(since=later, limit=10) == {}


def test_by_id_leaves_unknown_ids_out() -> None:
    """Test that an id with no data is absent."""
    result = DummySectorByIdProvider().get_data(["Energy", "unknown"])

    assert list(result) == ["Energy"]


def test_provider_items_chain_with_converter() -> None:
    """Test that provider items are converter inputs, without adaptation."""
    converter = DummySectorConverter(
        author=OrganizationAuthor(name="Example"), markings=[]
    )

    result = DummySectorDateRangeProvider(SOURCE).get_data(since=D1, limit=10)
    objects = [
        obj
        for items in result.values()
        for i in items
        for obj in converter.transform(i)
    ]

    assert [obj.name for obj in objects] == ["Energy", "Finance", "Health"]  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("base", "suffix"),
    [
        (AbstractDateRangeProvider, "DateRangeProvider"),
        (AbstractByIdProvider, "ByIdProvider"),
    ],
)
def test_wrongly_named_provider_is_rejected(base: type, suffix: str) -> None:
    """Test that a concrete provider must end with its suffix."""
    with pytest.raises(TypeError, match=f"<Provider><Payload>{suffix}"):
        type("CrowdStrikeActors", (base,), {"get_data": lambda self: {}})


@pytest.mark.parametrize("base", [AbstractDateRangeProvider, AbstractByIdProvider])
def test_abstract_intermediate_provider_may_have_any_name(base: type) -> None:
    """Test that an abstract intermediate class is not checked."""
    intermediate = type(
        "CrowdStrikeBase", (base,), {"get_data": abstractmethod(lambda self: {})}
    )

    assert intermediate.__name__ == "CrowdStrikeBase"
