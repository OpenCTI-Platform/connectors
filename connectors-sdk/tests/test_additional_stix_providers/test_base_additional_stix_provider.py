# pragma: no cover # Do not compute coverage on test files
"""Offer tests for AbstractAdditionalStixProvider."""

from abc import abstractmethod

import connectors_sdk.additional_stix_providers as additional_stix_providers
import pytest
from connectors_sdk.additional_stix_providers import AbstractAdditionalStixProvider
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import (
    BaseIdentifiedObject,
    OrganizationAuthor,
    Sector,
    TLPMarking,
)


class FakeSource:
    """A source counting calls, with data for some ids and failures for others."""

    def __init__(self, data: dict[str, str], failures: set[str]) -> None:
        """Store the source behaviour."""
        self.data = data
        self.failures = failures
        self.calls: list[str] = []

    def read(self, id: str) -> str | None:
        """Return the value of an id, None, or raise."""
        self.calls.append(id)
        if id in self.failures:
            raise ConnectionError("source down")
        return self.data.get(id)


class DummySectorAdditionalStixProvider(AbstractAdditionalStixProvider[str]):
    """Dummy provider returning a sector per id."""

    def __init__(
        self,
        source: FakeSource,
        author: OrganizationAuthor,
        markings: list[TLPMarking],
        cache: bool = False,
    ) -> None:
        """Keep the source."""
        super().__init__(author=author, markings=markings, cache=cache)
        self.source = source

    def _fetch(self, id: str) -> list[BaseIdentifiedObject] | None:
        """Read the source and build a sector."""
        try:
            value = self.source.read(id)
        except ConnectionError as err:
            raise DataRetrievalError(f"Cannot read {id}") from err
        if value is None:
            return None
        return [Sector(name=value, author=self.author, markings=self.markings)]


@pytest.fixture
def source() -> FakeSource:
    """Return a source with data for 'A' and a failure for 'X'."""
    return FakeSource(data={"A": "Energy"}, failures={"X"})


def make_provider(
    source: FakeSource, cache: bool = False
) -> DummySectorAdditionalStixProvider:
    """Build a provider."""
    return DummySectorAdditionalStixProvider(
        source=source,
        author=OrganizationAuthor(name="Example Corp"),
        markings=[TLPMarking(level="amber")],
        cache=cache,
    )


def test_public_api_is_present() -> None:
    """Test that features are not removed by mistake."""
    assert set(additional_stix_providers.__all__) == {"AbstractAdditionalStixProvider"}


def test_abstract_provider_cannot_be_instantiated() -> None:
    """Test that the ABC itself cannot be instantiated."""
    with pytest.raises(TypeError):
        AbstractAdditionalStixProvider(  # type: ignore[abstract]
            author=OrganizationAuthor(name="Example Corp"), markings=[]
        )


def test_get_returns_objects(source: FakeSource) -> None:
    """Test that data found for an id is returned as objects."""
    result = make_provider(source).get("A")

    assert result is not None
    assert [obj.name for obj in result] == ["Energy"]  # type: ignore[attr-defined]


def test_get_returns_none_when_nothing(source: FakeSource) -> None:
    """Test that an id without data gives None."""
    assert make_provider(source).get("B") is None


def test_get_many_groups_by_id_and_fetches_once(source: FakeSource) -> None:
    """Test that ids are deduplicated and ids without data left out."""
    result = make_provider(source).get_many(["A", "B", "A"])

    assert list(result) == ["A"]
    assert source.calls == ["A", "B"]


def test_failure_is_raised(source: FakeSource) -> None:
    """Test that a source failure raises a DataRetrievalError with its cause."""
    with pytest.raises(DataRetrievalError) as error:
        make_provider(source).get("X")

    assert isinstance(error.value.__cause__, ConnectionError)


def test_failure_in_a_list_is_raised(source: FakeSource) -> None:
    """Test that a failure for one id fails the whole call."""
    with pytest.raises(DataRetrievalError):
        make_provider(source).get_many(["A", "X"])


def test_author_and_markings_applied_not_returned(source: FakeSource) -> None:
    """Test that objects reference the context without containing it."""
    provider = make_provider(source)

    result = provider.get("A") or []

    stix = result[0].to_stix2_object()
    assert stix["created_by_ref"] == provider.author.id
    assert stix["object_marking_refs"] == [provider.markings[0].id]
    assert all(
        obj.id not in {provider.author.id, provider.markings[0].id} for obj in result
    )


def test_cache_returns_cached_result(source: FakeSource) -> None:
    """Test that a cached id is fetched once."""
    provider = make_provider(source, cache=True)

    first, second = provider.get("A"), provider.get("A")

    assert first == second
    assert source.calls == ["A"]


def test_cache_keeps_none(source: FakeSource) -> None:
    """Test that 'nothing' results are cached too."""
    provider = make_provider(source, cache=True)

    assert provider.get("B") is None
    assert provider.get("B") is None
    assert source.calls == ["B"]


def test_failure_is_not_cached(source: FakeSource) -> None:
    """Test that an id failing then succeeding is fetched again."""
    provider = make_provider(source, cache=True)
    with pytest.raises(DataRetrievalError):
        provider.get("X")

    source.failures.clear()
    source.data["X"] = "Health"

    assert provider.get("X") is not None
    assert source.calls == ["X", "X"]


def test_clear_cache(source: FakeSource) -> None:
    """Test that a cleared cache fetches again."""
    provider = make_provider(source, cache=True)
    provider.get("A")

    provider.clear_cache()
    provider.get("A")

    assert source.calls == ["A", "A"]


def test_cache_disabled_by_default(source: FakeSource) -> None:
    """Test that without cache every call reaches the source."""
    provider = make_provider(source)

    provider.get("A")
    provider.get("A")

    assert source.calls == ["A", "A"]


def test_wrongly_named_provider_is_rejected() -> None:
    """Test that a concrete provider must end with 'AdditionalStixProvider'."""
    with pytest.raises(TypeError, match="AdditionalStixProvider"):

        class CrowdStrikeReportPdfFetcher(AbstractAdditionalStixProvider[str]):
            def _fetch(self, id: str) -> list[BaseIdentifiedObject] | None:
                return None


def test_abstract_intermediate_class_name_is_not_checked() -> None:
    """Test that an abstract intermediate class can have any name."""

    class ProviderBase(AbstractAdditionalStixProvider[str]):
        @abstractmethod
        def helper(self) -> None:
            """Abstract helper."""

    class ProviderPayloadAdditionalStixProvider(ProviderBase):
        def helper(self) -> None:
            """Concrete helper."""

        def _fetch(self, id: str) -> list[BaseIdentifiedObject] | None:
            return None

    assert ProviderPayloadAdditionalStixProvider.__name__.endswith(
        "AdditionalStixProvider"
    )
