# pragma: no cover # Do not compute coverage on test files
"""Offer tests for AbstractConverter and ConversionError."""

from abc import abstractmethod

import pytest
from connectors_sdk.converters import AbstractConverter, ConversionError
from connectors_sdk.exceptions.error import UseCaseError
from connectors_sdk.models import (
    BaseIdentifiedObject,
    OrganizationAuthor,
    Sector,
    TLPMarking,
)
from pydantic import BaseModel


class DummySector(BaseModel):
    """Dummy payload."""

    name: str


class DummySectors(BaseModel):
    """Dummy payload nesting other payloads."""

    sectors: list[DummySector]


class DummySectorConverter(AbstractConverter[DummySector]):
    """Dummy converter."""

    def transform(self, input: DummySector) -> list[BaseIdentifiedObject]:
        """Convert a dummy sector."""
        return [Sector(name=input.name, author=self.author, markings=self.markings)]


class DummySectorsConverter(AbstractConverter[DummySectors]):
    """Dummy converter delegating to a sub-converter."""

    def __init__(self, author: OrganizationAuthor, markings: list[TLPMarking]) -> None:
        """Build the sub-converter with the same context."""
        super().__init__(author=author, markings=markings)
        self.sector_converter = DummySectorConverter(author=author, markings=markings)

    def transform(self, input: DummySectors) -> list[BaseIdentifiedObject]:
        """Convert dummy sectors through the sub-converter."""
        result: list[BaseIdentifiedObject] = []
        for sector in input.sectors:
            result.extend(self.sector_converter.transform(sector))
        return result


@pytest.fixture
def author() -> OrganizationAuthor:
    """Return an author."""
    return OrganizationAuthor(name="Example Corp")


@pytest.fixture
def markings() -> list[TLPMarking]:
    """Return markings."""
    return [TLPMarking(level="amber+strict")]


def test_conversion_error_is_a_use_case_error() -> None:
    """Test that ConversionError can be skipped like any UseCaseError."""
    assert issubclass(ConversionError, UseCaseError)


def test_conversion_error_keeps_its_cause() -> None:
    """Test that the original exception is chained."""
    # Given an original error
    cause = ValueError("bad value")
    # When raising a ConversionError from it
    with pytest.raises(ConversionError) as error:
        raise ConversionError("Cannot convert") from cause
    # Then the cause is kept
    assert error.value.__cause__ is cause


def test_abstract_converter_cannot_be_instantiated(
    author: OrganizationAuthor, markings: list[TLPMarking]
) -> None:
    """Test that the ABC itself cannot be instantiated."""
    with pytest.raises(TypeError):
        AbstractConverter(author=author, markings=markings)  # type: ignore[abstract]


def test_converter_stores_run_context(
    author: OrganizationAuthor, markings: list[TLPMarking]
) -> None:
    """Test that author and markings are kept by the converter."""
    converter = DummySectorConverter(author=author, markings=markings)
    assert converter.author is author
    assert converter.markings is markings


def test_converter_applies_author_and_markings_without_returning_them(
    author: OrganizationAuthor, markings: list[TLPMarking]
) -> None:
    """Test that produced objects reference the context but do not contain it."""
    # Given a converter
    converter = DummySectorConverter(author=author, markings=markings)
    # When transforming an input
    result = converter.transform(DummySector(name="Energy"))
    # Then the objects reference the author and markings
    stix = result[0].to_stix2_object()
    assert stix["created_by_ref"] == author.id
    assert stix["object_marking_refs"] == [markings[0].id]
    # And the author and markings are not returned
    assert all(obj.id not in {author.id, markings[0].id} for obj in result)


def test_converter_is_deterministic(
    author: OrganizationAuthor, markings: list[TLPMarking]
) -> None:
    """Test that the same input gives the same ids."""
    first = DummySectorConverter(author=author, markings=markings)
    second = DummySectorConverter(author=author, markings=markings)
    payload = DummySector(name="Energy")
    assert [o.id for o in first.transform(payload)] == [
        o.id for o in second.transform(payload)
    ]


def test_wrongly_named_converter_is_rejected() -> None:
    """Test that a concrete converter must end with 'Converter'."""
    with pytest.raises(TypeError, match="Converter"):

        class CrowdStrikeActorBuilder(AbstractConverter[DummySector]):
            def transform(self, input: DummySector) -> list[BaseIdentifiedObject]:
                return []


def test_abstract_intermediate_class_name_is_not_checked() -> None:
    """Test that an abstract intermediate class can have any name."""

    class ProviderBase(AbstractConverter[DummySector]):
        @abstractmethod
        def helper(self) -> None:
            """Abstract helper."""

    class ProviderSectorConverter(ProviderBase):
        def helper(self) -> None:
            """Concrete helper."""

        def transform(self, input: DummySector) -> list[BaseIdentifiedObject]:
            return []

    assert ProviderSectorConverter.__name__.endswith("Converter")


def test_converter_composition(
    author: OrganizationAuthor, markings: list[TLPMarking]
) -> None:
    """Test that a converter can include the output of a sub-converter."""
    # Given a parent converter delegating to a sub-converter
    converter = DummySectorsConverter(author=author, markings=markings)
    # When transforming a nested payload
    result = converter.transform(
        DummySectors(sectors=[DummySector(name="Energy"), DummySector(name="Health")])
    )
    # Then the sub-converter objects are returned with the same context
    assert [obj.name for obj in result] == ["Energy", "Health"]  # type: ignore[attr-defined]
    for obj in result:
        stix = obj.to_stix2_object()
        assert stix["created_by_ref"] == author.id
        assert stix["object_marking_refs"] == [markings[0].id]
