"""Tests for the source-independent enrichment contract."""

import pytest
from pydantic import BaseModel

from shared.enricher import AbstractEnricher


class Item(BaseModel):
    name: str


class SourceDown(Exception):
    """The fake source failed."""


class InMemoryEnricher(AbstractEnricher[Item]):
    """Minimal implementation over a dict, counting its source lookups."""

    def __init__(self, data: dict[str, Item], failing: set[str] = frozenset()):
        super().__init__()
        self.data = data
        self.failing = set(failing)
        self.fetched: list[str] = []

    def _fetch(self, key: str) -> Item | None:
        self.fetched.append(key)
        if key in self.failing:
            raise SourceDown(key)
        return self.data.get(key)


def _enricher(**kwargs) -> InMemoryEnricher:
    return InMemoryEnricher({"known": Item(name="Known")}, **kwargs)


def test_abstract_enricher_cannot_be_instantiated():
    with pytest.raises(TypeError):
        AbstractEnricher()  # type: ignore[abstract]


def test_known_key_returns_a_validated_item():
    assert _enricher().extract("known") == Item(name="Known")


def test_unknown_key_returns_none_without_raising():
    assert _enricher().extract("unknown") is None


def test_found_item_is_fetched_once():
    enricher = _enricher()

    first = enricher.extract("known")
    second = enricher.extract("known")

    assert enricher.fetched == ["known"]
    assert first == second == Item(name="Known")


def test_miss_is_fetched_once():
    enricher = _enricher()

    assert enricher.extract("unknown") is None
    assert enricher.extract("unknown") is None
    assert enricher.fetched == ["unknown"]


def test_different_keys_are_fetched_separately():
    enricher = _enricher()

    enricher.extract("known")
    enricher.extract("unknown")

    assert enricher.fetched == ["known", "unknown"]


def test_error_is_raised_and_not_cached():
    enricher = _enricher(failing={"known"})

    with pytest.raises(SourceDown):
        enricher.extract("known")
    enricher.failing.clear()

    assert enricher.extract("known") == Item(name="Known")
    assert enricher.fetched == ["known", "known"]


def test_lookup_after_a_reset_contacts_the_source_again():
    enricher = _enricher()

    enricher.extract("known")
    enricher.extract("unknown")
    enricher.reset_cache()
    enricher.extract("known")
    enricher.extract("unknown")

    assert enricher.fetched == ["known", "unknown", "known", "unknown"]


def test_caches_are_per_instance():
    first, second = _enricher(), _enricher()

    first.extract("known")
    second.extract("known")

    assert first.fetched == second.fetched == ["known"]
