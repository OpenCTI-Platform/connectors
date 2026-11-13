"""Tests for the loading contract."""

import pytest
from stix2.v21 import Bundle, DomainName

from shared.loader import AbstractLoader

BUNDLE = Bundle(
    id="bundle--00000000-0000-5000-8000-000000000001",
    objects=[DomainName(value="a.example")],
)


class InMemoryLoader(AbstractLoader):
    """Minimal loader keeping the bundles it receives."""

    def __init__(self) -> None:
        self.loaded: list[Bundle] = []

    def load(self, bundle: Bundle) -> None:
        self.loaded.append(bundle)


class FailingLoader(AbstractLoader):
    def load(self, bundle: Bundle) -> None:
        raise OSError(f"cannot deliver {bundle.id}")


def test_abstract_loader_cannot_be_instantiated():
    with pytest.raises(TypeError):
        AbstractLoader()  # type: ignore[abstract]


def test_loader_receives_the_bundle_and_returns_nothing():
    loader = InMemoryLoader()

    assert loader.load(BUNDLE) is None
    assert loader.loaded == [BUNDLE]


def test_load_failure_is_raised():
    with pytest.raises(OSError, match="cannot deliver bundle--00000000"):
        FailingLoader().load(BUNDLE)


def test_bundle_is_left_unchanged():
    before = BUNDLE.serialize()

    InMemoryLoader().load(BUNDLE)

    assert BUNDLE.serialize() == before
