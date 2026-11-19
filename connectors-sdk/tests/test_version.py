# pragma: no cover # Do not compute coverage on test files
"""Offer tests for the SDK version."""

import importlib.metadata
from importlib.metadata import PackageNotFoundError, version

import connectors_sdk
import pytest


def test_version_is_read_from_the_installed_distribution():
    """Test that `__version__` matches the installed package metadata."""
    # Given the installed SDK
    # Then its version should be the one of its distribution
    assert connectors_sdk.__version__ == version("connectors-sdk")


def test_version_falls_back_when_the_sdk_is_not_installed(
    monkeypatch: pytest.MonkeyPatch,
):
    """Test that the version falls back to `0.0.0` without package metadata."""

    # Given no installed distribution
    def _not_found(_: str) -> str:
        raise PackageNotFoundError("connectors-sdk")

    monkeypatch.setattr(importlib.metadata, "version", _not_found)
    # When reading the version
    # Then it should fall back to the placeholder version
    assert connectors_sdk._read_version() == "0.0.0"
