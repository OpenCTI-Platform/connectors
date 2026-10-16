"""Shared fixtures for censys_collections tests."""

import pytest


@pytest.fixture(name="mock_config")
def fixture_mock_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCTI_URL", "http://test")
    monkeypatch.setenv("OPENCTI_TOKEN", "opencti-token")
    monkeypatch.setenv("CENSYS_COLLECTIONS_ORGANISATION_ID", "censys-org-id")
    monkeypatch.setenv("CENSYS_COLLECTIONS_TOKEN", "censys-token")
