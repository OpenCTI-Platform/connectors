"""Tests for censys_collections.settings."""

import pytest
from censys_collections.settings import ConfigLoader


@pytest.mark.usefixtures("mock_config")
def test_config_loads_required_fields() -> None:
    config = ConfigLoader()
    assert config.censys_collections.organisation_id.get_secret_value() == "censys-org-id"
    assert config.censys_collections.token.get_secret_value() == "censys-token"


@pytest.mark.usefixtures("mock_config")
def test_config_defaults() -> None:
    config = ConfigLoader()
    assert config.censys_collections.tlp_level == "TLP:AMBER"
    assert config.censys_collections.indicator_score == 50
    assert config.censys_collections.collection_ids is None
    assert config.censys_collections.excluded_collection_ids is None
    assert config.censys_collections.auto_indicator_by_score is False
    assert config.censys_collections.indicator_score_threshold == 50
    assert config.connector.name == "Censys Collections"


@pytest.mark.usefixtures("mock_config")
def test_config_collection_ids_csv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CENSYS_COLLECTIONS_COLLECTION_IDS", "abc-123,def-456")
    config = ConfigLoader()
    assert config.censys_collections.collection_ids == ["abc-123", "def-456"]


@pytest.mark.usefixtures("mock_config")
def test_config_excluded_collection_ids_csv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CENSYS_COLLECTIONS_EXCLUDED_COLLECTION_IDS", "abc-123,def-456")
    config = ConfigLoader()
    assert config.censys_collections.excluded_collection_ids == ["abc-123", "def-456"]


@pytest.mark.usefixtures("mock_config")
def test_config_auto_indicator_by_score_toggle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CENSYS_COLLECTIONS_AUTO_INDICATOR_BY_SCORE", "true")
    monkeypatch.setenv("CENSYS_COLLECTIONS_INDICATOR_SCORE_THRESHOLD", "75")
    config = ConfigLoader()
    assert config.censys_collections.auto_indicator_by_score is True
    assert config.censys_collections.indicator_score_threshold == 75


@pytest.mark.usefixtures("mock_config")
def test_config_custom_tlp_and_score(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CENSYS_COLLECTIONS_TLP_LEVEL", "TLP:GREEN")
    monkeypatch.setenv("CENSYS_COLLECTIONS_INDICATOR_SCORE", "75")
    config = ConfigLoader()
    assert config.censys_collections.tlp_level == "TLP:GREEN"
    assert config.censys_collections.indicator_score == 75
