import pytest
from settings import ConfigLoader


def test_settings_should_migrate_deprecated_reversinglabs_spectra_analyze_max_tlp(
    monkeypatch,
):
    """
    Test that the deprecated `reversinglabs_spectra_analyze.max_tlp` (`REVERSINGLABS_SPECTRA_ANALYZE_MAX_TLP`)
    is migrated to `connector.max_tlp` (`CONNECTOR_MAX_TLP`).
    """
    # Given: The max TLP is only set with the deprecated variable
    monkeypatch.delenv("CONNECTOR_MAX_TLP")
    monkeypatch.setenv("REVERSINGLABS_SPECTRA_ANALYZE_MAX_TLP", "TLP:RED")

    # When: The settings are loaded
    with pytest.warns(UserWarning, match="reversinglabs_spectra_analyze.max_tlp"):
        config = ConfigLoader()

    # Then: The value is used as connector.max_tlp
    assert config.connector.max_tlp == "TLP:RED"


def test_settings_should_migrate_deprecated_reversinglabs_max_tlp(monkeypatch):
    """
    Test that the deprecated `reversinglabs.max_tlp` (`REVERSINGLABS_MAX_TLP`), from the deprecated
    `reversinglabs` namespace, is migrated to `connector.max_tlp` (`CONNECTOR_MAX_TLP`).
    """
    # Given: The max TLP is only set with the variable of the deprecated namespace
    monkeypatch.delenv("CONNECTOR_MAX_TLP")
    monkeypatch.setenv("REVERSINGLABS_MAX_TLP", "TLP:RED")

    # When: The settings are loaded
    with pytest.warns(UserWarning, match=r"'reversinglabs\.max_tlp'"):
        config = ConfigLoader()

    # Then: The value is used as connector.max_tlp
    assert config.connector.max_tlp == "TLP:RED"
