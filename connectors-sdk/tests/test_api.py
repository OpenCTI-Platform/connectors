# pragma: no cover # Do not compute coverage on test files
"""Offer tests for the root public API."""

import connectors_sdk as root_api


def test_root_public_api_is_valid():
    """Test that features are not removed by mistake."""
    # Given the feature name
    # Then it should all be present
    imports = {
        "BaseConnectorSettings",
        "BaseConfigModel",
        "BaseExternalImportConnectorConfig",
        "BaseInternalEnrichmentConnectorConfig",
        "BaseInternalExportFileConnectorConfig",
        "BaseInternalImportFileConnectorConfig",
        "BaseStreamConnectorConfig",
        "ConfigError",
        "ConfigValidationError",
        "DatetimeFromIsoString",
        "ListFromString",
        "DeprecatedField",
    }
    missing = imports - set(root_api.__all__)
    extra = set(root_api.__all__) - imports
    assert not missing, f"Missing features in root public api: {missing}"
    assert not extra, f"Unexpected features in root public api: {extra}"
