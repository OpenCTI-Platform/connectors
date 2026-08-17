from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "ImportExternalReference",
                    "scope": "External-Reference",
                    "log_level": "error",
                    "auto": False,
                },
                "import_external_reference": {
                    "import_as_pdf": True,
                    "import_as_md": True,
                    "import_pdf_as_md": True,
                    "timestamp_files": False,
                    "cache_size": 32,
                    "cache_ttl": 3600,
                    "browser_worker_count": 4,
                    "max_download_size": 52428800,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "ImportExternalReference",
                    "scope": "External-Reference",
                },
                "import_external_reference": {},
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` accepts valid input.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.import_external_reference, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "url", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "ImportExternalReference",
                    "scope": "External-Reference",
                    "log_level": "error",
                },
                "import_external_reference": {},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "ImportExternalReference",
                    "scope": "External-Reference",
                    "log_level": "error",
                },
                "import_external_reference": {},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` raises on invalid input.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The field name that is expected to be reported in the
        validation error. Asserting the error mentions this field prevents
        regressions where the wrong field becomes the failing one.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err.value)
    # Walk the chained pydantic ValidationError to assert that the expected
    # field path is among the failing ones. Without this assertion the
    # parametrized field_name would not actually be exercised.
    cause = err.value.__cause__
    assert cause is not None, "ConfigValidationError must wrap the pydantic error"
    expected_field = field_name.split(".")[-1]
    error_fields = [str(error["loc"][-1]) for error in cause.errors() if error["loc"]]
    assert expected_field in error_fields, (
        f"Expected a validation error for field {field_name!r}, "
        f"got errors for: {error_fields}"
    )
