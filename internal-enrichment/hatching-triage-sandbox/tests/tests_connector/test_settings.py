from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "Artifact, Url",
                    "log_level": "error",
                    "auto": True,
                },
                "hatching_triage_sandbox": {
                    "token": "test-api-token",
                    "base_url": "https://tria.ge/api",
                    "use_existing_analysis": True,
                    "family_color": "#0059f7",
                    "botnet_color": "#f79e00",
                    "campaign_color": "#7a01e5",
                    "tag_color": "#54483b",
                    "max_tlp": "TLP:AMBER",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "hatching_triage_sandbox": {
                    "token": "test-api-token",
                },
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
    assert isinstance(settings.hatching_triage_sandbox, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "url", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "Artifact, Url",
                    "log_level": "error",
                },
                "hatching_triage_sandbox": {
                    "token": "test-api-token",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "Artifact, Url",
                    "log_level": "error",
                },
                "hatching_triage_sandbox": {
                    "token": "test-api-token",
                },
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
