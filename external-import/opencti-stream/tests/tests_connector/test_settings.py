from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from opencti_stream import ConnectorSettings
from pydantic import ValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "opencti-stream",
                    "log_level": "error",
                    "duration_period": "PT1M",
                    "live_stream_id": "live",
                    "live_stream_listen_delete": False,
                    "live_stream_no_dependencies": False,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "opencti-stream",
                    "live_stream_id": "live",
                },
            },
            id="minimal_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://target-opencti:8080",
                    "token": "target-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "opencti-stream",
                    "live_stream_id": "live",
                    "live_stream_opencti_url": "http://source-opencti:8080",
                    "live_stream_opencti_token": "source-token",
                },
            },
            id="dual_instance_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, expected_loc",
    [
        pytest.param(
            {},
            ("opencti", "url"),
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "opencti-stream",
                    "live_stream_id": "live",
                },
            },
            ("opencti", "url"),
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "opencti-stream",
                    # Missing live_stream_id
                },
            },
            ("connector", "live_stream_id"),
            id="missing_live_stream_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, expected_loc):
    """
    Test that `ConnectorSettings` raises on invalid input AND that the failure points
    at the expected field. We unwrap the `ConfigValidationError` (raised by
    `connectors-sdk` to wrap a pydantic `ValidationError`) and assert the expected
    field appears in at least one of the validation error locations.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param expected_loc: Tuple representing the pydantic location (e.g. ("connector", "live_stream_id"))
        that should appear in the underlying ValidationError
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err_info:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err_info.value)

    # The cause is the underlying pydantic ValidationError; check the expected field
    # appears in the reported error locations. We match the last element of the loc
    # tuple (the field name) since some errors are reported at the nested location
    # (e.g. ("connector", "live_stream_id")) and some at the inner-model root
    # (e.g. ("url",) when `_OpenCTIConfig` is built with empty input).
    cause = err_info.value.__cause__
    assert isinstance(
        cause, ValidationError
    ), "Expected wrapped pydantic ValidationError"
    error_locs = [error["loc"] for error in cause.errors()]
    expected_field = expected_loc[-1]
    assert any(
        loc and loc[-1] == expected_field for loc in error_locs
    ), f"Expected validation error on field {expected_field!r}, got {error_locs}"
