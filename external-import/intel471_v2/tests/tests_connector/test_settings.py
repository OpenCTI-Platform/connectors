from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from intel471 import ConnectorSettings
from intel471.settings import normalize_epoch_millis

INITIAL_HISTORY_TIMESTAMP = 1696156471000  # 2023-10-01


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
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "intel471": {
                    "api_username": "test-username",
                    "api_key": "test-api-key",
                    "interval_indicators": 60,
                    "initial_history_indicators": INITIAL_HISTORY_TIMESTAMP,
                    "interval_yara": 60,
                    "initial_history_yara": INITIAL_HISTORY_TIMESTAMP,
                    "interval_cves": 120,
                    "initial_history_cves": INITIAL_HISTORY_TIMESTAMP,
                    "interval_reports": 120,
                    "initial_history_reports": INITIAL_HISTORY_TIMESTAMP,
                    "proxy": None,
                    "ioc_score": 90,
                    "backend": "verity471",
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
                "connector": {},
                "intel471": {
                    "api_username": "test-username",
                    "api_key": "test-api-key",
                    "interval_indicators": 60,
                },
            },
            id="minimal_valid_settings_dict",
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
    assert isinstance(settings.intel471, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "intel471": {
                    "api_username": "test-username",
                    "api_key": "test-api-key",
                    "interval_indicators": 60,
                    "initial_history_indicators": INITIAL_HISTORY_TIMESTAMP,
                    "interval_yara": 60,
                    "initial_history_yara": INITIAL_HISTORY_TIMESTAMP,
                    "interval_cves": 120,
                    "initial_history_cves": INITIAL_HISTORY_TIMESTAMP,
                    "interval_reports": 120,
                    "initial_history_reports": INITIAL_HISTORY_TIMESTAMP,
                    "proxy": None,
                    "ioc_score": 90,
                    "backend": "titan",
                },
            },
            "opencti.url",
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
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "intel471": {
                    "api_key": "test-api-key",
                    "interval_indicators": 60,
                    "initial_history_indicators": INITIAL_HISTORY_TIMESTAMP,
                    "interval_yara": 60,
                    "initial_history_yara": INITIAL_HISTORY_TIMESTAMP,
                    "interval_cves": 120,
                    "initial_history_cves": INITIAL_HISTORY_TIMESTAMP,
                    "interval_reports": 120,
                    "initial_history_reports": INITIAL_HISTORY_TIMESTAMP,
                    "proxy": None,
                    "ioc_score": 90,
                    "backend": "titan",
                },
            },
            "intel471.api_username",
            id="missing_intel471_api_username",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

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

    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        FakeConnectorSettings()


@pytest.mark.parametrize(
    "value, expected",
    [
        pytest.param(0, 0, id="zero_means_no_initial_history"),
        pytest.param(
            INITIAL_HISTORY_TIMESTAMP,
            INITIAL_HISTORY_TIMESTAMP,
            id="milliseconds_are_kept_as_is",
        ),
        pytest.param(
            INITIAL_HISTORY_TIMESTAMP // 1000,
            INITIAL_HISTORY_TIMESTAMP,
            id="seconds_are_converted_to_milliseconds",
        ),
        pytest.param(946_684_800, 946_684_800_000, id="lower_bound_in_seconds"),
        pytest.param(
            946_684_800_000, 946_684_800_000, id="lower_bound_in_milliseconds"
        ),
        pytest.param(4_102_444_800, 4_102_444_800_000, id="upper_bound_in_seconds"),
        pytest.param(
            4_102_444_800_000, 4_102_444_800_000, id="upper_bound_in_milliseconds"
        ),
    ],
)
def test_normalize_epoch_millis_should_return_milliseconds(value, expected):
    """
    Test that `normalize_epoch_millis` passes through epoch milliseconds, scales up
    epoch seconds, and leaves the `0` default (no initial history) alone.

    :param value: The raw `initial_history_*` value
    :param expected: The expected value in epoch milliseconds
    """

    assert normalize_epoch_millis(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(12345, id="too_small_for_either_unit"),
        pytest.param(946_684_799, id="just_below_lower_bound_in_seconds"),
        pytest.param(4_102_444_801_000, id="just_above_upper_bound_in_milliseconds"),
        pytest.param(-INITIAL_HISTORY_TIMESTAMP, id="negative"),
    ],
)
def test_normalize_epoch_millis_should_raise_when_neither_unit(value):
    """
    Test that `normalize_epoch_millis` rejects values that are plausible neither as
    epoch milliseconds nor as epoch seconds, rather than silently turning them into
    a date that would re-ingest the whole history.

    :param value: The raw `initial_history_*` value
    """

    with pytest.raises(ValueError, match="not a valid epoch timestamp"):
        normalize_epoch_millis(value)


def test_settings_should_convert_initial_history_given_in_seconds():
    """
    Test that `ConnectorSettings` converts every `initial_history_*` given in epoch
    seconds into epoch milliseconds, so the streams always call the API in the unit
    it expects.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {},
                    "intel471": {
                        "api_username": "test-username",
                        "api_key": "test-api-key",
                        "initial_history_indicators": INITIAL_HISTORY_TIMESTAMP // 1000,
                        "initial_history_yara": INITIAL_HISTORY_TIMESTAMP // 1000,
                        "initial_history_cves": INITIAL_HISTORY_TIMESTAMP,
                        "initial_history_reports": 0,
                    },
                }
            )

    settings = FakeConnectorSettings()
    assert settings.intel471.initial_history_indicators == INITIAL_HISTORY_TIMESTAMP
    assert settings.intel471.initial_history_yara == INITIAL_HISTORY_TIMESTAMP
    assert settings.intel471.initial_history_cves == INITIAL_HISTORY_TIMESTAMP
    assert settings.intel471.initial_history_reports == 0


def test_settings_should_raise_when_initial_history_is_not_an_epoch():
    """
    Test that an `initial_history_*` value that is plausible neither as epoch
    milliseconds nor as epoch seconds fails configuration validation on startup.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {},
                    "intel471": {
                        "api_username": "test-username",
                        "api_key": "test-api-key",
                        "initial_history_indicators": 12345,
                    },
                }
            )

    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        FakeConnectorSettings()
