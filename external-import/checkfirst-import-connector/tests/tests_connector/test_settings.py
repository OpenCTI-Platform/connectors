from datetime import date, datetime, timedelta, timezone
from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


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
                    "duration_period": "PT5M",
                },
                "checkfirst": {
                    "api_url": "https://api.checkfirst.example",
                    "api_key": "test-api-key",
                    "api_endpoint": "/v1/articles",
                    "since": "2025-01-01T00:00:00Z",
                    "until": "2025-01-31T23:59:59Z",
                    "force_reprocess": True,
                    "tlp_level": "clear",
                    "max_row_bytes": 8192,
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
                "checkfirst": {
                    "api_url": "https://api.checkfirst.example",
                    "api_key": "test-api-key",
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
    assert isinstance(settings.checkfirst, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "checkfirst": {
                    "api_url": "https://api.checkfirst.example",
                    "api_key": "test-api-key",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "checkfirst": {
                    "api_url": "https://api.checkfirst.example",
                    "api_key": "test-api-key",
                },
            },
            "connector.id",
            id="invalid_connector_id",
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

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    assert str("Error validating configuration") in str(err)


def _settings_from(checkfirst: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a minimal valid dict and the given `checkfirst` values."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "checkfirst": {
                        "api_url": "https://api.checkfirst.example",
                        "api_key": "test-api-key",
                        **checkfirst,
                    },
                }
            )

    return FakeConnectorSettings()


def test_settings_should_default_until_to_none():
    """`until` is optional: without it the import window has no end."""
    assert _settings_from({}).checkfirst.until is None


@pytest.mark.parametrize(
    "until, expected",
    [
        pytest.param(
            "2025-01-31T23:59:59Z",
            datetime(2025, 1, 31, 23, 59, 59, tzinfo=timezone.utc),
            id="iso_string_utc",
        ),
        pytest.param(
            "2025-01-31T23:59:59+02:00",
            datetime(2025, 1, 31, 21, 59, 59, tzinfo=timezone.utc),
            id="iso_string_with_offset",
        ),
        pytest.param(
            date(2025, 1, 31),
            datetime(2025, 1, 31, tzinfo=timezone.utc),
            id="yaml_unquoted_date",
        ),
        pytest.param(
            datetime(2025, 1, 31, 23, 59, 59),
            datetime(2025, 1, 31, 23, 59, 59, tzinfo=timezone.utc),
            id="yaml_unquoted_naive_datetime",
        ),
    ],
)
def test_settings_should_parse_absolute_until_as_utc(until, expected):
    """An absolute `until` becomes a UTC-aware datetime, whatever form the config gives."""
    settings = _settings_from({"since": "2025-01-01T00:00:00Z", "until": until})
    assert settings.checkfirst.until == expected


def test_settings_should_resolve_relative_until_against_now():
    """A duration `until` is resolved against now, like `since`."""
    before = datetime.now(tz=timezone.utc)
    settings = _settings_from({"since": "P1Y", "until": "P30D"})
    after = datetime.now(tz=timezone.utc)

    assert before - timedelta(days=30) <= settings.checkfirst.until
    assert settings.checkfirst.until <= after - timedelta(days=30)


def test_settings_should_accept_until_equal_to_since():
    """A window of a single instant is valid: the bounds are inclusive."""
    settings = _settings_from(
        {"since": "2025-01-01T00:00:00Z", "until": "2025-01-01T00:00:00Z"}
    )
    assert settings.checkfirst.until == settings.checkfirst.since


def test_settings_should_raise_when_until_is_not_a_date():
    """An unparsable `until` is reported against that field."""
    with pytest.raises(ConfigValidationError) as err:
        _settings_from({"until": "not-a-date"})

    assert "checkfirst.until" in str(err.value.__cause__)


@pytest.mark.parametrize(
    "since, until",
    [
        pytest.param(
            "2025-02-01T00:00:00Z", "2025-01-01T00:00:00Z", id="absolute_dates"
        ),
        pytest.param(
            "2025-02-01T00:00:00Z", date(2025, 1, 1), id="aware_since_naive_until"
        ),
        pytest.param("P30D", "P1Y", id="relative_durations"),
    ],
)
def test_settings_should_raise_when_until_is_before_since(since, until):
    """A window that ends before it starts is refused at startup."""
    with pytest.raises(ConfigValidationError) as err:
        _settings_from({"since": since, "until": until})

    assert "`CHECKFIRST_UNTIL` must not be earlier than `CHECKFIRST_SINCE`" in str(
        err.value.__cause__
    )


@pytest.mark.parametrize(
    "tuning, expected",
    [
        pytest.param(
            {
                "convert_workers": "4",
                "convert_batch_size": "16",
                "bundle_size": "5000",
                "max_row_bytes": "8192",
            },
            (4, 16, 5000, 8192),
            id="string_values_are_coerced_to_int",
        ),
        pytest.param(
            {
                "convert_workers": "",
                "convert_batch_size": "",
                "bundle_size": "",
                "max_row_bytes": "",
            },
            (1, 32, 10_000, None),
            id="empty_values_fall_back_to_defaults",
        ),
    ],
)
def test_settings_should_coerce_tuning_values(tuning, expected):
    """
    Test that the tuning parameters accept the string values provided by env vars,
    and that an empty value falls back to the field default instead of failing.
    """
    checkfirst = _settings_from(tuning).checkfirst
    assert (
        checkfirst.convert_workers,
        checkfirst.convert_batch_size,
        checkfirst.bundle_size,
        checkfirst.max_row_bytes,
    ) == expected


def test_settings_should_refuse_a_boolean_tuning_value():
    """A boolean is an int subclass in Python; it must not be read as 0 or 1."""
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {},
        "checkfirst": {
            "api_url": "https://api.checkfirst.example",
            "api_key": "test-api-key",
            "convert_workers": True,
        },
    }

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()


def test_settings_should_read_an_empty_until_as_unset():
    """An empty `CHECKFIRST_UNTIL` means no upper bound, as when it is unset."""
    assert _settings_from({"until": ""}).checkfirst.until is None
