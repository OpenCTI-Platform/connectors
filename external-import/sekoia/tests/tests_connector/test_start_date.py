import base64
import logging
import time
from datetime import date, datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError
from src.connector.models import ConfigLoader
from src.connector.models.configs.sekoia_configs import _ConfigLoaderSekoia
from src.connector.sekoia import SekoiaConnector

SETTINGS_LOGGER = "src.connector.models.configs.sekoia_configs"


def _load(monkeypatch, start_date=None):
    """Load the Sekoia settings from the environment, like the connector does."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("SEKOIA_API_KEY", "test-api-key")
    monkeypatch.delenv("SEKOIA_START_DATE", raising=False)
    if start_date is not None:
        monkeypatch.setenv("SEKOIA_START_DATE", start_date)
    return ConfigLoader().sekoia


def _assert_close_to_now(value: datetime, expected_delta: timedelta) -> None:
    assert value.tzinfo is not None
    assert value.utcoffset() == timedelta(0)
    expected = datetime.now(timezone.utc) - expected_delta
    assert abs(value - expected) < timedelta(minutes=1)


def test_default_start_date_is_90_days_ago(monkeypatch):
    settings = _load(monkeypatch)

    _assert_close_to_now(settings.start_date, timedelta(days=90))


@pytest.mark.parametrize(
    "raw",
    ["2023-05-01", "2023-05-01T00:00:00", "2023-05-01T00:00:00Z"],
)
def test_iso_datetime_is_exact_utc_datetime(monkeypatch, raw):
    settings = _load(monkeypatch, raw)

    assert settings.start_date == datetime(2023, 5, 1, tzinfo=timezone.utc)


def test_iso_duration_is_relative_to_now(monkeypatch):
    settings = _load(monkeypatch, "P30D")

    _assert_close_to_now(settings.start_date, timedelta(days=30))


@pytest.mark.parametrize("raw", ["2022/01/01", "20220101"])
def test_legacy_format_is_accepted_with_deprecation_warning(monkeypatch, caplog, raw):
    # Also proves the compatibility validator runs before the SDK one: the SDK
    # validator alone rejects these strings.
    with caplog.at_level(logging.WARNING, logger=SETTINGS_LOGGER):
        settings = _load(monkeypatch, raw)

    assert settings.start_date == datetime(2022, 1, 1, tzinfo=timezone.utc)
    warnings = [r for r in caplog.records if r.name == SETTINGS_LOGGER]
    assert len(warnings) == 1
    assert "Deprecated" in warnings[0].getMessage()


def test_iso_values_do_not_emit_deprecation_warning(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger=SETTINGS_LOGGER):
        _load(monkeypatch, "2023-05-01")
        _load(monkeypatch, "P30D")
        _load(monkeypatch)

    assert [r for r in caplog.records if r.name == SETTINGS_LOGGER] == []


def test_legacy_format_with_timezone_is_converted_to_utc(monkeypatch):
    settings = _load(monkeypatch, "2022/01/01 02:00:00 +02:00")

    assert settings.start_date == datetime(2022, 1, 1, tzinfo=timezone.utc)
    assert settings.start_date.utcoffset() == timedelta(0)


@pytest.mark.parametrize("raw", ["not-a-date", "2023-02-31", "P"])
def test_garbage_start_date_is_rejected(monkeypatch, raw):
    with pytest.raises(ValidationError) as exc_info:
        _load(monkeypatch, raw)

    assert "start_date" in str(exc_info.value)


def _connector(start_date: datetime) -> SekoiaConnector:
    config = MagicMock()
    config.sekoia.start_date = start_date
    return SekoiaConnector(config, MagicMock())


def _decode(cursor: str) -> str:
    return base64.b64decode(cursor).decode("utf-8")


def test_first_cursor_is_utc_with_z_suffix():
    connector = _connector(datetime(2023, 5, 1, 12, 30, 15, tzinfo=timezone.utc))

    cursor = _decode(connector.generate_first_cursor())

    assert cursor == "2023-05-01T12:30:15Z"
    assert "+00:00" not in cursor


def test_first_cursor_is_truncated_to_the_second():
    connector = _connector(
        datetime(2023, 5, 1, 12, 30, 15, 123456, tzinfo=timezone.utc)
    )

    assert _decode(connector.generate_first_cursor()) == "2023-05-01T12:30:15Z"


def test_first_cursor_converts_non_utc_datetime_to_utc():
    connector = _connector(
        datetime(2023, 5, 1, 2, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    )

    assert _decode(connector.generate_first_cursor()) == "2023-05-01T00:00:00Z"


@pytest.mark.parametrize("tz", ["Asia/Tokyo", "America/Los_Angeles"])
def test_first_cursor_treats_naive_datetime_as_utc(monkeypatch, tz):
    # A naive datetime must not depend on the timezone of the host
    monkeypatch.setenv("TZ", tz)
    time.tzset()
    try:
        connector = _connector(datetime(2023, 5, 1))

        assert _decode(connector.generate_first_cursor()) == "2023-05-01T00:00:00Z"
    finally:
        monkeypatch.undo()
        time.tzset()


def test_first_cursor_from_default_setting(monkeypatch):
    connector = _connector(_load(monkeypatch).start_date)

    cursor = _decode(connector.generate_first_cursor())

    assert cursor.endswith("Z")
    assert "+00:00" not in cursor
    parsed = datetime.fromisoformat(cursor.removesuffix("Z")).replace(
        tzinfo=timezone.utc
    )
    _assert_close_to_now(parsed, timedelta(days=90))


def _build(start_date) -> _ConfigLoaderSekoia:
    """Build the settings with a value as a YAML or env source would provide it."""
    return _ConfigLoaderSekoia(api_key="test-api-key", start_date=start_date)


@pytest.mark.parametrize("tz", ["Asia/Tokyo", "America/Los_Angeles"])
@pytest.mark.parametrize(
    "raw",
    [date(2023, 5, 1), datetime(2023, 5, 1)],
    ids=["unquoted_yaml_date", "naive_datetime"],
)
def test_yaml_date_and_naive_datetime_are_utc(monkeypatch, raw, tz):
    monkeypatch.setenv("TZ", tz)
    time.tzset()
    try:
        settings = _build(raw)

        assert settings.start_date == datetime(2023, 5, 1, tzinfo=timezone.utc)
    finally:
        monkeypatch.undo()
        time.tzset()


def test_aware_datetime_is_converted_to_utc():
    settings = _build(datetime(2023, 5, 1, 2, tzinfo=timezone(timedelta(hours=2))))

    assert settings.start_date == datetime(2023, 5, 1, tzinfo=timezone.utc)
    assert settings.start_date.utcoffset() == timedelta(0)


def test_unquoted_yaml_integer_is_a_legacy_date_not_a_unix_timestamp(caplog):
    with caplog.at_level(logging.WARNING, logger=SETTINGS_LOGGER):
        settings = _build(20220101)

    assert settings.start_date == datetime(2022, 1, 1, tzinfo=timezone.utc)
    assert len([r for r in caplog.records if r.name == SETTINGS_LOGGER]) == 1


def test_boolean_start_date_is_rejected():
    with pytest.raises(ValidationError):
        _build(True)


@pytest.mark.parametrize(
    ("raw", "expected_delta"),
    [(" P90D", timedelta(days=90)), ("P30D ", timedelta(days=30))],
)
def test_surrounding_whitespace_is_ignored(monkeypatch, caplog, raw, expected_delta):
    with caplog.at_level(logging.WARNING, logger=SETTINGS_LOGGER):
        settings = _load(monkeypatch, raw)

    _assert_close_to_now(settings.start_date, expected_delta)
    assert [r for r in caplog.records if r.name == SETTINGS_LOGGER] == []


def test_iso_date_with_whitespace_has_no_false_deprecation_warning(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger=SETTINGS_LOGGER):
        settings = _load(monkeypatch, "2023-05-01 ")

    assert settings.start_date == datetime(2023, 5, 1, tzinfo=timezone.utc)
    assert [r for r in caplog.records if r.name == SETTINGS_LOGGER] == []


def test_deprecation_warning_mentions_missing_parts_come_from_current_date(
    monkeypatch, caplog
):
    with caplog.at_level(logging.WARNING, logger=SETTINGS_LOGGER):
        _load(monkeypatch, "2022/01")

    assert "current date" in caplog.records[-1].getMessage()


def test_first_cursor_is_not_generated_when_state_has_a_cursor():
    connector = _connector(datetime(2023, 5, 1, tzinfo=timezone.utc))
    connector.helper.get_state.return_value = {"last_cursor": "state-cursor"}

    with patch.object(
        connector, "generate_first_cursor", wraps=connector.generate_first_cursor
    ) as generate, patch.object(connector, "_run", return_value="next") as run:
        connector.process_message()

    generate.assert_not_called()
    assert run.call_args.args[0] == "state-cursor"


def test_first_cursor_is_generated_when_state_has_no_cursor():
    connector = _connector(datetime(2023, 5, 1, tzinfo=timezone.utc))
    connector.helper.get_state.return_value = {}

    with patch.object(connector, "_run", return_value="next") as run:
        connector.process_message()

    assert _decode(run.call_args.args[0]) == "2023-05-01T00:00:00Z"


def test_out_of_range_legacy_date_is_a_validation_error_without_warning(
    monkeypatch, caplog
):
    # Not ISO for the SDK (year 9999 excluded), and the UTC conversion overflows
    with caplog.at_level(logging.WARNING, logger=SETTINGS_LOGGER):
        with pytest.raises(ValidationError) as exc_info:
            _load(monkeypatch, "9999-12-31T23:00:00-05:00")

    assert "start_date" in str(exc_info.value)
    assert [r for r in caplog.records if r.name == SETTINGS_LOGGER] == []


def test_out_of_range_aware_datetime_is_a_validation_error():
    # e.g. an unquoted YAML timestamp: the UTC conversion overflows
    extreme = datetime(9999, 12, 31, 23, tzinfo=timezone(timedelta(hours=-5)))

    with pytest.raises(ValidationError) as exc_info:
        _build(extreme)

    assert "start_date" in str(exc_info.value)
    assert "out of range" in str(exc_info.value)
