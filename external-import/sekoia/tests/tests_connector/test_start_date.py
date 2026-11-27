import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError
from src.connector.models import ConfigLoader
from src.connector.sekoia import SekoiaConnector


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


def test_first_cursor_from_default_setting(monkeypatch):
    connector = _connector(_load(monkeypatch).start_date)

    cursor = _decode(connector.generate_first_cursor())

    assert cursor.endswith("Z")
    assert "+00:00" not in cursor
    parsed = datetime.fromisoformat(cursor.removesuffix("Z")).replace(
        tzinfo=timezone.utc
    )
    _assert_close_to_now(parsed, timedelta(days=90))


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
