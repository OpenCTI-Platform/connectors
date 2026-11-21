from datetime import datetime, timezone

import pytest
from luminar_connector.expiration import is_expired, parse_stix_timestamp

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-10-20T12:00:00Z", datetime(2026, 10, 20, 12, tzinfo=timezone.utc)),
        ("2026-10-20T12:00:00z", datetime(2026, 10, 20, 12, tzinfo=timezone.utc)),
        (
            "2026-10-20T14:00:00+02:00",
            datetime(2026, 10, 20, 12, tzinfo=timezone.utc),
        ),
        ("2026-10-20T12:00:00", datetime(2026, 10, 20, 12, tzinfo=timezone.utc)),
        (
            "2026-10-20T12:00:00.123456789Z",
            datetime(2026, 10, 20, 12, 0, 0, 123456, tzinfo=timezone.utc),
        ),
    ],
)
def test_parse_stix_timestamp_valid(value, expected):
    assert parse_stix_timestamp(value) == expected


@pytest.mark.parametrize("value", [None, 123, "", "   ", "not-a-date"])
def test_parse_stix_timestamp_invalid(value):
    assert parse_stix_timestamp(value) is None


def test_only_indicators_expire():
    assert (
        is_expired({"type": "malware", "valid_until": "2000-01-01T00:00:00Z"}, NOW)
        is False
    )


def test_indicator_without_valid_until_never_expires():
    assert is_expired({"type": "indicator"}, NOW) is False


@pytest.mark.parametrize(
    "valid_until, expired",
    [
        ("2026-10-20T11:59:59Z", True),
        ("2026-10-20T12:00:00Z", True),  # valid strictly before valid_until
        ("2026-10-20T12:00:01Z", False),
    ],
)
def test_indicator_expiration_boundary(valid_until, expired):
    assert is_expired({"type": "indicator", "valid_until": valid_until}, NOW) is expired


def test_unparseable_valid_until_raises():
    with pytest.raises(ValueError):
        is_expired({"type": "indicator", "valid_until": "soon"}, NOW)
