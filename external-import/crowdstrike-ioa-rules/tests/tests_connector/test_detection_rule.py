from datetime import datetime, timedelta, timezone

import pytest
from connector.detection_rule import DetectionRule, normalize_level, parse_timestamp
from pydantic import ValidationError


@pytest.mark.parametrize(
    "value,expected",
    [
        ("High", "high"),
        (" informational ", "informational"),
        ("Info", "informational"),
        ("moderate", "medium"),
        ("CRITICAL", "critical"),
        ("unknown", None),
        ("", None),
        (None, None),
        (3, None),
    ],
)
def test_normalize_level(value, expected):
    assert normalize_level(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-01-02T03:04:05Z", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        (
            "2026-01-02T03:04:05.1234567Z",
            datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc),
        ),
        (
            "2026-01-02T03:04:05.123456789+02:00",
            datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone(timedelta(hours=2))),
        ),
        ("2026-01-02T03:04:05", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        (1767323045, datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        (
            datetime(2026, 1, 2, 3, 4, 5),
            datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        ),
        (None, None),
        ("", None),
    ],
)
def test_parse_timestamp(value, expected):
    assert parse_timestamp(value) == expected


def test_parse_timestamp_rejects_garbage():
    with pytest.raises(ValueError):
        parse_timestamp("yesterday")


def test_detection_rule_requires_a_pattern():
    with pytest.raises(ValidationError):
        DetectionRule(
            key="k",
            external_id="k",
            name="n",
            pattern="",
            pattern_type="kql",
            enabled=True,
        )
