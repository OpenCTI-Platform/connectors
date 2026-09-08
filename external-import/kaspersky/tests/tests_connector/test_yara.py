"""Tests for the Kaspersky YARA rule date parsing and update logic (issue #5941)."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from kaspersky.models import YaraRule
from kaspersky.utils.yara import YaraRuleUpdater


def _make_rule(last_modified, name="apt_rule"):
    return YaraRule(
        name=name,
        description="desc",
        report=None,
        last_modified=last_modified,
        rule="rule apt_rule { condition: true }",
    )


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2018-10-12T00:00:00Z", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("2018-10-12", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("12-10-2018", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("12.10.2018", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("2018.10.12", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("2018-10", datetime(2018, 10, 1, tzinfo=timezone.utc)),
        ("Oct 12 2018", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("Oct 12, 2018", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("October 12 2018", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("October 12, 2018", datetime(2018, 10, 12, tzinfo=timezone.utc)),
        ("['2020-03-05']", datetime(2020, 3, 5, tzinfo=timezone.utc)),
        ('["2020-03-05"]', datetime(2020, 3, 5, tzinfo=timezone.utc)),
    ],
)
def test_parse_last_modified_supported_formats(value, expected):
    rule = _make_rule(value)
    assert rule.last_modified == expected


@pytest.mark.parametrize("value", ["-", "", "   ", "not-a-date"])
def test_parse_last_modified_returns_none_for_invalid(value):
    rule = _make_rule(value)
    assert rule.last_modified is None


def test_parse_last_modified_accepts_none():
    rule = _make_rule(None)
    assert rule.last_modified is None


def _make_updater():
    helper = MagicMock()
    return YaraRuleUpdater(helper=helper)


def test_needs_updating_case_insensitive_name_and_newer_date():
    updater = _make_updater()
    current = _make_rule("2018-01-01", name="apt_Shadowpad_dropper")
    new = _make_rule("2020-01-01", name="apt_ShadowPad_dropper")

    assert updater._needs_updating(current, new) is True


def test_needs_updating_same_date_not_updated():
    updater = _make_updater()
    current = _make_rule("2020-01-01", name="apt_rule")
    new = _make_rule("2020-01-01", name="apt_rule")

    assert updater._needs_updating(current, new) is False


def test_needs_updating_none_date_not_updated():
    updater = _make_updater()
    current = _make_rule(None, name="apt_rule")
    new = _make_rule("2020-01-01", name="apt_rule")

    assert updater._needs_updating(current, new) is False


def test_needs_updating_different_names_not_updated():
    updater = _make_updater()
    current = _make_rule("2018-01-01", name="apt_one")
    new = _make_rule("2020-01-01", name="apt_two")

    assert updater._needs_updating(current, new) is False
