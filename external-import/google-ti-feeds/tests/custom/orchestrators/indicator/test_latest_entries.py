"""Tests for the de-duplication of IOC delta package entries."""

from typing import Any

from connector.src.custom.orchestrators.indicator.orchestrator_indicator import (
    latest_entries,
)


def _entry(
    ioc_id: str, modified: int | None, marker: str, ioc_type: str = "domain"
) -> Any:
    attributes = {"marker": marker}
    if modified is not None:
        attributes["last_modification_date"] = modified
    return {"id": ioc_id, "type": ioc_type, "attributes": attributes}


def _markers(entries: list[dict[str, Any]]) -> list[str]:
    return [entry["attributes"]["marker"] for entry in entries]


def test_latest_entry_wins_whatever_the_order() -> None:
    """The entry with the latest modification date is kept."""
    # Given an IOC listed three times, the latest in the middle
    entries = [
        _entry("example.com", 100, "old"),
        _entry("example.com", 300, "latest"),
        _entry("example.com", 200, "older"),
    ]
    # When the package is de-duplicated
    # Then only the latest entry remains
    assert _markers(latest_entries(entries)) == ["latest"]  # noqa: S101


def test_later_entry_wins_on_equal_or_missing_dates() -> None:
    """On equal or missing dates, the later entry in the package is kept."""
    # Given IOCs listed twice with equal or missing dates
    entries = [
        _entry("a.com", 100, "first"),
        _entry("a.com", 100, "second"),
        _entry("b.com", None, "first-b"),
        _entry("b.com", None, "second-b"),
    ]
    # When the package is de-duplicated
    # Then the later entries remain, in first-seen order
    assert _markers(latest_entries(entries)) == ["second", "second-b"]  # noqa: S101


def test_distinct_iocs_are_kept() -> None:
    """IOCs with different IDs or types are all kept."""
    # Given distinct IOCs, two sharing an ID but not a type
    entries = [
        _entry("a.com", 100, "domain"),
        _entry("a.com", 100, "url", ioc_type="url"),
        _entry("b.com", 100, "other"),
    ]
    # When the package is de-duplicated
    # Then nothing is dropped
    assert _markers(latest_entries(entries)) == ["domain", "url", "other"]  # noqa: S101
