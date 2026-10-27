# pragma: no cover # Do not compute coverage on test files
"""Offer tests for WhoisFreaksThreatFeedConverter."""

import json
from pathlib import Path
from typing import Any

import pytest
from connectors_sdk.converters import ConversionError
from connectors_sdk.converters.whoisfreaks import (
    WhoisFreaksThreatFeedConverter,
    WhoisFreaksThreatFeedRecord,
)
from connectors_sdk.models import (
    DomainName,
    Indicator,
    Note,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from freezegun import freeze_time

FIXTURES = Path(__file__).parent / "fixtures"


def load() -> dict[str, Any]:
    """Load the record fixture."""
    return json.loads(  # type: ignore[no-any-return]
        (FIXTURES / "threat_feed_record.json").read_text()
    )


@pytest.fixture
def converter() -> WhoisFreaksThreatFeedConverter:
    """Return a malware feed converter."""
    return WhoisFreaksThreatFeedConverter(
        author=OrganizationAuthor(name="WhoisFreaks"),
        markings=[TLPMarking(level="amber")],
        feed_type="malware",
    )


def test_unsupported_feed_type_is_rejected() -> None:
    """Test that only known feeds are accepted."""
    with pytest.raises(ValueError, match="Unsupported threat feed"):
        WhoisFreaksThreatFeedConverter(
            author=OrganizationAuthor(name="WhoisFreaks"),
            markings=[],
            feed_type="unknown",
        )


def test_record_conversion(converter: WhoisFreaksThreatFeedConverter) -> None:
    """Test the objects produced from a record."""
    # Given a record for an un-normalised domain
    record = WhoisFreaksThreatFeedRecord.model_validate(load())
    # When transforming it
    observable, indicator, relationship, note = converter.transform(record)
    # Then the domain is normalised and the indicator scored
    assert isinstance(observable, DomainName)
    assert isinstance(indicator, Indicator)
    assert isinstance(relationship, Relationship)
    assert isinstance(note, Note)
    assert observable.value == "example.com"
    assert observable.score == 80
    assert indicator.name == "example.com"
    assert indicator.pattern == "[domain-name:value = 'example.com']"
    assert indicator.score == 80
    assert indicator.valid_from == record.first_seen
    assert indicator.labels == [
        "whoisfreaks",
        "whoisfreaks-malware",
        "threat-type-malware",
    ]
    # And the indicator is based on the observable
    assert relationship.type == "based-on"
    assert relationship.source.id == indicator.id
    assert relationship.target.id == observable.id
    # And the note lists the columns and references both objects
    assert [obj.id for obj in note.objects or []] == [indicator.id, observable.id]
    assert "| `confidence` | 0.8 |" in note.content
    assert "| `No_of_threat_matched_pivots` | 3 |" in note.content


def test_note_uses_source_fields(converter: WhoisFreaksThreatFeedConverter) -> None:
    """Test that the source columns are rendered and empty ones dropped."""
    record = WhoisFreaksThreatFeedRecord.model_validate(
        {
            **load(),
            "source_fields": {
                "domain": "example.com",
                "response_detail": "a|b\nc",
                "empty_column": " ",
            },
        }
    )
    note = converter.transform(record)[3]

    assert isinstance(note, Note)
    assert "| `response_detail` | a\\|b c |" in note.content
    assert "empty_column" not in note.content


def test_note_is_stable_across_runs(converter: WhoisFreaksThreatFeedConverter) -> None:
    """Test that the note id does not depend on the conversion date."""
    record = WhoisFreaksThreatFeedRecord.model_validate(load())
    with freeze_time("2026-10-01"):
        first = converter.transform(record)[3].id
    with freeze_time("2026-10-02"):
        second = converter.transform(record)[3].id

    assert first == second


def test_naive_first_seen_raises_conversion_error(
    converter: WhoisFreaksThreatFeedConverter,
) -> None:
    """Test that a value rejected by the SDK models raises a ConversionError."""
    record = WhoisFreaksThreatFeedRecord.model_validate(
        {**load(), "first_seen": "2026-09-01T10:00:00"}
    )
    with pytest.raises(ConversionError, match="example.com"):
        converter.transform(record)


def test_author_and_markings(converter: WhoisFreaksThreatFeedConverter) -> None:
    """Test that every object references the author and markings."""
    record = WhoisFreaksThreatFeedRecord.model_validate(load())
    for obj in converter.transform(record):
        stix = obj.to_stix2_object()
        created_by = stix.get("created_by_ref") or stix.get("x_opencti_created_by_ref")
        assert created_by == converter.author.id
        assert stix["object_marking_refs"] == [converter.markings[0].id]
