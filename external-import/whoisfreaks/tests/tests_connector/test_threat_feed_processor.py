from datetime import datetime, timezone

import pytest
import stix2
from connector.data_processors.threat_feed import ThreatFeedProcessor
from whoisfreaks_client.models import ThreatFeedRecord


def make_record(domain: str) -> ThreatFeedRecord:
    return ThreatFeedRecord(
        domain=domain,
        threat_type="malware",
        confidence_score=0.91,
        first_seen=datetime(
            2026,
            9,
            1,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026,
            9,
            2,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        No_of_threat_matched_pivots=4,
    )


def test_threat_feed_processor_creates_indicator_observable_and_relationship():
    processor = ThreatFeedProcessor("malware")
    record = make_record("Example.COM")

    objects = processor._to_stix(record, stix2.TLP_WHITE)

    # Domain-Name + Note + Indicator + based-on Relationship
    assert len(objects) == 4

    object_types = {obj.type for obj in objects}

    assert object_types == {
        "domain-name",
        "note",
        "indicator",
        "relationship",
    }

    domain = next(obj for obj in objects if obj.type == "domain-name")

    assert domain.value == "example.com"

    indicator = next(obj for obj in objects if obj.type == "indicator")
    note = next(obj for obj in objects if obj.type == "note")
    assert domain.id in note.object_refs
    assert indicator.id in note.object_refs
    assert "| Field | Value |" in note.content
    assert "example.com" in note.content
    assert "threat_type" in note.content
    assert "confidence" in note.content
    assert "first_seen" in note.content
    assert "last_seen" in note.content
    assert "No_of_threat_matched_pivots" in note.content
    assert note.note_types == ["external"]

    assert indicator.pattern == "[domain-name:value = 'example.com']"
    assert indicator.pattern_type == "stix"
    assert indicator.x_opencti_score == 91

    relationship = next(obj for obj in objects if obj.type == "relationship")

    assert relationship.relationship_type == "based-on"
    assert relationship.source_ref == indicator.id
    assert relationship.target_ref == domain.id

    for obj in objects:
        assert obj.object_marking_refs == [stix2.TLP_WHITE.id]


@pytest.mark.parametrize("same_timestamps", [False, True])
def test_indicator_has_no_valid_until(same_timestamps):
    """last_seen is observation metadata, never the indicator expiry."""
    processor = ThreatFeedProcessor("malware")
    record = make_record("example.com")
    if same_timestamps:
        record.last_seen = record.first_seen

    objects = processor._to_stix(record, stix2.TLP_WHITE)

    assert len(objects) == 4
    indicator = next(obj for obj in objects if obj.type == "indicator")
    assert indicator.valid_from == record.first_seen
    assert "valid_until" not in indicator
    assert indicator.x_whoisfreaks_last_seen == record.last_seen.isoformat()


def test_threat_feed_note_includes_every_source_column():
    processor = ThreatFeedProcessor("malware")
    record = make_record("example.com")
    record.source_fields = {
        "domain": "example.com",
        "threat_type": "malware",
        "response_detail": "additional source data",
        "empty_column": "",
    }

    note = next(
        obj for obj in processor._to_stix(record, stix2.TLP_WHITE) if obj.type == "note"
    )

    assert "response_detail" in note.content
    assert "additional source data" in note.content
    assert "empty_column" not in note.content  # empty columns are dropped


def test_threat_feed_clear_uses_clear_marking():
    marking = ThreatFeedProcessor._get_tlp_marking("clear")

    assert marking.x_opencti_definition == "TLP:CLEAR"


def test_transform_yields_pages_with_author():
    processor = ThreatFeedProcessor("malware")
    processor._author = stix2.Identity(
        id="identity--11111111-1111-4111-8111-111111111111",
        name="WhoisFreaks",
        identity_class="organization",
    )

    class FakeConfig:
        class WhoisFreaks:
            tlp_level = "clear"

        whoisfreaks = WhoisFreaks()

    processor.settings = FakeConfig()

    pages = [
        [make_record("one.com")],
        [make_record("two.com")],
    ]

    bundles = list(processor.transform(iter(pages)))

    assert len(bundles) == 2
    # author + TLP marking + domain + note + indicator + relationship
    assert len(bundles[0]) == 6
    assert any(obj.type == "identity" for obj in bundles[0])
    assert any(obj.type == "marking-definition" for obj in bundles[0])
    assert any(obj.type == "note" for obj in bundles[0])


def test_transform_does_not_crash_on_empty_page():
    processor = ThreatFeedProcessor("malware")
    processor._author = stix2.Identity(
        id="identity--11111111-1111-4111-8111-111111111111",
        name="WhoisFreaks",
        identity_class="organization",
    )

    class FakeConfig:
        class WhoisFreaks:
            tlp_level = "clear"

        whoisfreaks = WhoisFreaks()

    processor.settings = FakeConfig()

    bundles = list(processor.transform(iter([[]])))
    assert bundles == []


def test_transform_splits_bundles_at_object_limit(monkeypatch):
    monkeypatch.setattr(
        "connector.data_processors.threat_feed._MAX_BUNDLE_OBJECTS",
        6,
    )
    processor = ThreatFeedProcessor("malware")
    processor._author = stix2.Identity(
        id="identity--11111111-1111-4111-8111-111111111111",
        name="WhoisFreaks",
        identity_class="organization",
    )

    class FakeConfig:
        class WhoisFreaks:
            tlp_level = "clear"

        whoisfreaks = WhoisFreaks()

    processor.settings = FakeConfig()

    bundles = list(
        processor.transform(
            iter([[make_record("one.example"), make_record("two.example")]])
        )
    )

    assert [len(bundle) for bundle in bundles] == [6, 6]
    for bundle in bundles:
        assert any(obj.type == "marking-definition" for obj in bundle)
