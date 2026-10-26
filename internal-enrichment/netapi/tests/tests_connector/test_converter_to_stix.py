"""Tests for the note and the in-place enrichment of the observable."""

import copy
from datetime import datetime, timezone

from connector.converter_to_stix import (
    EPOCH_ANCHOR,
    OWN_LABEL,
    ConverterToStix,
    ObservableNote,
    stable_timestamp,
)
from connectors_sdk.models import TLPMarking
from mock_responses import (
    CHECK_LISTED_NOW,
    CHECK_LISTED_PAST,
    CHECK_LISTED_VIA_DOMAIN,
    RANK_IN_TOP_1M,
    RANK_NOT_IN_TOP_1M,
)

DOMAIN_ID = "domain-name--11111111-1111-4111-8111-111111111111"
IP_ID = "ipv4-addr--22222222-2222-4222-8222-222222222222"


def make_converter() -> ConverterToStix:
    return ConverterToStix(author=ConverterToStix.make_author())


def test_author_is_a_deterministic_organization():
    author = make_converter().author.to_stix2_object()
    again = make_converter().author.to_stix2_object()

    assert author["type"] == "identity"
    assert author["name"] == "NetAPI"
    assert author["identity_class"] == "organization"
    assert author["id"] == again["id"]


def test_note_id_and_created_derive_from_the_observable():
    converter = make_converter()
    markings = [TLPMarking(level="clear")]

    first = converter.build_note(
        DOMAIN_ID, "000359.xyz", CHECK_LISTED_NOW, RANK_NOT_IN_TOP_1M, markings
    ).to_stix2_object()
    changed = copy.deepcopy(CHECK_LISTED_NOW)
    changed["last_seen"] = "2026-10-27 01:05:00 UTC"
    second = converter.build_note(
        DOMAIN_ID, "000359.xyz", changed, RANK_NOT_IN_TOP_1M, markings
    ).to_stix2_object()

    assert first["id"] == second["id"] == ObservableNote.stable_id(DOMAIN_ID)
    assert first["created"] == second["created"] == EPOCH_ANCHOR
    assert second["modified"] >= first["modified"]
    assert first["object_refs"] == [DOMAIN_ID]
    assert first["created_by_ref"] == converter.author.id
    assert first["object_marking_refs"] == [markings[0].id]
    assert first["note_types"] == ["external"]
    assert first["labels"] == ["netapi"]


def test_note_created_is_the_observable_creation_time():
    note = make_converter().build_note(
        DOMAIN_ID,
        "000359.xyz",
        CHECK_LISTED_NOW,
        None,
        [TLPMarking(level="clear")],
        observed_at="2024-05-01T10:00:00.000Z",
    )
    assert note.to_stix2_object()["created"] == datetime(
        2024, 5, 1, 10, 0, tzinfo=timezone.utc
    )


def test_stable_timestamp_falls_back_to_the_epoch():
    assert stable_timestamp(None) == EPOCH_ANCHOR
    assert stable_timestamp("not a date") == EPOCH_ANCHOR
    assert stable_timestamp("2999-01-01T00:00:00Z") == EPOCH_ANCHOR
    naive = datetime(2024, 5, 1, 10, 0)
    assert stable_timestamp(naive) == naive.replace(tzinfo=timezone.utc)


def test_note_of_a_current_listing_names_feed_registrar_and_rank():
    content = (
        make_converter()
        .build_note(
            DOMAIN_ID,
            "000359.xyz",
            CHECK_LISTED_NOW,
            RANK_IN_TOP_1M,
            [TLPMarking(level="clear")],
        )
        .to_stix2_object()["content"]
    )

    assert "**Status:** listed now" in content
    assert "| Observable | 000359.xyz |" in content
    assert "Matched entry" not in content
    assert "| First seen | 2023-02-25 |" in content
    assert "| Last seen | 2026-10-26 01:05:27 UTC |" in content
    assert "| Reported by | blackbook |" in content
    assert "| Registrar | [Alibaba Cloud](https://netapi.com/whois-" in content
    assert "| Top 1M rank | #11 (snapshot of 2026-10-26) |" in content
    assert "[current list](https://netapi.com/api2/?method=compromised" in content


def test_note_of_a_hostname_names_the_matched_registered_domain():
    content = (
        make_converter()
        .build_note(
            DOMAIN_ID,
            "www.000359.xyz",
            CHECK_LISTED_VIA_DOMAIN,
            RANK_NOT_IN_TOP_1M,
            [TLPMarking(level="clear")],
        )
        .to_stix2_object()["content"]
    )

    assert "| Matched entry | 000359.xyz (the registered domain) |" in content
    assert "| Top 1M rank | not in the NetAPI Top 1M |" in content


def test_note_of_a_past_listing_has_no_registrar_and_no_rank():
    note = make_converter().build_note(
        IP_ID, "1.1.1.1", CHECK_LISTED_PAST, None, [TLPMarking(level="clear")]
    )
    content = note.to_stix2_object()["content"]

    assert note.abstract == "NetAPI - listed in the compromised feed in the past"
    assert "**Status:** listed in the past (last seen 2026-06-17)" in content
    assert "Registrar" not in content
    assert "Top 1M" not in content
    assert "| Reported by | urlhaus.abuse.ch |" in content


def test_table_cells_are_flattened_and_escaped():
    check = copy.deepcopy(CHECK_LISTED_NOW)
    check["block_reason"] = "a|b\nc\\d"
    content = (
        make_converter()
        .build_note(DOMAIN_ID, "000359.xyz", check, None, [TLPMarking(level="clear")])
        .to_stix2_object()["content"]
    )
    assert "| Reported by | a\\|b c\\\\d |" in content


def test_current_listing_adds_the_label_reference_and_score():
    entity = {
        "type": "domain-name",
        "id": DOMAIN_ID,
        "value": "000359.xyz",
        "x_opencti_labels": ["analyst-tag"],
        "external_references": [
            {"source_name": "Analyst", "url": "https://a.example"},
            {"source_name": "Analyst", "url": "https://a.example"},
            {"source_name": "NetAPI", "url": "https://old.example"},
        ],
    }

    enriched = make_converter().enrich_observable(entity, CHECK_LISTED_NOW, 80)

    assert enriched["x_opencti_score"] == 80
    assert enriched["x_opencti_labels"] == ["analyst-tag", OWN_LABEL]
    assert "labels" not in enriched
    assert "external_references" not in enriched
    assert enriched["x_opencti_external_references"] == [
        {"source_name": "Analyst", "url": "https://a.example"},
        {
            "source_name": "NetAPI",
            "url": "https://netapi.com/compromised-urls/",
            "description": (
                "NetAPI compromised feed: listed now (seen in the compromised feed "
                "within the last 24 hours)"
            ),
        },
    ]
    # the source entity is untouched
    assert entity["x_opencti_labels"] == ["analyst-tag"]
    assert "x_opencti_score" not in entity


def test_past_listing_removes_the_own_label_and_keeps_the_score():
    entity = {
        "type": "ipv4-addr",
        "id": IP_ID,
        "value": "1.1.1.1",
        "x_opencti_score": 60,
        "x_opencti_labels": ["NetAPI-Compromised", "keep-me"],
        "labels": ["legacy"],
    }

    enriched = make_converter().enrich_observable(entity, CHECK_LISTED_PAST, None)

    assert enriched["x_opencti_score"] == 60
    assert enriched["x_opencti_labels"] == ["keep-me", "legacy"]
    reference = enriched["x_opencti_external_references"][-1]
    assert reference["url"] == "https://netapi.com/compromised-ips/"
    assert reference["description"].startswith(
        "NetAPI compromised feed: listed in the past (last seen 2026-06-17)"
    )
