import pytest
import stix2
from connector.data_processors.nrd import NRDProcessor
from whoisfreaks_client.nrd_client import NRDRecord


@pytest.mark.parametrize(
    ("feed_name", "feed_type", "whois"),
    [
        ("nrd_gtld_with_whois", "gtld", True),
        ("nrd_cctld_with_whois", "cctld", True),
        ("nrd_gtld_without_whois", "gtld", False),
        ("nrd_cctld_without_whois", "cctld", False),
    ],
)
def test_nrd_feed_configuration(
    feed_name,
    feed_type,
    whois,
):
    processor = NRDProcessor(feed_name)

    assert processor.feed_name == feed_name
    assert processor.feed_type == feed_type
    assert processor.whois is whois


def test_invalid_nrd_feed():
    with pytest.raises(ValueError, match="Unsupported NRD feed"):
        NRDProcessor("invalid")


def test_nrd_to_stix_with_indicators():
    processor = NRDProcessor("nrd_gtld_with_whois")

    record = NRDRecord(
        domain_name="Example.COM.",
        fields={
            "domain_name": "Example.COM.",
            "registrant_name": "Example",
            "create_date": "2026-08-11",
            "name_server_1": "ns1.example.com",
        },
    )

    objects = processor._to_stix(
        record,
        stix2.TLP_WHITE,
        create_indicators=True,
    )

    # Domain-Name + WHOIS Note + Indicator + based-on Relationship
    assert len(objects) == 4

    observable = objects[0]
    note = objects[1]
    indicator = objects[2]
    relationship = objects[3]

    assert observable.type == "domain-name"
    assert observable.value == "example.com"
    assert observable.x_whoisfreaks_registrant_name == "Example"
    assert observable.x_whoisfreaks_create_date == "2026-08-11"
    assert observable.x_whoisfreaks_name_server_1 == "ns1.example.com"
    assert not hasattr(observable, "x_whoisfreaks_domain_name")
    assert "example.com" in observable.x_opencti_description
    assert "nrd_gtld_with_whois" in observable.x_opencti_description
    # Description is a short summary; full columns live in the Note
    assert "registrant_name" not in observable.x_opencti_description
    assert "| Field | Value |" not in observable.x_opencti_description

    assert note.type == "note"
    assert "example.com" in note.content
    assert "| Field | Value |" in note.content
    assert "registrant_name" in note.content
    assert "create_date" in note.content
    assert "name_server_1" in note.content
    assert note.note_types == ["external"]
    assert observable.id in note.object_refs

    assert indicator.type == "indicator"
    assert indicator.name == "example.com"
    assert indicator.pattern == ("[domain-name:value = 'example.com']")
    assert indicator.pattern_type == "stix"

    assert relationship.type == "relationship"
    assert relationship.relationship_type == "based-on"
    assert relationship.source_ref == indicator.id
    assert relationship.target_ref == observable.id


def test_nrd_to_stix_observable_only():
    processor = NRDProcessor("nrd_gtld_with_whois")

    record = NRDRecord(
        domain_name="Example.COM.",
        fields={"domain_name": "Example.COM."},
    )

    objects = processor._to_stix(
        record,
        stix2.TLP_WHITE,
        create_indicators=False,
    )

    # Domain-Name + Note (domain_name column is present and non-empty)
    assert len(objects) == 2
    assert objects[0].type == "domain-name"
    assert objects[0].value == "example.com"
    assert objects[1].type == "note"


def test_nrd_to_stix_domains_only_feed_no_note():
    processor = NRDProcessor("nrd_gtld_without_whois")

    record = NRDRecord(
        domain_name="example.com",
        fields={"domain_name": "example.com"},
    )

    objects = processor._to_stix(
        record,
        stix2.TLP_WHITE,
        create_indicators=False,
    )

    assert len(objects) == 1
    assert objects[0].type == "domain-name"
    assert objects[0].value == "example.com"


def test_nrd_whois_custom_properties_include_all_non_empty_columns():
    processor = NRDProcessor("nrd_gtld_with_whois")

    record = NRDRecord(
        domain_name="example.com",
        fields={
            "domain_name": "example.com",
            "create_date": "2026-08-11",
            "domain_registrar_name": "Example Registrar",
            "registrant_country_code": "US",
            "empty_field": "",
        },
    )

    properties = processor._whois_custom_properties(record)

    assert properties == {
        "x_whoisfreaks_create_date": "2026-08-11",
        "x_whoisfreaks_domain_registrar_name": "Example Registrar",
        "x_whoisfreaks_registrant_country_code": "US",
    }


def test_nrd_ordered_whois_items_preserves_extra_columns():
    processor = NRDProcessor("nrd_gtld_with_whois")

    record = NRDRecord(
        domain_name="example.com",
        fields={
            "domain_name": "example.com",
            "create_date": "2026-08-11",
            "custom_extra_column": "extra-value",
            "empty_field": "",
        },
    )

    items = processor._ordered_whois_items(record)
    columns = [c for c, _ in items]
    assert "domain_name" in columns
    assert "create_date" in columns
    assert "custom_extra_column" in columns
    assert "empty_field" not in columns  # empty columns are dropped
    assert dict(items)["custom_extra_column"] == "extra-value"


def test_nrd_tlp_marking():
    processor = NRDProcessor("nrd_gtld_with_whois")

    clear = processor._get_tlp_marking("clear")
    assert clear.x_opencti_definition == "TLP:CLEAR"
    assert processor._get_tlp_marking("white") == stix2.TLP_WHITE
    assert processor._get_tlp_marking("green") == stix2.TLP_GREEN
    assert processor._get_tlp_marking("amber") == stix2.TLP_AMBER
    strict = processor._get_tlp_marking("amber+strict")
    assert strict.id != stix2.TLP_AMBER.id
    assert strict.x_opencti_definition == "TLP:AMBER+STRICT"
    assert processor._get_tlp_marking("red") == stix2.TLP_RED


def test_nrd_transform_splits_bundles_at_object_limit(monkeypatch):
    monkeypatch.setattr("connector.data_processors.nrd._MAX_BUNDLE_OBJECTS", 4)
    processor = NRDProcessor("nrd_gtld_without_whois")
    processor._author = stix2.Identity(
        id="identity--11111111-1111-4111-8111-111111111111",
        name="WhoisFreaks",
        identity_class="organization",
    )

    class FakeConfig:
        class WhoisFreaks:
            tlp_level = "clear"
            create_indicators_for_nrd = False

        whoisfreaks = WhoisFreaks()

    processor.settings = FakeConfig()
    records = [
        NRDRecord(domain_name=f"domain-{index}.example", fields={})
        for index in range(3)
    ]

    bundles = list(processor.transform(iter([records])))

    assert [len(bundle) for bundle in bundles] == [4, 3]
    for bundle in bundles:
        assert any(obj.type == "marking-definition" for obj in bundle)
