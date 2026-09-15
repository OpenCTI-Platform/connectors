from connector.connector import DOPPEL_ENTITY_TYPE_MAPPING
from connector.converter_to_stix import ConverterToStix


def _make_converter():
    return ConverterToStix(helper=None)


def test_marking_from_tlp():
    converter = _make_converter()
    assert converter.marking_from_tlp("TLP:AMBER+STRICT").level == "amber+strict"
    assert converter.marking_from_tlp("TLP:CLEAR").level == "clear"
    assert converter.marking_from_tlp(None) is None
    assert converter.marking_from_tlp("") is None
    assert converter.marking_from_tlp("UNKNOWN") is None


def test_entity_type_mapping():
    assert DOPPEL_ENTITY_TYPE_MAPPING["url"] == "url"
    assert DOPPEL_ENTITY_TYPE_MAPPING["domain-name"] == "domain"


def test_build_external_reference():
    converter = _make_converter()
    alert = {
        "id": "FLG-38",
        "doppel_link": "https://app.doppel.com/alerts/FLG-38",
        "entity": "http://filigran-test-phishing.com",
    }

    external_reference = converter.build_external_reference(alert)

    assert external_reference.source_name == "Doppel Alert"
    assert external_reference.url == "https://app.doppel.com/alerts/FLG-38"
    assert external_reference.external_id == "FLG-38"


def test_build_url_observable_carries_external_reference():
    converter = _make_converter()
    alert = {"id": "FLG-38", "doppel_link": "https://app.doppel.com/alerts/FLG-38"}
    external_reference = converter.build_external_reference(alert)

    observable = converter.build_observable(
        observable_type="url",
        value="http://filigran-test-phishing.com",
        external_reference=external_reference,
    )
    stix_object = observable.to_stix2_object()

    assert stix_object.type == "url"
    assert stix_object.value == "http://filigran-test-phishing.com"
    assert stix_object.x_opencti_external_references[0].url == alert["doppel_link"]


def test_build_domain_observable():
    converter = _make_converter()
    external_reference = converter.build_external_reference({"id": "FLG-1"})

    observable = converter.build_observable(
        observable_type="domain-name",
        value="filigran-test-phishing.com",
        external_reference=external_reference,
    )
    stix_object = observable.to_stix2_object()

    assert stix_object.type == "domain-name"
    assert stix_object.value == "filigran-test-phishing.com"


def test_build_note_mentions_alert_and_takedown():
    converter = _make_converter()
    alert = {
        "id": "FLG-38",
        "entity": "http://filigran-test-phishing.com",
        "archetype": "domains",
        "doppel_link": "https://app.doppel.com/alerts/FLG-38",
    }

    note = converter.build_note(
        observable_ref="url--4bf6eebd-e328-5b29-bd66-795f6f823f68",
        alert=alert,
        takedown_requested=True,
        takedown_comment="Confirmed phishing.",
    )

    assert "FLG-38" in note.content
    assert "Confirmed phishing." in note.content
    assert note.objects[0].id == "url--4bf6eebd-e328-5b29-bd66-795f6f823f68"
