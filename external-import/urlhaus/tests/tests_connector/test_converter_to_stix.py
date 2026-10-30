from unittest.mock import MagicMock

from external_import_connector.converter_to_stix import ConverterToStix

INDICATOR_ID = "indicator--4f1e2bb6-4f0f-5a3f-9d6e-1c6c3c0d6a01"
OBSERVABLE_ID = "url--6c8e3f1a-2b7d-5c4e-8f9a-0b1c2d3e4f50"
MALWARE = {
    "id": "malware-internal-id",
    "standard_id": "malware--2a6f1e0b-3c4d-5e6f-8a9b-0c1d2e3f4a5b",
    "entity_type": "Malware",
}


def _row(tags: str) -> list:
    return [
        "4047624",
        "2026-10-30 14:53:12",
        "http://42.234.72.133:38558/bin.sh",
        "online",
        "2026-10-30 14:53:12",
        "malware_download",
        tags,
        "https://urlhaus.abuse.ch/url/4047624/",
        "reporter",
    ]


def _converter(threat_cache: dict) -> tuple[ConverterToStix, MagicMock]:
    helper = MagicMock()
    helper.api.stix_domain_object.list.side_effect = lambda **kwargs: (
        [MALWARE] if kwargs["filters"]["filters"][0]["values"] == ["Mozi"] else []
    )
    return ConverterToStix(helper, MagicMock(), threat_cache), helper


def test_label_without_entity_is_queried_once_per_run():
    threat_cache = {}
    converter, helper = _converter(threat_cache)

    for _ in range(3):
        relations = converter.create_threat_relationship(
            _row("zip,Mozi"), INDICATOR_ID, OBSERVABLE_ID
        )
        assert len(relations) == 2
        assert all(r["target_ref"] == MALWARE["standard_id"] for r in relations)

    assert helper.api.stix_domain_object.list.call_count == 2
    assert threat_cache == {"zip": None, "Mozi": MALWARE}


def test_search_threat_by_name_returns_none_when_not_found():
    converter, _ = _converter({})

    assert converter._search_threat_by_name("zip") is None
    assert converter.threat_cache == {"zip": None}
