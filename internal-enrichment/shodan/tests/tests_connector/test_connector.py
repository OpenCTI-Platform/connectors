from types import SimpleNamespace

import pytest
from connector.connector import ShodanConnector


@pytest.fixture
def connector() -> ShodanConnector:
    """Build a connector without running `__init__` (no OpenCTI or Shodan call)."""
    connector = object.__new__(ShodanConnector)
    connector.config = SimpleNamespace(connector=SimpleNamespace(max_tlp="amber"))
    return connector


@pytest.mark.parametrize(
    "object_marking",
    [[], [{"definition_type": "TLP", "definition": "TLP:GREEN"}]],
)
def test_extract_and_check_markings_accepts_entity_within_max_tlp(
    connector, object_marking
):
    connector._extract_and_check_markings({"objectMarking": object_marking})


@pytest.mark.parametrize(
    "object_marking",
    [
        [{"definition_type": "TLP", "definition": "TLP:RED"}],
        # Every TLP of the entity is checked, not only the last one
        [
            {"definition_type": "TLP", "definition": "TLP:RED"},
            {"definition_type": "TLP", "definition": "TLP:GREEN"},
        ],
    ],
)
def test_extract_and_check_markings_refuses_entity_above_max_tlp(
    connector, object_marking
):
    with pytest.raises(ValueError, match="greater than MAX TLP"):
        connector._extract_and_check_markings({"objectMarking": object_marking})


def _sample_host_response(ip_str: str, banner_text: str = "X" * 64) -> dict:
    return {
        "ip_str": ip_str,
        "isp": f"ISP-{ip_str}",
        "os": "Linux",
        "org": "Example Org",
        "domains": ["example.com"],
        "hostnames": ["host.example.com"],
        "asn": "AS64500",
        "city": "Paris",
        "country_name": "France",
        "country_code": "FR",
        "region_code": "IDF",
        "latitude": 48.8534,
        "longitude": 2.3488,
        "tags": ["cloud"],
        "vulns": [],
        "data": [{"port": 443, "data": banner_text}],
    }


def _serialize_bundle_objs(objs: list) -> str:
    import json as _json

    serialized = [
        _json.loads(o.serialize()) if hasattr(o, "serialize") else o for o in objs
    ]
    return _json.dumps({"type": "bundle", "objects": serialized})


def _make_indicator_connector(
    *,
    import_search_results: bool = True,
    max_search_results: int = 100,
    max_bundle_size_mb: int = 32,
    playbook: dict | None = None,
) -> ShodanConnector:
    from unittest.mock import MagicMock

    from connectors_sdk.models import OrganizationAuthor

    conn = object.__new__(ShodanConnector)
    conn.config = SimpleNamespace(
        connector=SimpleNamespace(max_tlp="amber"),
        shodan=SimpleNamespace(
            default_score=50,
            import_search_results=import_search_results,
            max_search_results=max_search_results,
            max_bundle_size_mb=max_bundle_size_mb,
            create_note=True,
            use_isp_name_for_asn=False,
        ),
    )
    conn.default_score = 50
    conn.import_search_results = import_search_results
    conn.max_search_results = max_search_results
    conn.max_bundle_size_mb = max_bundle_size_mb
    conn.create_note = True
    conn.use_isp_name_for_asn = False
    conn.shodan_identity = OrganizationAuthor(
        name="Shodan",
        description="Connector Enrichment Shodan",
    )

    helper = MagicMock()
    helper.playbook = playbook
    helper.get_attribute_in_extension.return_value = 50
    helper.api.stix_core_relationship.list.return_value = []
    helper.stix2_create_bundle.side_effect = _serialize_bundle_objs
    helper.send_stix2_bundle.return_value = ["bundle-1"]
    conn.helper = helper
    conn.shodanAPI = MagicMock()
    conn.shodanAPI.count.return_value = {
        "total": 1500,
        "facets": {
            "org": [],
            "domain": [],
            "port": [],
            "asn": [],
            "country": [],
        },
    }
    return conn


def _indicator_payload() -> dict:
    indicator = {
        "id": "indicator--11111111-2222-4333-8444-555555555555",
        "type": "indicator",
        "pattern_type": "shodan",
        "pattern": "http.title:test",
        "x_opencti_score": 50,
    }
    return {
        "stix_objects": [indicator],
        "stix_entity": indicator,
        "enrichment_entity": {
            "id": indicator["id"],
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:CLEAR"}],
        },
    }


def test_indicator_search_caps_hosts_at_max_search_results_and_preserves_original_bundle():
    import json as _json

    conn = _make_indicator_connector(max_search_results=3)
    conn.shodanAPI.search_cursor.return_value = (
        {"ip_str": f"10.0.0.{i}"} for i in range(1, 20)
    )
    conn.shodanAPI.host.side_effect = lambda ip: _sample_host_response(ip)
    payload = _indicator_payload()

    result = conn.process_message(payload)

    assert result == "Sent 1 STIX bundle(s) for import"
    assert conn.shodanAPI.host.call_count == 3
    assert len(payload["stix_objects"]) == 1
    sent_bundle = _json.loads(conn.helper.send_stix2_bundle.call_args.args[0])
    sent_objects = sent_bundle["objects"]
    sent_ids = {obj["id"] for obj in sent_objects}
    assert payload["stix_entity"]["id"] in sent_ids
    notes = [
        obj
        for obj in sent_objects
        if obj["type"] == "note" and obj.get("abstract") == "Shodan Summary Information"
    ]
    assert len(notes) == 1
    assert "Imported 3 of 1500 matching hosts" in notes[0]["content"]
    conn.helper.connector_logger.warning.assert_called_once()


def test_indicator_search_stops_before_exceeding_max_bundle_size_mb_including_playbook_overhead():
    import json as _json

    # Playbook already carries a 600 KB previous_bundle and banners have JSON-escaped quotes/newlines
    conn = _make_indicator_connector(
        max_search_results=0,
        max_bundle_size_mb=1,
        playbook={"playbook_id": "pb-1", "previous_bundle": "P" * 600_000},
    )
    conn.shodanAPI.search_cursor.return_value = [
        {"ip_str": f"10.0.1.{i}"} for i in range(1, 6)
    ]
    escaped_banner = '"line"\n' * 20_000
    conn.shodanAPI.host.side_effect = lambda ip: _sample_host_response(
        ip, banner_text=escaped_banner
    )

    conn.process_message(_indicator_payload())

    assert 1 <= conn.shodanAPI.host.call_count < 5
    sent_bundle_str = conn.helper.send_stix2_bundle.call_args.args[0]
    assert conn._actual_transport_bytes(sent_bundle_str) <= 1 * 1024 * 1024
    sent_objects = _json.loads(sent_bundle_str)["objects"]
    notes = [
        obj
        for obj in sent_objects
        if obj["type"] == "note" and obj.get("abstract") == "Shodan Summary Information"
    ]
    assert "max_bundle_size_mb (1 MiB)" in notes[0]["content"]


def test_oversized_first_host_is_excluded_cleanly_with_truncation_summary():
    import json as _json

    conn = _make_indicator_connector(max_search_results=0, max_bundle_size_mb=1)
    conn.shodanAPI.search_cursor.return_value = [{"ip_str": "10.0.2.1"}]
    # Single host banner > 1 MiB alone
    conn.shodanAPI.host.return_value = _sample_host_response(
        "10.0.2.1", banner_text="Z" * 1_100_000
    )

    result = conn.process_message(_indicator_payload())

    assert result == "Sent 1 STIX bundle(s) for import"
    sent_objects = _json.loads(conn.helper.send_stix2_bundle.call_args.args[0])[
        "objects"
    ]
    assert not any(obj["type"] == "ipv4-addr" for obj in sent_objects)
    notes = [
        obj
        for obj in sent_objects
        if obj["type"] == "note" and obj.get("abstract") == "Shodan Summary Information"
    ]
    assert len(notes) == 1
    assert "Imported 0 of 1500 matching hosts" in notes[0]["content"]


def test_indicator_without_import_search_results_keeps_indicator_and_summary_note():
    import json as _json

    conn = _make_indicator_connector(import_search_results=False)
    payload = _indicator_payload()

    conn.process_message(payload)

    conn.shodanAPI.search_cursor.assert_not_called()
    sent_objects = _json.loads(conn.helper.send_stix2_bundle.call_args.args[0])[
        "objects"
    ]
    sent_types = {obj["type"] for obj in sent_objects}
    assert "indicator" in sent_types
    assert "note" in sent_types
    assert "ipv4-addr" not in sent_types


def test_process_message_does_not_resend_original_bundle_when_send_stix2_bundle_fails():
    conn = _make_indicator_connector(
        max_search_results=1, playbook={"playbook_id": "pb-1"}
    )
    conn.shodanAPI.search_cursor.return_value = [{"ip_str": "10.0.0.1"}]
    conn.shodanAPI.host.return_value = _sample_host_response("10.0.0.1")
    conn.helper.send_stix2_bundle.side_effect = RuntimeError("Request body too large")

    with pytest.raises(RuntimeError, match="Request body too large"):
        conn.process_message(_indicator_payload())

    assert conn.helper.send_stix2_bundle.call_count == 1
