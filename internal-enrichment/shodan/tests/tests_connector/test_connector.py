import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.connector import ShodanConnector
from connectors_sdk.models import OrganizationAuthor


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
    serialized = [
        json.loads(o.serialize()) if hasattr(o, "serialize") else o for o in objs
    ]
    return json.dumps({"type": "bundle", "objects": serialized})


def _make_indicator_connector(
    *,
    import_search_results: bool = True,
    max_bundle_size_mb: int = 40,
    playbook: dict | None = None,
) -> ShodanConnector:
    conn = object.__new__(ShodanConnector)
    conn.config = SimpleNamespace(
        connector=SimpleNamespace(max_tlp="amber"),
        shodan=SimpleNamespace(
            default_score=50,
            import_search_results=import_search_results,
            max_bundle_size_mb=max_bundle_size_mb,
            create_note=True,
            use_isp_name_for_asn=False,
        ),
    )
    conn.default_score = 50
    conn.import_search_results = import_search_results
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


def test_indicator_search_stops_before_exceeding_max_bundle_size_mb_with_playbook_and_non_ascii_banners():
    previous_bundle = "P" * 600_000
    conn = _make_indicator_connector(
        max_bundle_size_mb=1,
        playbook={"playbook_id": "pb-1", "previous_bundle": previous_bundle},
    )
    conn.shodanAPI.search_cursor.return_value = [
        {"ip_str": f"10.0.1.{i}"} for i in range(1, 6)
    ]
    # Non-ASCII characters (each escapes to \uXXXX = 6 ASCII bytes in json.dumps)
    non_ascii_banner = "é☃" * 20_000
    conn.shodanAPI.host.side_effect = lambda ip: _sample_host_response(
        ip, banner_text=non_ascii_banner
    )
    payload = _indicator_payload()

    result = conn.process_message(payload)

    assert result == "Sent 1 STIX bundle(s) for import"
    assert 1 <= conn.shodanAPI.host.call_count < 5
    assert len(payload["stix_objects"]) == 1
    sent_bundle_str = conn.helper.send_stix2_bundle.call_args.args[0]
    # Compute playbook wire payload size independently of ShodanConnector._request_size
    independent_wire_size = len(
        json.dumps(
            {"previous_bundle": previous_bundle, "bundle": sent_bundle_str}
        ).encode("utf-8")
    )
    assert len(json.dumps(sent_bundle_str).encode("utf-8")) + len(
        json.dumps(previous_bundle).encode("utf-8")
    ) <= (1 * 1024 * 1024)
    assert independent_wire_size <= 1 * 1024 * 1024 + 64
    sent_objects = json.loads(sent_bundle_str)["objects"]
    notes = [
        obj
        for obj in sent_objects
        if obj["type"] == "note" and obj.get("abstract") == "Shodan Summary Information"
    ]
    assert "bundle size limit of 1 MiB reached" in notes[0]["content"]


def test_indicator_search_without_playbook_caps_raw_utf8_bundle_size():
    conn = _make_indicator_connector(max_bundle_size_mb=1, playbook=None)
    conn.shodanAPI.search_cursor.return_value = [
        {"ip_str": f"10.0.3.{i}"} for i in range(1, 6)
    ]
    conn.shodanAPI.host.side_effect = lambda ip: _sample_host_response(
        ip, banner_text="A" * 350_000
    )

    conn.process_message(_indicator_payload())

    assert 1 <= conn.shodanAPI.host.call_count < 5
    sent_bundle_str = conn.helper.send_stix2_bundle.call_args.args[0]
    assert len(sent_bundle_str.encode("utf-8")) <= 1 * 1024 * 1024
    notes = [
        obj
        for obj in json.loads(sent_bundle_str)["objects"]
        if obj["type"] == "note" and obj.get("abstract") == "Shodan Summary Information"
    ]
    assert "bundle size limit of 1 MiB reached" in notes[0]["content"]


def test_oversized_first_host_is_excluded_cleanly_with_truncation_summary():
    conn = _make_indicator_connector(max_bundle_size_mb=1, playbook=None)
    conn.shodanAPI.search_cursor.return_value = [{"ip_str": "10.0.2.1"}]
    conn.shodanAPI.host.return_value = _sample_host_response(
        "10.0.2.1", banner_text="Z" * 1_100_000
    )

    result = conn.process_message(_indicator_payload())

    assert result == "Sent 1 STIX bundle(s) for import"
    sent_objects = json.loads(conn.helper.send_stix2_bundle.call_args.args[0])[
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


def test_eviction_loop_pops_trailing_host_when_final_bundle_exceeds_limit():
    conn = _make_indicator_connector(max_bundle_size_mb=1, playbook=None)
    conn.shodanAPI.search_cursor.return_value = [
        {"ip_str": "10.0.4.1"},
        {"ip_str": "10.0.4.2"},
    ]
    conn.shodanAPI.host.side_effect = lambda ip: _sample_host_response(
        ip, banner_text="B" * 520_000
    )
    conn.helper.stix2_create_bundle.side_effect = lambda objs: _serialize_bundle_objs(
        objs
    ) + (" " * 40_000)

    conn.process_message(_indicator_payload())

    sent_bundle_str = conn.helper.send_stix2_bundle.call_args.args[0]
    assert len(sent_bundle_str.encode("utf-8")) <= 1 * 1024 * 1024
    sent_ips = [
        obj["value"]
        for obj in json.loads(sent_bundle_str.strip())["objects"]
        if obj["type"] == "ipv4-addr"
    ]
    assert sent_ips == ["10.0.4.1"]


def test_base_bundle_exceeding_max_bundle_size_mb_raises_value_error():
    conn = _make_indicator_connector(
        max_bundle_size_mb=1,
        playbook={"playbook_id": "pb-1", "previous_bundle": "X" * 1_200_000},
    )
    conn.import_search_results = False

    with pytest.raises(
        ValueError, match="Base Shodan STIX bundle exceeds SHODAN_MAX_BUNDLE_SIZE_MB"
    ):
        conn.process_message(_indicator_payload())


def test_failed_host_lookup_logs_warning_and_continues():
    conn = _make_indicator_connector(max_bundle_size_mb=40, playbook=None)
    conn.shodanAPI.search_cursor.return_value = [
        {"ip_str": "10.0.5.1"},
        {"ip_str": "10.0.5.2"},
    ]

    def host_side_effect(ip):
        if ip == "10.0.5.1":
            raise RuntimeError("rate limited")
        return _sample_host_response(ip)

    conn.shodanAPI.host.side_effect = host_side_effect

    conn.process_message(_indicator_payload())

    conn.helper.connector_logger.warning.assert_called_once_with(
        "Shodan host lookup failed, skipping host",
        {"ip": "10.0.5.1", "error": "rate limited"},
    )
    sent_objects = json.loads(conn.helper.send_stix2_bundle.call_args.args[0])[
        "objects"
    ]
    sent_ips = [obj["value"] for obj in sent_objects if obj["type"] == "ipv4-addr"]
    assert sent_ips == ["10.0.5.2"]


def test_indicator_without_import_search_results_keeps_indicator_and_summary_note():
    conn = _make_indicator_connector(import_search_results=False)
    payload = _indicator_payload()

    conn.process_message(payload)

    conn.shodanAPI.search_cursor.assert_not_called()
    sent_objects = json.loads(conn.helper.send_stix2_bundle.call_args.args[0])[
        "objects"
    ]
    sent_types = {obj["type"] for obj in sent_objects}
    assert "indicator" in sent_types
    assert "note" in sent_types
    assert "ipv4-addr" not in sent_types


def test_process_message_does_not_resend_original_bundle_when_send_stix2_bundle_fails():
    conn = _make_indicator_connector(playbook={"playbook_id": "pb-1"})
    conn.shodanAPI.search_cursor.return_value = [{"ip_str": "10.0.0.1"}]
    conn.shodanAPI.host.return_value = _sample_host_response("10.0.0.1")
    conn.helper.send_stix2_bundle.side_effect = RuntimeError("Request body too large")

    with pytest.raises(RuntimeError, match="Request body too large"):
        conn.process_message(_indicator_payload())

    assert conn.helper.send_stix2_bundle.call_count == 1
