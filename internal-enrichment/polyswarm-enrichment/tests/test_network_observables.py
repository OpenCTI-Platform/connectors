"""Tests for URL, domain and IP observable enrichment (lookup only).

Mock results follow the shapes measured against the live API on 2026-11-06:
``search_url`` yields URL-type scans whose ``json`` carries ``detections``
(benign/malicious/total), ``polyscore``, ``last_scanned`` or ``created``,
``permalink``, ``window_closed`` and ``metadata``; ``search_by_ioc`` yields
IOC resources whose ``json`` is the SHA-256 string. Both raise ``NoResultsException`` when nothing exists.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from conftest import StubHelper
from polyswarm_enrichment.client_api import (
    CircuitBreaker,
    ConnectorClient,
    is_non_public_network_value,
)
from polyswarm_enrichment.connector import ConnectorTemplate
from polyswarm_enrichment.converter_to_stix import ConverterToStix
from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions

PERMALINK = "https://polyswarm.network/scan/results/url/abc123"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _iocs(*hashes):
    """search_by_ioc results as the SDK yields them: IOC resources, json = SHA-256."""
    return iter([SimpleNamespace(json=h) for h in hashes])


def _url_scan(malicious=2, total=4, scanned=None, **extra):
    """Build a URL-type scan result shaped like the measured API output."""
    if scanned is None:
        scanned = datetime.now(timezone.utc) - timedelta(days=3)
    data = {
        "id": "71234567890",
        "type": "URL",
        "detections": {
            "benign": total - malicious,
            "malicious": malicious,
            "total": total,
        },
        # Score comes from the engine verdicts, not from polyscore
        "polyscore": 0.33,
        "last_scanned": scanned.isoformat(),
        "permalink": PERMALINK,
        "window_closed": True,
        "metadata": [{"tool": "ip", "tool_metadata": {}}],
    }
    data.update(extra)
    return SimpleNamespace(json=data, permalink=data.get("permalink"))


def _make_client(search_url=None, search_by_ioc=None, community="default"):
    """ConnectorClient with a mocked PolySwarm SDK instance (no network)."""
    client = object.__new__(ConnectorClient)
    client.helper = StubHelper()
    client.polyswarm_community = community
    client.polyswarm = MagicMock()
    client.polyswarm_default = None
    client._circuit_breakers = {community: CircuitBreaker()}
    if search_url is not None:
        client.polyswarm.search_url.side_effect = search_url
    if search_by_ioc is not None:
        client.polyswarm.search_by_ioc.side_effect = search_by_ioc
    return client


def _raise_no_results(*_args, **_kwargs):
    raise polyswarm_exceptions.NoResultsException("no results")


def _make_connector(client=None, scope=None):
    connector = object.__new__(ConnectorTemplate)
    connector.helper = StubHelper()
    connector.helper.connect_scope = scope or (
        "stixfile,artifact,url,domain-name,ipv4-addr,ipv6-addr"
    )
    connector.helper.api = MagicMock()
    connector.stix_objects_list = []
    connector.converter_to_stix = ConverterToStix(connector.helper)
    connector.client = client or MagicMock()
    connector.max_tlp = "TLP:RED"
    connector.replace_with_lower_score = True
    connector.ioc_enabled = False
    connector.network_related_files_max = 10
    connector.network_indicator_min_detections = 2
    connector._send_bundle = MagicMock(return_value="[CONNECTOR] sent")
    return connector


_STIX_TYPES = {
    "Url": "url",
    "Domain-Name": "domain-name",
    "IPv4-Addr": "ipv4-addr",
    "IPv6-Addr": "ipv6-addr",
}


def _message(entity_type, value, event_type="enrichment"):
    obs_id = f"{_STIX_TYPES[entity_type]}--0d6a4c5e-4a2b-5c3d-9e8f-123456789abc"
    observable = {"id": obs_id, "type": _STIX_TYPES[entity_type], "value": value}
    return {
        "enrichment_entity": {"entity_type": entity_type, "id": "internal-id"},
        "stix_objects": [observable],
        "stix_entity": observable,
        "event_type": event_type,
    }


def _sent_objects(connector):
    return connector._send_bundle.call_args[0][0]


def _by_type(objects, stix_type):
    return [o for o in objects if o.get("type") == stix_type]


# ===========================================================================
# Routing
# ===========================================================================
class TestRouting:
    @pytest.mark.parametrize(
        "entity_type,value",
        [
            ("Url", "http://malware.wicar.org/data/eicar.com"),
            ("Domain-Name", "wicar.org"),
            ("IPv4-Addr", "8.8.8.8"),
            ("IPv6-Addr", "2001:4860:4860::8888"),
        ],
    )
    def test_network_types_use_lookup_path(self, entity_type, value):
        connector = _make_connector()
        connector.client.lookup_network_observable.return_value = {
            "scan": None,
            "related_files": [],
            "errors": [],
        }
        connector.process_message(_message(entity_type, value))
        connector.client.lookup_network_observable.assert_called_once_with(
            value, entity_type, related_files_max=10
        )
        connector.client.query_polyswarm.assert_not_called()

    def test_hash_path_unchanged(self):
        connector = _make_connector()
        connector.client.query_polyswarm.return_value = None
        file_id = "file--0d6a4c5e-4a2b-5c3d-9e8f-123456789abc"
        data = {
            "enrichment_entity": {"entity_type": "StixFile", "id": "internal-id"},
            "stix_objects": [{"id": file_id, "hashes": {"SHA-256": SHA_A}}],
            "stix_entity": {"id": file_id, "hashes": {"SHA-256": SHA_A}},
        }
        connector._collect_intelligence = MagicMock(return_value=[])
        connector.process_message(data)
        connector.client.query_polyswarm.assert_called_once_with(SHA_A)
        connector.client.lookup_network_observable.assert_not_called()

    def test_hash_without_hashes_still_reports_no_hash(self):
        connector = _make_connector()
        data = {
            "enrichment_entity": {"entity_type": "StixFile"},
            "stix_objects": [],
            "stix_entity": {"id": "file--1"},
        }
        assert "No hash" in connector.process_message(data)
        connector.client.lookup_network_observable.assert_not_called()

    def test_out_of_scope_playbook_sends_original_bundle(self):
        connector = _make_connector(scope="stixfile,artifact")
        message = _message("Domain-Name", "wicar.org", event_type=None)
        connector.process_message(message)
        connector._send_bundle.assert_called_once_with(message["stix_objects"])
        connector.client.lookup_network_observable.assert_not_called()

    def test_tlp_check_applies_to_network_observables(self):
        connector = _make_connector()
        connector.max_tlp = "TLP:GREEN"
        message = _message("IPv4-Addr", "8.8.8.8")
        message["enrichment_entity"]["objectMarking"] = [{"definition": "TLP:RED"}]
        assert "max_tlp" in connector.process_message(message)
        connector.client.lookup_network_observable.assert_not_called()


# ===========================================================================
# Private and internal values are never sent
# ===========================================================================
class TestNonPublicValues:
    @pytest.mark.parametrize(
        "entity_type,value",
        [
            ("IPv4-Addr", "10.0.0.5"),
            ("IPv4-Addr", "192.168.1.1"),
            ("IPv4-Addr", "127.0.0.1"),
            ("IPv4-Addr", "169.254.10.10"),
            ("IPv4-Addr", "224.0.0.251"),
            ("IPv4-Addr", "240.0.0.1"),
            ("IPv4-Addr", "0.0.0.0"),
            ("IPv4-Addr", "10.0.0.0/8"),
            ("IPv6-Addr", "::1"),
            ("IPv6-Addr", "fe80::1"),
            ("IPv6-Addr", "fd00::1"),
            ("IPv6-Addr", "ff02::1"),
            ("Domain-Name", "fileserver"),
            ("Domain-Name", "printer.local"),
            ("Domain-Name", "db.internal"),
            ("Domain-Name", "nas.lan"),
            ("Domain-Name", "intranet.corp"),
            ("Domain-Name", "router.home.arpa"),
            ("Domain-Name", "app.localhost"),
            ("Domain-Name", "localhost"),
            ("Url", "http://10.1.2.3/admin"),
            ("Url", "https://wiki.corp/page"),
            ("Url", "http://[::1]:8080/"),
            ("Url", "http://intranet/"),
        ],
    )
    def test_detected_as_non_public(self, entity_type, value):
        assert is_non_public_network_value(value, entity_type) is True

    @pytest.mark.parametrize(
        "entity_type,value",
        [
            ("IPv4-Addr", "8.8.8.8"),
            ("IPv6-Addr", "2001:4860:4860::8888"),
            ("Domain-Name", "wicar.org"),
            ("Domain-Name", "www.google.com."),
            ("Url", "https://www.google.com/"),
            ("Url", "malware.wicar.org/data/eicar.com"),
        ],
    )
    def test_public_values_allowed(self, entity_type, value):
        assert is_non_public_network_value(value, entity_type) is False

    def test_private_ip_skipped_without_api_call(self):
        client = _make_client()
        connector = _make_connector(client=client)
        result = connector.process_message(_message("IPv4-Addr", "192.168.0.10"))
        assert "Skipped" in result
        client.polyswarm.search_url.assert_not_called()
        client.polyswarm.search_by_ioc.assert_not_called()
        connector._send_bundle.assert_not_called()

    def test_internal_domain_skipped_without_api_call(self):
        client = _make_client()
        connector = _make_connector(client=client)
        result = connector.process_message(_message("Domain-Name", "dc01.corp"))
        assert "Skipped" in result
        client.polyswarm.search_url.assert_not_called()
        client.polyswarm.search_by_ioc.assert_not_called()

    def test_skip_from_playbook_still_returns_original_bundle(self):
        client = _make_client()
        connector = _make_connector(client=client)
        message = _message("IPv4-Addr", "10.0.0.1", event_type=None)
        connector.process_message(message)
        connector._send_bundle.assert_called_once_with(message["stix_objects"])
        client.polyswarm.search_url.assert_not_called()


# ===========================================================================
# Found scan: note, score, permalink reference, indicator threshold
# ===========================================================================
class TestFoundScan:
    def _run(self, entity_type, value, scan, related=None, min_detections=2):
        client = _make_client(
            search_url=lambda _v: iter([scan]),
            search_by_ioc=lambda **_kw: _iocs(*(related or [])),
        )
        connector = _make_connector(client=client)
        connector.network_indicator_min_detections = min_detections
        connector.process_message(_message(entity_type, value))
        return connector, client, _sent_objects(connector)

    def test_note_score_and_reference(self):
        connector, client, objects = self._run(
            "Url", "http://malware.wicar.org/data/eicar.com", _url_scan(2, 4)
        )
        client.polyswarm.search_url.assert_called_once_with(
            "http://malware.wicar.org/data/eicar.com"
        )
        notes = _by_type(objects, "note")
        assert len(notes) == 1
        note = notes[0]
        assert "Malicious: 2/4" in note["content"]
        assert PERMALINK in note["content"]
        assert "Stale scan" not in note["content"]
        assert note["external_references"][0]["url"] == PERMALINK
        assert note["external_references"][0]["source_name"] == "PolySwarm"
        # Score comes from the engine verdicts, not from polyscore
        observable = next(o for o in objects if o.get("type") == "url")
        assert observable["x_opencti_score"] == 50
        connector.helper.api.stix_cyber_observable.update_field.assert_called_once_with(
            id="internal-id", input={"key": "x_opencti_score", "value": "50"}
        )

    def test_score_rounds(self):
        _, _, objects = self._run("Domain-Name", "wicar.org", _url_scan(1, 3))
        observable = next(o for o in objects if o.get("type") == "domain-name")
        assert observable["x_opencti_score"] == 33

    def test_no_score_when_total_zero(self):
        connector, _, objects = self._run("Domain-Name", "wicar.org", _url_scan(0, 0))
        observable = next(o for o in objects if o.get("type") == "domain-name")
        assert "x_opencti_score" not in observable
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()
        assert len(_by_type(objects, "note")) == 1

    def test_keeps_higher_score_when_replace_disabled(self):
        client = _make_client(search_url=lambda _v: iter([_url_scan(1, 4)]))
        connector = _make_connector(client=client)
        connector.replace_with_lower_score = False
        message = _message("Url", "https://example.com/x")
        message["stix_entity"]["extensions"] = {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {"score": 90}
        }
        connector.process_message(message)
        observable = next(o for o in _sent_objects(connector) if o.get("type") == "url")
        assert "x_opencti_score" not in observable
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()

    def test_old_scan_flagged_in_note(self):
        old = datetime(2021, 5, 12, tzinfo=timezone.utc)
        _, _, objects = self._run("IPv4-Addr", "8.8.8.8", _url_scan(0, 3, old))
        note = _by_type(objects, "note")[0]
        assert "Stale scan" in note["content"]
        assert "older than 90 days" in note["content"]
        assert "2021-05-12" in note["content"]

    def test_created_used_when_last_scanned_missing(self):
        scan = _url_scan(0, 3)
        scan.json.pop("last_scanned")
        scan.json["created"] = "2022-01-02T03:04:05"
        _, _, objects = self._run("IPv4-Addr", "8.8.8.8", scan)
        assert "2022-01-02" in _by_type(objects, "note")[0]["content"]

    def test_one_detection_gives_no_indicator(self):
        _, _, objects = self._run("Domain-Name", "wicar.org", _url_scan(1, 3))
        assert _by_type(objects, "indicator") == []

    def test_two_detections_gives_indicator(self):
        connector, _, objects = self._run(
            "Url", "http://malware.wicar.org/data/eicar.com", _url_scan(2, 4)
        )
        indicators = _by_type(objects, "indicator")
        assert len(indicators) == 1
        indicator = indicators[0]
        assert (
            indicator["pattern"]
            == "[url:value = 'http://malware.wicar.org/data/eicar.com']"
        )
        assert indicator["confidence"] == 50
        assert indicator["created_by_ref"] == connector.converter_to_stix.author.id
        assert indicator["x_opencti_main_observable_type"] == "Url"
        assert all(label.startswith("polyswarm-") for label in indicator["labels"])
        valid_from = datetime.strptime(indicator["valid_from"], "%Y-%m-%dT%H:%M:%S.%fZ")
        valid_until = datetime.strptime(
            indicator["valid_until"], "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        assert valid_until - valid_from == timedelta(days=30)
        based_on = [
            o
            for o in _by_type(objects, "relationship")
            if o["relationship_type"] == "based-on"
        ]
        assert len(based_on) == 1
        assert based_on[0]["source_ref"] == indicator["id"]
        assert based_on[0]["target_ref"] == _message("Url", "x")["stix_entity"]["id"]

    def test_indicator_threshold_is_configurable(self):
        _, _, objects = self._run(
            "Domain-Name", "wicar.org", _url_scan(1, 3), min_detections=1
        )
        indicator = _by_type(objects, "indicator")[0]
        assert indicator["pattern"] == "[domain-name:value = 'wicar.org']"

    def test_ipv6_handled(self):
        value = "2a00:1450:85a3::8a2e:370:7334"
        _, client, objects = self._run(
            "IPv6-Addr", value, _url_scan(3, 5), related=[SHA_A]
        )
        client.polyswarm.search_url.assert_called_once_with(value)
        client.polyswarm.search_by_ioc.assert_called_once_with(ip=value)
        indicator = _by_type(objects, "indicator")[0]
        assert indicator["pattern"] == f"[ipv6-addr:value = '{value}']"
        assert indicator["x_opencti_main_observable_type"] == "IPv6-Addr"
        assert len(_by_type(objects, "file")) == 1


# ===========================================================================
# Related files (IP and domain only)
# ===========================================================================
class TestRelatedFiles:
    def test_related_files_capped_by_setting(self):
        client = _make_client(
            search_url=_raise_no_results,
            search_by_ioc=lambda **_kw: _iocs(SHA_A, SHA_B, SHA_C),
        )
        connector = _make_connector(client=client)
        connector.network_related_files_max = 2
        message = _message("IPv4-Addr", "8.8.8.8")
        connector.process_message(message)
        objects = _sent_objects(connector)
        files = _by_type(objects, "file")
        assert [f["hashes"]["SHA-256"] for f in files] == [SHA_A, SHA_B]
        assert all("x_opencti_score" not in f for f in files)
        related = [
            o
            for o in _by_type(objects, "relationship")
            if o["relationship_type"] == "related-to"
        ]
        assert len(related) == 2
        assert {r["source_ref"] for r in related} == {message["stix_entity"]["id"]}
        assert {r["target_ref"] for r in related} == {f["id"] for f in files}

    def test_related_files_disabled_at_zero(self):
        client = _make_client(
            search_url=lambda _v: iter([_url_scan(0, 3)]),
            search_by_ioc=lambda **_kw: _iocs(SHA_A),
        )
        connector = _make_connector(client=client)
        connector.network_related_files_max = 0
        connector.process_message(_message("Domain-Name", "wicar.org"))
        client.polyswarm.search_by_ioc.assert_not_called()
        assert _by_type(_sent_objects(connector), "file") == []

    def test_domain_uses_domain_ioc_search(self):
        client = _make_client(
            search_url=_raise_no_results, search_by_ioc=_raise_no_results
        )
        connector = _make_connector(client=client)
        connector.process_message(_message("Domain-Name", "wicar.org"))
        client.polyswarm.search_by_ioc.assert_called_once_with(domain="wicar.org")
        assert _by_type(_sent_objects(connector), "file") == []

    def test_url_never_searches_related_files(self):
        client = _make_client(search_url=lambda _v: iter([_url_scan(0, 3)]))
        connector = _make_connector(client=client)
        connector.process_message(_message("Url", "https://www.google.com/"))
        client.polyswarm.search_by_ioc.assert_not_called()

    def test_related_file_id_is_deterministic(self):
        converter = ConverterToStix(StubHelper())
        assert (
            converter.create_related_file(SHA_A)["id"]
            == converter.create_related_file(SHA_A.upper())["id"]
        )


# ===========================================================================
# No scan found and API errors
# ===========================================================================
class TestNotFoundAndErrors:
    def test_no_results_gives_not_found_note(self):
        client = _make_client(
            search_url=_raise_no_results, search_by_ioc=_raise_no_results
        )
        connector = _make_connector(client=client)
        connector.process_message(_message("Domain-Name", "unseen-example.org"))
        objects = _sent_objects(connector)
        notes = _by_type(objects, "note")
        assert len(notes) == 1
        assert "No Scan Found" in notes[0]["abstract"]
        assert "unseen-example.org" in notes[0]["content"]
        assert _by_type(objects, "indicator") == []
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()

    def test_empty_generator_gives_not_found_note(self):
        client = _make_client(search_url=lambda _v: iter([]))
        connector = _make_connector(client=client)
        connector.process_message(_message("Url", "https://example.org/a"))
        notes = _by_type(_sent_objects(connector), "note")
        assert "No Scan Found" in notes[0]["abstract"]

    def test_api_error_gives_error_note_and_trips_breaker(self):
        def _boom(_v):
            raise polyswarm_exceptions.RequestException("server error")

        client = _make_client(search_url=_boom)
        connector = _make_connector(client=client)
        connector.process_message(_message("Url", "https://example.org/a"))
        notes = _by_type(_sent_objects(connector), "note")
        assert len(notes) == 1
        # Only the error note: an API failure is not reported as "no scan"
        assert "PolySwarm API" in notes[0]["abstract"]
        assert "Error" in notes[0]["content"]
        assert client._circuit_breakers["default"].failure_count == 1

    def test_open_circuit_skips_api_call(self):
        client = _make_client()
        client._circuit_breakers["default"] = CircuitBreaker(failure_threshold=1)
        client._circuit_breakers["default"].record_failure()
        result = client.lookup_network_observable("8.8.8.8", "IPv4-Addr", 10)
        client.polyswarm.search_url.assert_not_called()
        client.polyswarm.search_by_ioc.assert_not_called()
        assert result["errors"][0]["error_type"] == "circuit_breaker_open"

    def test_dual_community_keeps_most_recent_scan(self):
        client = _make_client(community="private")
        older = _url_scan(0, 3, datetime(2021, 1, 1, tzinfo=timezone.utc))
        newer = _url_scan(2, 4, datetime(2026, 1, 1, tzinfo=timezone.utc))
        client.polyswarm.search_url.side_effect = lambda _v: iter([older])
        client.polyswarm_default = MagicMock()
        client.polyswarm_default.search_url.side_effect = lambda _v: iter([newer])
        client._circuit_breakers["default"] = CircuitBreaker()
        result = client.lookup_network_observable("https://example.org/", "Url")
        assert result["scan"]["community"] == "default"
        assert result["scan"]["malicious"] == 2
