"""Tests for URL, domain and IP observable enrichment (lookup only).

Mock results follow the shapes measured against the live API on 2026-11-06:
``search_url`` yields URL-type scans whose ``json`` carries ``detections``
(benign/malicious/total), ``polyscore``, ``last_scanned`` or ``created``,
``permalink``, ``window_closed`` and ``metadata``; ``search_by_ioc`` yields
IOC resources whose ``json`` is the SHA-256 string. Both raise ``NoResultsException`` when nothing exists.
"""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from conftest import StubHelper
from polyswarm_enrichment import client_api
from polyswarm_enrichment.client_api import (
    CircuitBreaker,
    ConnectorClient,
    is_non_public_network_value,
    loggable_network_value,
    url_has_userinfo,
)
from polyswarm_enrichment.connector import _TLP_MARKING_TO_NAME, ConnectorTemplate
from polyswarm_enrichment.converter_to_stix import ConverterToStix
from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions
from pycti import OpenCTIConnectorHelper

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
        # The score travels in the bundle only, never as a separate API write
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()

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


# ===========================================================================
# Egress filter: forms that resolve to non-public addresses
# ===========================================================================
class TestNonPublicForms:
    @pytest.mark.parametrize(
        "entity_type,value",
        [
            # RFC 6598 shared address space
            ("IPv4-Addr", "100.64.0.1"),
            ("IPv4-Addr", "100.127.255.254"),
            ("Url", "http://100.64.0.1/admin"),
            # Non-canonical IPv4 forms (inet_aton accepts them)
            ("IPv4-Addr", "127.1"),
            ("IPv4-Addr", "10.1"),
            ("IPv4-Addr", "0x7f.0.0.1"),
            ("IPv4-Addr", "2130706433"),
            ("Url", "http://127.1/secret"),
            ("Url", "http://10.1/secret"),
            ("Url", "http://0x7f.0.0.1/"),
            ("Url", "http://2130706433/"),
            ("Url", "http://0177.0.0.1/"),
            ("Url", "http://8.8.8.010/"),
            ("Domain-Name", "127.1"),
            ("Domain-Name", "10.1"),
            # Trailing root dot
            ("Url", "http://127.0.0.1./secret"),
            ("Url", "http://printer.local./"),
            ("Domain-Name", "127.0.0.1."),
            ("Domain-Name", "localhost."),
            ("Domain-Name", "db.internal."),
            # IPv6 literals in brackets and IPv4-mapped IPv6
            ("Url", "http://[fe80::1]/"),
            ("Url", "http://[fd00::1]:8443/x"),
            ("Url", "http://[::ffff:10.0.0.1]/"),
            ("Url", "http://[::ffff:100.64.0.1]/"),
            ("IPv6-Addr", "::ffff:10.0.0.1"),
            ("IPv6-Addr", "::ffff:127.0.0.1"),
            ("IPv6-Addr", "[::1]"),
        ],
    )
    def test_detected_as_non_public(self, entity_type, value):
        assert is_non_public_network_value(value, entity_type) is True

    @pytest.mark.parametrize(
        "entity_type,value",
        [
            ("IPv4-Addr", "100.128.0.1"),
            ("IPv6-Addr", "::ffff:8.8.8.8"),
            ("Url", "http://8.8.8.8/"),
            ("Url", "http://[2001:4860:4860::8888]/dns"),
            ("Url", "https://example.com./path"),
            ("Domain-Name", "example.com."),
        ],
    )
    def test_public_forms_allowed(self, entity_type, value):
        assert is_non_public_network_value(value, entity_type) is False

    @pytest.mark.parametrize(
        "entity_type,value",
        [
            ("IPv4-Addr", "127.1"),
            ("IPv4-Addr", "10.1"),
            ("IPv4-Addr", "100.64.0.1"),
            ("Url", "http://127.1/secret"),
            ("Url", "http://10.1/secret"),
            ("Url", "http://127.0.0.1./secret"),
            ("Domain-Name", "127.0.0.1."),
        ],
    )
    def test_no_api_call_for_named_inputs(self, entity_type, value):
        client = _make_client()
        connector = _make_connector(client=client)
        result = connector.process_message(_message(entity_type, value))
        assert "Skipped" in result
        client.polyswarm.search_url.assert_not_called()
        client.polyswarm.search_by_ioc.assert_not_called()
        connector._send_bundle.assert_not_called()


# ===========================================================================
# URLs with credentials and URL logging
# ===========================================================================
class TestUrlCredentialsAndLogging:
    CRED_URL = "https://alice:secret@example.com/login"

    def test_userinfo_detected(self):
        assert url_has_userinfo(self.CRED_URL) is True
        assert url_has_userinfo("https://alice@example.com/") is True
        assert url_has_userinfo("alice:secret@example.com/login") is True
        assert url_has_userinfo("https://example.com/login?user=a@b.c") is False

    def test_url_with_credentials_never_sent(self, capsys):
        client = _make_client()
        connector = _make_connector(client=client)
        result = connector.process_message(_message("Url", self.CRED_URL))
        assert "credentials" in result
        client.polyswarm.search_url.assert_not_called()
        client.polyswarm.search_by_ioc.assert_not_called()
        connector._send_bundle.assert_not_called()
        logs = capsys.readouterr().out
        assert "username or password" in logs
        assert "secret" not in logs
        assert "alice" not in logs

    def test_url_with_credentials_from_playbook_returns_original_bundle(self):
        client = _make_client()
        connector = _make_connector(client=client)
        message = _message("Url", self.CRED_URL, event_type=None)
        connector.process_message(message)
        connector._send_bundle.assert_called_once_with(message["stix_objects"])
        client.polyswarm.search_url.assert_not_called()

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("https://example.com/a/b?token=abc#frag", "https://example.com"),
            ("http://[2001:db8::1]:8080/x?y=1", "http://[2001:db8::1]"),
            ("example.com/path?q=1", "example.com"),
            ("https://alice:secret@example.com/login", "https://example.com"),
        ],
    )
    def test_loggable_url_is_scheme_and_host(self, value, expected):
        assert loggable_network_value(value, "Url") == expected

    def test_loggable_value_unchanged_for_domains_and_ips(self):
        assert loggable_network_value("wicar.org", "Domain-Name") == "wicar.org"
        assert loggable_network_value("8.8.8.8", "IPv4-Addr") == "8.8.8.8"

    def test_full_url_sent_but_only_host_logged(self, capsys):
        value = "https://example.com/reset?token=abc123"
        client = _make_client(search_url=lambda _v: iter([_url_scan(0, 3)]))
        connector = _make_connector(client=client)
        connector.process_message(_message("Url", value))
        # The full URL, query string included, is what PolySwarm receives
        client.polyswarm.search_url.assert_called_once_with(value)
        logs = capsys.readouterr().out
        assert "https://example.com" in logs
        assert "abc123" not in logs
        assert "/reset" not in logs


# ===========================================================================
# Markings: derived objects keep the source observable's markings
# ===========================================================================
TLP_AMBER_ID = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
TLP_RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
TLP_GREEN_ID = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
TLP_CLEAR_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
TLP_AMBER_STRICT_ID = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"


class TestMarkingPropagation:
    def _run(self, message, scan=None, related=None, min_detections=2):
        client = _make_client(
            search_url=lambda _v: iter([scan or _url_scan(3, 4)]),
            search_by_ioc=lambda **_kw: _iocs(*(related or [SHA_A])),
        )
        connector = _make_connector(client=client)
        connector.network_indicator_min_detections = min_detections
        connector.process_message(message)
        return connector, _sent_objects(connector)

    def _derived(self, connector, objects, message):
        author_id = connector.converter_to_stix.author.id
        source_ids = {o["id"] for o in message["stix_objects"]}
        return [
            o
            for o in objects
            if o.get("id") not in source_ids and o.get("id") != author_id
        ]

    def test_stix_marking_refs_copied_to_every_derived_object(self):
        message = _message("IPv4-Addr", "8.8.8.8")
        message["stix_entity"]["object_marking_refs"] = [TLP_AMBER_ID]
        connector, objects = self._run(message)
        derived = self._derived(connector, objects, message)
        types = {o["type"] for o in derived}
        assert {"note", "indicator", "relationship", "file"} <= types
        assert all(o["object_marking_refs"] == [TLP_AMBER_ID] for o in derived)

    def test_marked_bundle_is_json_serialisable(self):
        # pycti's stix2_create_bundle json.dumps the objects; stix2 relationships
        # copied with ** kept stix2 datetimes and failed live on 9 Nov 2026
        message = _message("Domain-Name", "example.org")
        message["stix_entity"]["object_marking_refs"] = [TLP_AMBER_ID]
        _, objects = self._run(message, related=[SHA_A, SHA_B])
        assert any(o.get("type") == "relationship" for o in objects)
        # The real helper turns stix2 objects into dicts, then json.dumps the bundle
        bundle = OpenCTIConnectorHelper.stix2_create_bundle(list(objects))
        assert json.loads(bundle)["objects"]

    def test_error_note_carries_markings(self):
        def _boom(_v):
            raise polyswarm_exceptions.RequestException("server error")

        message = _message("Url", "https://example.org/a")
        message["stix_entity"]["object_marking_refs"] = [TLP_GREEN_ID]
        client = _make_client(search_url=_boom)
        connector = _make_connector(client=client)
        connector.process_message(message)
        note = _by_type(_sent_objects(connector), "note")[0]
        assert note["object_marking_refs"] == [TLP_GREEN_ID]

    def test_not_found_note_carries_opencti_markings(self):
        message = _message("Domain-Name", "unseen-example.org")
        message["enrichment_entity"]["objectMarking"] = [
            {"definition": "TLP:GREEN", "standard_id": TLP_GREEN_ID}
        ]
        client = _make_client(
            search_url=_raise_no_results, search_by_ioc=_raise_no_results
        )
        connector = _make_connector(client=client)
        connector.process_message(message)
        note = _by_type(_sent_objects(connector), "note")[0]
        assert note["object_marking_refs"] == [TLP_GREEN_ID]

    def test_marking_definitions_from_incoming_bundle_are_kept(self):
        marking = {
            "type": "marking-definition",
            "id": TLP_AMBER_ID,
            "definition_type": "tlp",
            "definition": {"tlp": "amber"},
        }
        message = _message("IPv4-Addr", "8.8.8.8")
        message["stix_entity"]["object_marking_refs"] = [TLP_AMBER_ID]
        message["stix_objects"].append(marking)
        _, objects = self._run(message)
        assert marking in objects

    def test_unresolved_markings_still_applied_and_not_cleaned(self):
        custom = "marking-definition--11111111-2222-4333-8444-555555555555"
        message = _message("Domain-Name", "wicar.org")
        message["stix_entity"]["object_marking_refs"] = [custom]
        connector, objects = self._run(message)
        note = _by_type(objects, "note")[0]
        assert note["object_marking_refs"] == [custom]
        # Bundle cleanup would strip refs whose definition is not in the bundle
        assert connector._send_bundle.call_args.kwargs == {
            "cleanup_inconsistent_bundle": False
        }

    def test_no_markings_means_no_marking_refs(self):
        _, objects = self._run(_message("Domain-Name", "wicar.org"))
        assert all("object_marking_refs" not in o for o in objects)


# ===========================================================================
# TLP gate with the standard marking-definition ids
# ===========================================================================
class TestTlpGateStandardIds:
    def test_table_matches_stix2_and_pycti_ids(self):
        import stix2
        from pycti import MarkingDefinition

        assert _TLP_MARKING_TO_NAME[stix2.TLP_WHITE.id] == "TLP:CLEAR"
        assert _TLP_MARKING_TO_NAME[stix2.TLP_GREEN.id] == "TLP:GREEN"
        assert _TLP_MARKING_TO_NAME[stix2.TLP_AMBER.id] == "TLP:AMBER"
        assert _TLP_MARKING_TO_NAME[stix2.TLP_RED.id] == "TLP:RED"
        for name in ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"):
            assert (
                _TLP_MARKING_TO_NAME[MarkingDefinition.generate_id("TLP", name)] == name
            )
        assert len(_TLP_MARKING_TO_NAME) == 5

    @pytest.mark.parametrize(
        "ref,expected",
        [
            (TLP_CLEAR_ID, "TLP:CLEAR"),
            (TLP_GREEN_ID, "TLP:GREEN"),
            (TLP_AMBER_ID, "TLP:AMBER"),
            (TLP_AMBER_STRICT_ID, "TLP:AMBER+STRICT"),
            (TLP_RED_ID, "TLP:RED"),
        ],
    )
    def test_standard_ref_resolves(self, ref, expected):
        assert ConnectorTemplate._get_tlp({"object_marking_refs": [ref]}) == expected

    @pytest.mark.parametrize("ref", [TLP_AMBER_ID, TLP_AMBER_STRICT_ID, TLP_RED_ID])
    def test_standard_ref_above_max_tlp_blocks_lookup(self, ref):
        connector = _make_connector()
        connector.max_tlp = "TLP:GREEN"
        message = _message("Url", "https://example.com/")
        message["stix_entity"]["object_marking_refs"] = [ref]
        assert "max_tlp" in connector.process_message(message)
        connector.client.lookup_network_observable.assert_not_called()

    def test_standard_ref_within_max_tlp_allows_lookup(self):
        connector = _make_connector()
        connector.max_tlp = "TLP:AMBER"
        connector.client.lookup_network_observable.return_value = {
            "scan": None,
            "related_files": [],
            "errors": [],
        }
        message = _message("Url", "https://example.com/")
        message["stix_entity"]["object_marking_refs"] = [TLP_GREEN_ID]
        connector.process_message(message)
        connector.client.lookup_network_observable.assert_called_once()

    def test_every_marking_is_checked_not_just_the_first(self):
        connector = _make_connector()
        connector.max_tlp = "TLP:AMBER"
        message = _message("IPv4-Addr", "8.8.8.8")
        message["enrichment_entity"]["objectMarking"] = [
            {"definition": "TLP:GREEN", "standard_id": TLP_GREEN_ID},
            {"definition": "TLP:RED", "standard_id": TLP_RED_ID},
        ]
        assert "max_tlp" in connector.process_message(message)
        connector.client.lookup_network_observable.assert_not_called()

    def test_unresolved_marking_fails_closed_below_red(self, capsys):
        connector = _make_connector()
        connector.max_tlp = "TLP:AMBER"
        message = _message("Domain-Name", "wicar.org")
        message["stix_entity"]["object_marking_refs"] = [
            "marking-definition--11111111-2222-4333-8444-555555555555"
        ]
        result = connector.process_message(message)
        assert "can't be resolved" in result
        connector.client.lookup_network_observable.assert_not_called()
        connector._send_bundle.assert_not_called()
        assert "can't be resolved" in capsys.readouterr().out

    def test_unresolved_marking_from_playbook_returns_original_bundle(self):
        connector = _make_connector()
        connector.max_tlp = "TLP:GREEN"
        message = _message("Domain-Name", "wicar.org", event_type=None)
        message["stix_entity"]["object_marking_refs"] = ["marking-definition--x"]
        connector.process_message(message)
        connector._send_bundle.assert_called_once_with(message["stix_objects"])
        connector.client.lookup_network_observable.assert_not_called()

    def test_unresolved_marking_allowed_when_max_tlp_red(self):
        connector = _make_connector()
        connector.client.lookup_network_observable.return_value = {
            "scan": None,
            "related_files": [],
            "errors": [],
        }
        message = _message("Domain-Name", "wicar.org")
        message["stix_entity"]["object_marking_refs"] = ["marking-definition--x"]
        connector.process_message(message)
        connector.client.lookup_network_observable.assert_called_once()

    def test_marking_resolved_from_bundled_definition(self):
        custom_red = "marking-definition--99999999-2222-4333-8444-555555555555"
        connector = _make_connector()
        connector.max_tlp = "TLP:AMBER"
        message = _message("Domain-Name", "wicar.org")
        message["stix_entity"]["object_marking_refs"] = [custom_red]
        message["stix_objects"].append(
            {
                "type": "marking-definition",
                "id": custom_red,
                "definition_type": "TLP",
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:RED",
            }
        )
        assert "max_tlp" in connector.process_message(message)
        connector.client.lookup_network_observable.assert_not_called()

    def test_resolved_non_tlp_marking_does_not_block(self):
        pap = "marking-definition--77777777-2222-4333-8444-555555555555"
        connector = _make_connector()
        connector.max_tlp = "TLP:AMBER"
        connector.client.lookup_network_observable.return_value = {
            "scan": None,
            "related_files": [],
            "errors": [],
        }
        message = _message("Domain-Name", "wicar.org")
        message["stix_entity"]["object_marking_refs"] = [pap]
        message["enrichment_entity"]["objectMarking"] = [
            {"definition_type": "PAP", "definition": "PAP:GREEN", "standard_id": pap}
        ]
        connector.process_message(message)
        connector.client.lookup_network_observable.assert_called_once()


# ===========================================================================
# Score goes in the bundle only
# ===========================================================================
class TestScoreInBundle:
    def test_score_added_when_observable_not_in_incoming_bundle(self):
        client = _make_client(search_url=lambda _v: iter([_url_scan(1, 4)]))
        connector = _make_connector(client=client)
        message = _message("Domain-Name", "wicar.org")
        message["stix_objects"] = []
        connector.process_message(message)
        objects = _sent_objects(connector)
        observables = [o for o in objects if o.get("type") == "domain-name"]
        assert len(observables) == 1
        assert observables[0]["x_opencti_score"] == 25
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()

    def test_higher_existing_score_left_out_when_replace_disabled(self):
        client = _make_client(search_url=lambda _v: iter([_url_scan(1, 4)]))
        connector = _make_connector(client=client)
        connector.replace_with_lower_score = False
        message = _message("Domain-Name", "wicar.org")
        message["stix_objects"] = []
        message["stix_entity"]["extensions"] = {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {"score": 90}
        }
        connector.process_message(message)
        observable = next(
            o for o in _sent_objects(connector) if o.get("type") == "domain-name"
        )
        assert "x_opencti_score" not in observable
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()

    def test_lower_existing_score_replaced_when_replace_disabled(self):
        client = _make_client(search_url=lambda _v: iter([_url_scan(3, 4)]))
        connector = _make_connector(client=client)
        connector.replace_with_lower_score = False
        message = _message("Domain-Name", "wicar.org")
        message["stix_entity"]["extensions"] = {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {"score": 10}
        }
        connector.process_message(message)
        observable = next(
            o for o in _sent_objects(connector) if o.get("type") == "domain-name"
        )
        assert observable["x_opencti_score"] == 75
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()


# ===========================================================================
# Playbook: blank value still returns the original bundle
# ===========================================================================
class TestBlankValue:
    @pytest.mark.parametrize("value", ["", "   ", None])
    def test_blank_value_from_playbook_returns_original_bundle(self, value):
        connector = _make_connector()
        message = _message("Url", "x", event_type=None)
        message["stix_entity"]["value"] = value
        result = connector.process_message(message)
        assert "No value" in result
        connector._send_bundle.assert_called_once_with(message["stix_objects"])
        connector.client.lookup_network_observable.assert_not_called()

    def test_blank_value_from_enrichment_sends_nothing(self):
        connector = _make_connector()
        message = _message("Url", "x")
        message["stix_entity"]["value"] = ""
        assert "No value" in connector.process_message(message)
        connector._send_bundle.assert_not_called()


# ===========================================================================
# Related-file lookup errors are reported, not hidden as "no result"
# ===========================================================================
class TestRelatedFileErrors:
    def test_api_error_on_ioc_search_gives_error_note(self):
        def _boom(**_kw):
            raise polyswarm_exceptions.RequestException("502 bad gateway")

        client = _make_client(search_url=_raise_no_results, search_by_ioc=_boom)
        connector = _make_connector(client=client)
        connector.process_message(_message("IPv4-Addr", "8.8.8.8"))
        notes = _by_type(_sent_objects(connector), "note")
        assert len(notes) == 1
        assert "PolySwarm API" in notes[0]["abstract"]
        assert "No Scan Found" not in notes[0]["abstract"]

    def test_network_error_on_ioc_search_is_reported(self):
        def _boom(**_kw):
            raise ConnectionError("connection reset")

        client = _make_client(
            search_url=lambda _v: iter([_url_scan(0, 3)]), search_by_ioc=_boom
        )
        result = client.lookup_network_observable("wicar.org", "Domain-Name", 10)
        assert result["scan"] is not None
        assert result["related_files"] == []
        assert result["errors"][0]["error_type"] == "network_error"
        assert client._circuit_breakers["default"].failure_count == 1

    def test_hashes_collected_before_error_are_kept(self):
        def _partial(**_kw):
            yield SimpleNamespace(json=SHA_A)
            raise polyswarm_exceptions.RequestException("500 server error")

        client = _make_client(search_url=_raise_no_results, search_by_ioc=_partial)
        result = client.lookup_network_observable("8.8.8.8", "IPv4-Addr", 10)
        assert result["related_files"] == [SHA_A]
        assert len(result["errors"]) == 1

    def test_no_results_on_ioc_search_is_not_an_error(self):
        client = _make_client(
            search_url=_raise_no_results, search_by_ioc=_raise_no_results
        )
        result = client.lookup_network_observable("8.8.8.8", "IPv4-Addr", 10)
        assert result["errors"] == []


def test_sdk_does_not_log_searched_values():
    # polyswarm_api logs "Searching for url <full url>" at INFO
    import logging
    from unittest.mock import patch

    sdk_logger = logging.getLogger("polyswarm_api")
    sdk_logger.setLevel(logging.NOTSET)
    config = SimpleNamespace(
        api_key="k", community="default", polykg_api_url=None, max_polling_time=60
    )
    with patch.object(client_api, "PolyswarmAPI"), patch.object(
        ConnectorClient, "_validate_api_access"
    ):
        ConnectorClient(MagicMock(), config)
    assert sdk_logger.level == logging.WARNING


def test_extra_brackets_are_treated_as_malformed():
    # One bracket pair is IPv6 notation; nested brackets are malformed and never sent
    assert is_non_public_network_value("[[2001:4860:4860::8888]]", "IPv6-Addr")
    assert is_non_public_network_value("[[8.8.8.8]]", "IPv4-Addr")
    assert not is_non_public_network_value("[2001:4860:4860::8888]", "IPv6-Addr")
    assert is_non_public_network_value("[[google.com]]", "Domain-Name")
