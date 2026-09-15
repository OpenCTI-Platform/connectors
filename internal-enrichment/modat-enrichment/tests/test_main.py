from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from connector import ConnectorSettings, ModatConnector
from modat_client import ModatClient
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "ipv4-addr",
                    "log_level": "error",
                    "auto": True,
                },
                "modat": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                    "max_tlp": "TLP:CLEAR",
                    "default_score": 75,
                    "create_note": True,
                    "include_cves": False,
                    "max_services_in_summary": 10,
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "ipv4-addr"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto == True


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ModatConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
    assert connector.api_base_url == "http://test.com/"
    assert connector.api_key == "test-api-key"
    assert connector.max_tlp == "TLP:CLEAR"


# --- ModatClient: SSRF / IPv4 validation ----------------------------------


@pytest.mark.parametrize(
    "bad_value",
    [
        "1.1.1.1/../healthz/v1",
        "1.1.1.1?foo=bar",
        "not-an-ip",
        "::1",  # IPv6 — connector scope is IPv4 only
        "1.1.1.1.1",
        "",
        None,
    ],
)
def test_modat_client_rejects_non_ipv4(bad_value):
    """The Modat client must refuse anything that isn't a literal IPv4 address,
    so that an attacker-controlled observable value cannot escape the URL path."""
    client = ModatClient(helper=MagicMock(), base_url="http://test", api_key="k")
    with pytest.raises(ValueError):
        client.get_host_details(bad_value)


def test_modat_client_accepts_real_ipv4(monkeypatch):
    client = ModatClient(helper=MagicMock(), base_url="http://test", api_key="k")
    seen = {}

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"ip": "1.2.3.4"}}

    def fake_get(url, headers=None, timeout=None):
        seen["url"] = url
        seen["headers"] = headers
        return FakeResp()

    monkeypatch.setattr(client.session, "get", fake_get)
    out = client.get_host_details("1.2.3.4")
    assert out == {"data": {"ip": "1.2.3.4"}}
    assert seen["url"] == "http://test/host/1.2.3.4/v1"
    # Defense in depth: Authorization must be passed per-request, not via
    # session.headers, so requests strips it on cross-origin redirects.
    assert seen["headers"]["Authorization"].startswith("Bearer ")


# --- process_message paths ------------------------------------------------


def _build_message(value="1.2.3.4", tlp_marking=None):
    stix_entity = {
        "type": "ipv4-addr",
        "id": "ipv4-addr--12345678-1234-4234-8234-123456789abc",
        "value": value,
        "object_marking_refs": [],
    }
    enrichment_entity = {"entity_type": "IPv4-Addr", "objectMarking": []}
    if tlp_marking:
        enrichment_entity["objectMarking"] = [
            {"definition_type": "TLP", "definition": tlp_marking}
        ]
    return {
        "enrichment_entity": enrichment_entity,
        "stix_entity": stix_entity,
        "stix_objects": [],
        "event_type": "create",
    }


def _build_connector(mock_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.stix2_create_bundle = lambda objects: {"type": "bundle", "objects": objects}
    helper.send_stix2_bundle = lambda bundle: [bundle]
    return ModatConnector(config=settings, helper=helper)


def test_process_message_skips_when_modat_returns_404(
    mock_opencti_connector_helper, monkeypatch
):
    connector = _build_connector(mock_opencti_connector_helper)

    response = requests.Response()
    response.status_code = 404

    def fake_get(self, ip):  # noqa: ARG001
        raise requests.HTTPError(response=response)

    monkeypatch.setattr(ModatClient, "get_host_details", fake_get)
    msg = _build_message()
    result = connector.process_message(msg)
    assert "1 STIX bundle" in result
    # No enrichment objects appended on 404
    assert msg["stix_objects"] == []


def test_process_message_skips_invalid_ipv4(mock_opencti_connector_helper, monkeypatch):
    """Even if a malformed value sneaks through OpenCTI's validation, the
    connector must not issue a request and must not crash."""
    connector = _build_connector(mock_opencti_connector_helper)
    called = {"n": 0}

    def fake_get(self, ip):  # noqa: ARG001
        called["n"] += 1
        return {"data": {}}

    monkeypatch.setattr(
        ModatClient,
        "get_host_details",
        lambda self, ip: ModatClient._validate_ipv4(ip) or fake_get(self, ip),
    )

    msg = _build_message(value="1.1.1.1/../etc")
    result = connector.process_message(msg)
    assert "1 STIX bundle" in result
    assert called["n"] == 0
    assert msg["stix_objects"] == []


def test_process_message_rejects_high_tlp(mock_opencti_connector_helper):
    """Observables above MODAT_MAX_TLP must never be sent to Modat."""
    connector = _build_connector(mock_opencti_connector_helper)
    msg = _build_message(tlp_marking="TLP:RED")  # CLEAR is the configured max
    with pytest.raises(ValueError, match="TLP of the observable"):
        connector.process_message(msg)


# --- end-to-end enrichment with a captured bundle -------------------------

# A representative `GET /host/{ip}/v1` payload (the connector reads `data`).
MODAT_RECORD = {
    "asn": {"number": 13335, "org": "Cloudflare, Inc."},
    "geo": {
        "country_name": "United States",
        "city_name": "San Francisco",
        "country_iso_code": "US",
    },
    "fqdns": ["example.org", "www.example.org"],
    "tags": ["open-directory", "iot device"],
    "is_anycast": True,
    "services": [
        {
            "transport": "tcp",
            "protocol": "https",
            "last_scanned_port": 443,
            "ports": [443],
            # Volatile field: changes every time Modat re-scans. The note id must
            # NOT depend on this, or re-enrichment would create duplicate notes.
            "scanned_at": "2026-05-01T00:00:00Z",
            "fingerprints": {"service": {"name": "nginx", "version": "1.25"}},
            "tls": {
                "fingerprint_sha256": "a" * 64,
                "fingerprint_sha1": "b" * 40,
                "serial_number": "0123456789",
                "issuer": {
                    "common_name": ["Example CA"],
                    "organization": ["Example Org"],
                },
                "subject": {"common_name": ["example.org"]},
                "valid_from": "2026-01-01T00:00:00Z",
                "expires_at": "2027-01-01T00:00:00Z",
                "is_self_signed": False,
                "supported_versions": ["TLSv1.3"],
                "extensions": {
                    "subject_alt_name": {"dns": ["example.org", "alt.example.org"]}
                },
                "raw": (
                    "Signature Algorithm: ecdsa-with-SHA384\n"
                    "Public Key Algorithm: id-ecPublicKey\n"
                ),
            },
        }
    ],
    "cves": [{"id": "CVE-2024-12345", "cvss": 9.8, "is_kev": True}],
}


def _otype(obj):
    if isinstance(obj, dict):
        return obj.get("type")
    return getattr(obj, "type", None)


def _oget(obj, key):
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _capture_bundles(connector):
    captured = []
    connector.helper.stix2_create_bundle = lambda objects: captured.append(objects) or {
        "type": "bundle",
        "objects": objects,
    }
    connector.helper.send_stix2_bundle = lambda bundle: [bundle]
    return captured


def test_process_message_builds_expected_stix(
    mock_opencti_connector_helper, monkeypatch
):
    connector = _build_connector(mock_opencti_connector_helper)
    captured = _capture_bundles(connector)
    monkeypatch.setattr(
        ModatClient, "get_host_details", lambda self, ip: {"data": MODAT_RECORD}
    )

    connector.process_message(_build_message())

    objects = captured[-1]
    types = {_otype(o) for o in objects}
    assert "identity" in types  # author + ASN org
    assert "autonomous-system" in types
    assert "location" in types  # country + city
    assert "domain-name" in types  # fqdns + SAN domains
    assert "x509-certificate" in types
    assert "relationship" in types
    assert "note" in types
    # include_cves defaults to False in the stub config, so no CVE objects.
    assert "vulnerability" not in types


def test_process_message_note_is_idempotent(mock_opencti_connector_helper, monkeypatch):
    """Re-enriching the same IP must reuse the same note id (no duplicate notes),
    even though the Modat payload carries a volatile per-service scan timestamp."""
    connector = _build_connector(mock_opencti_connector_helper)
    captured = _capture_bundles(connector)

    def _note_id(objects):
        return next(_oget(o, "id") for o in objects if _otype(o) == "note")

    monkeypatch.setattr(
        ModatClient, "get_host_details", lambda self, ip: {"data": MODAT_RECORD}
    )
    connector.process_message(_build_message())
    first_id = _note_id(captured[-1])

    # Second scan: same host, but Modat reports a new scan time.
    rescanned = {**MODAT_RECORD, "services": [dict(MODAT_RECORD["services"][0])]}
    rescanned["services"][0]["scanned_at"] = "2026-06-01T12:34:56Z"
    monkeypatch.setattr(
        ModatClient, "get_host_details", lambda self, ip: {"data": rescanned}
    )
    connector.process_message(_build_message())
    second_id = _note_id(captured[-1])

    assert first_id == second_id


def test_process_message_creates_vulnerabilities_when_enabled(
    mock_opencti_connector_helper, monkeypatch
):
    connector = _build_connector(mock_opencti_connector_helper)
    connector.include_cves = True
    connector.converter.include_cves = True
    captured = _capture_bundles(connector)
    monkeypatch.setattr(
        ModatClient, "get_host_details", lambda self, ip: {"data": MODAT_RECORD}
    )

    connector.process_message(_build_message())

    objects = captured[-1]
    vulns = [o for o in objects if _otype(o) == "vulnerability"]
    assert len(vulns) == 1
    assert _oget(vulns[0], "name") == "CVE-2024-12345"


def test_process_message_tolerates_malformed_scalars(
    mock_opencti_connector_helper, monkeypatch
):
    """Malformed scalar values (string port, 'N/A' CVSS, numeric serial/ASN) must
    NOT abort enrichment — the lenient model coerces them and the connector still
    builds a full bundle. Regression guard: these used to raise ValidationError
    and skip all enrichment."""
    connector = _build_connector(mock_opencti_connector_helper)
    captured = _capture_bundles(connector)
    messy = {
        "asn": {"number": "13335", "org": 999},
        "geo": {"country_name": "United States", "country_iso_code": 840},
        "fqdns": ["example.org"],
        "services": [
            {
                "transport": "tcp",
                "last_scanned_port": "unknown",
                "http": {"status_code": "200"},
                "tls": {"serial_number": 12345, "fingerprint_sha256": "a" * 64},
                "cves": [{"id": "CVE-1", "cvss": "N/A", "is_kev": "false"}],
            }
        ],
        "cves": [{"id": "CVE-2", "cvss": ""}],
    }
    monkeypatch.setattr(
        ModatClient, "get_host_details", lambda self, ip: {"data": messy}
    )

    result = connector.process_message(_build_message())

    assert "1 STIX bundle" in result
    types = {_otype(o) for o in captured[-1]}
    # enrichment still produced objects despite the malformed scalars
    assert "autonomous-system" in types
    assert "domain-name" in types
    assert "note" in types
