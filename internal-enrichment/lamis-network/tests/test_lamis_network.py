# -*- coding: utf-8 -*-
"""Unit tests for Lamis Network OpenCTI connector."""

import uuid
from unittest.mock import MagicMock, patch

import pytest
import requests
import requests_mock
import stix2
from lamis_network.builder import LamisNetworkBuilder
from lamis_network.client import LamisNetworkClient
from lamis_network.connector import (
    _MARKING_ID_TO_TLP,
    LamisNetworkConnector,
    _normalize_tlp,
    _validated_response,
)

# ==============================================================================
# Client Tests
# ==============================================================================


def test_client_get_ip_reputation_success():
    client = LamisNetworkClient(
        api_key="test_key", base_url="https://api.lamisnetwork.com"
    )
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.lamisnetwork.com/v1/ip/8.8.8.8",
            json={
                "ip": "8.8.8.8",
                "fraud_score": 15,
                "is_datacenter": True,
                "is_vpn": False,
                "asn": {"asn": 15169, "name": "Google LLC"},
                "geo": {
                    "country": "United States",
                    "country_code": "US",
                    "city": "Mountain View",
                },
            },
            status_code=200,
        )
        data = client.get_ip_reputation("8.8.8.8")
        assert data is not None
        assert data["ip"] == "8.8.8.8"
        assert data["fraud_score"] == 15
        assert data["is_datacenter"] is True
        assert m.last_request.headers["Authorization"] == "Bearer test_key"
        assert "X-API-Key" not in m.last_request.headers


def test_client_fallback_to_score_param():
    client = LamisNetworkClient(
        api_key="test_key", base_url="https://api.lamisnetwork.com"
    )
    with requests_mock.Mocker() as m:
        m.get("https://api.lamisnetwork.com/v1/ip/1.1.1.1", status_code=404)
        m.get(
            "https://api.lamisnetwork.com/v1/score?ip=1.1.1.1",
            json={"ip": "1.1.1.1", "fraud_score": 5},
            status_code=200,
        )
        data = client.get_ip_reputation("1.1.1.1")
        assert data is not None
        assert data["fraud_score"] == 5


def test_client_handles_auth_error():
    client = LamisNetworkClient(api_key="bad_key")
    with requests_mock.Mocker() as m:
        m.get("https://api.lamisnetwork.com/v1/ip/8.8.8.8", status_code=401)
        data = client.get_ip_reputation("8.8.8.8")
        assert data is None


def test_client_handles_rate_limit():
    client = LamisNetworkClient(api_key="test_key")
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.lamisnetwork.com/v1/ip/8.8.8.8",
            status_code=429,
            headers={"Retry-After": "60"},
        )
        data = client.get_ip_reputation("8.8.8.8")
        assert data is None


def test_client_handles_timeout():
    client = LamisNetworkClient(api_key="test_key", timeout=1)
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.lamisnetwork.com/v1/ip/8.8.8.8",
            exc=requests.exceptions.Timeout,
        )
        data = client.get_ip_reputation("8.8.8.8")
        assert data is None


def test_client_invalid_json():
    client = LamisNetworkClient(api_key="test_key")
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.lamisnetwork.com/v1/ip/8.8.8.8",
            text="not json",
            status_code=200,
        )
        assert client.get_ip_reputation("8.8.8.8") is None


# ==============================================================================
# Builder Tests
# ==============================================================================


@pytest.fixture
def mock_helper():
    helper = MagicMock()
    helper.connect_confidence_level = 50
    helper.stix2_create_bundle.return_value = '{"type": "bundle"}'
    return helper


@pytest.fixture
def dummy_author():
    return stix2.Identity(
        id=f"identity--{uuid.uuid4()}",
        name="Lamis Network",
        identity_class="organization",
    )


@pytest.fixture
def dummy_observable():
    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    return {
        "id": obs_id,
        "standard_id": obs_id,
        "entity_type": "IPv4-Addr",
        "value": "198.51.100.1",
        "objectMarking": [
            {
                "definition_type": "TLP",
                "definition": "TLP:CLEAR",
                "standard_id": f"marking-definition--{uuid.uuid4()}",
            }
        ],
    }


def test_builder_enrich_observable(mock_helper, dummy_author, dummy_observable):
    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    stix_entity = {
        "type": "ipv4-addr",
        "id": dummy_observable["standard_id"],
        "value": dummy_observable["value"],
    }
    builder.enrich_observable(stix_entity, 85, ["vpn"])
    assert len(builder.bundle) == 2
    assert builder.bundle[1]["id"] == dummy_observable["standard_id"]
    assert stix_entity.get("extensions") is None
    extension = next(iter(builder.bundle[1]["extensions"].values()))
    assert extension["score"] == 85
    assert "vpn" in extension["labels"]
    assert extension["external_references"][0]["source_name"] == "Lamis Network"
    mock_helper.api.stix_cyber_observable.update_field.assert_not_called()


def test_builder_add_asn(mock_helper, dummy_author, dummy_observable):
    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    builder.add_asn({"asn": "AS13335", "name": "Cloudflare, Inc."})

    as_objects = [
        obj for obj in builder.bundle if isinstance(obj, stix2.AutonomousSystem)
    ]
    rel_objects = [obj for obj in builder.bundle if isinstance(obj, stix2.Relationship)]

    assert len(as_objects) == 1
    assert as_objects[0].number == 13335
    assert as_objects[0].name == "Cloudflare, Inc."
    assert list(as_objects[0].object_marking_refs) == [
        dummy_observable["objectMarking"][0]["standard_id"]
    ]

    assert len(rel_objects) == 1
    assert rel_objects[0].relationship_type == "belongs-to"
    assert rel_objects[0].target_ref == as_objects[0].id


def test_builder_add_geolocation(mock_helper, dummy_author, dummy_observable):
    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    builder.add_geolocation(
        {
            "country": "Austria",
            "country_code": "AT",
            "city": "Vienna",
        }
    )

    loc_objects = [obj for obj in builder.bundle if isinstance(obj, stix2.Location)]
    rel_objects = [obj for obj in builder.bundle if isinstance(obj, stix2.Relationship)]

    assert len(loc_objects) == 2
    assert any(loc.name == "Austria" for loc in loc_objects)
    assert any(loc.name == "Vienna" for loc in loc_objects)
    assert any(loc.city == "Vienna" for loc in loc_objects if loc.name == "Vienna")

    assert len(rel_objects) == 2
    assert all(rel.relationship_type == "located-at" for rel in rel_objects)


def test_builder_create_indicator(mock_helper, dummy_author, dummy_observable):
    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    builder.create_indicator(
        ip_value="198.51.100.1",
        entity_type="IPv4-Addr",
        fraud_score=90,
        labels=["vpn", "suspicious"],
        description="High risk VPN IP",
    )

    ind_objects = [obj for obj in builder.bundle if isinstance(obj, stix2.Indicator)]
    rel_objects = [obj for obj in builder.bundle if isinstance(obj, stix2.Relationship)]

    assert len(ind_objects) == 1
    assert ind_objects[0].name == "198.51.100.1"
    assert ind_objects[0].pattern == "[ipv4-addr:value = '198.51.100.1']"
    assert "suspicious" in ind_objects[0].labels
    assert "vpn" in ind_objects[0].labels

    assert len(rel_objects) == 1
    assert rel_objects[0].relationship_type == "based-on"
    assert rel_objects[0].source_ref == ind_objects[0].id


def test_builder_send_bundle(mock_helper, dummy_author, dummy_observable):
    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    builder.add_asn({"asn": 1234, "name": "Test ASN"})
    res = builder.send_bundle()

    assert "Sent STIX bundle" in res
    mock_helper.stix2_create_bundle.assert_called_once()
    mock_helper.send_stix2_bundle.assert_called_once()


def test_enrichment_bundle_serializes(mock_helper, dummy_author, dummy_observable):
    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    builder.enrich_observable(
        {
            "type": "ipv4-addr",
            "id": dummy_observable["standard_id"],
            "value": dummy_observable["value"],
        },
        85,
        ["vpn", "suspicious"],
    )
    builder.add_asn({"asn": 13335, "name": "Cloudflare"})
    serialized = stix2.Bundle(objects=builder.bundle, allow_custom=True).serialize()
    assert '"score": 85' in serialized
    assert '"object_marking_refs"' in serialized
    assert '"labels"' in serialized


def test_normalize_tlp():
    assert _normalize_tlp("CLEAR") == "TLP:CLEAR"
    assert _normalize_tlp("tlp:amber") == "TLP:AMBER"
    assert _normalize_tlp("TLP:RED") == "TLP:RED"
    assert _normalize_tlp(None) == "TLP:CLEAR"
    assert _normalize_tlp("", fallback="TLP:WHITE") == "TLP:WHITE"


# ==============================================================================
# Connector Tests
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_connector_check_max_tlp(mock_helper_cls):
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.side_effect = lambda tlp, max_tlp: tlp in (
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
    )

    with patch.dict("os.environ", {"LAMIS_NETWORK_MAX_TLP": "TLP:AMBER"}):
        connector = LamisNetworkConnector()

        obs_clear = {
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:CLEAR",
                    "standard_id": f"marking-definition--{uuid.uuid4()}",
                }
            ]
        }
        assert connector._check_max_tlp(obs_clear) is True

        obs_red = {
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:RED",
                    "standard_id": stix2.TLP_RED.id,
                }
            ]
        }
        assert connector._check_max_tlp(obs_red) is False
        assert (
            connector._check_max_tlp(
                {
                    "objectMarking": [
                        {
                            "definition_type": "TLP",
                            "definition": "TLP:GREEN",
                            "standard_id": stix2.TLP_GREEN.id,
                        },
                        {
                            "definition_type": "TLP",
                            "definition": "TLP:RED",
                            "standard_id": stix2.TLP_RED.id,
                        },
                    ]
                }
            )
            is False
        )
        assert (
            connector._check_max_tlp(
                {
                    "objectMarking": [
                        {
                            "definition_type": "TLP",
                            "definition": "TLP:RED",
                            "standard_id": stix2.TLP_RED.id,
                        },
                        {
                            "definition_type": "TLP",
                            "definition": "TLP:GREEN",
                            "standard_id": stix2.TLP_GREEN.id,
                        },
                    ]
                }
            )
            is False
        )
        assert (
            connector._check_max_tlp(
                {
                    "objectMarking": [
                        {
                            "definition_type": "TLP",
                            "definition": "TLP:UNKNOWN",
                            "standard_id": f"marking-definition--{uuid.uuid4()}",
                        },
                    ]
                }
            )
            is False
        )


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_connector_process_message_success(mock_helper_cls):
    mock_helper = MagicMock()
    mock_helper.connect_confidence_level = 50
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "203.0.113.10",
        "fraud_score": 88,
        "is_datacenter": True,
        "is_vpn": True,
        "is_tor": False,
        "is_proxy": False,
        "asn": {"asn": 64500, "name": "Example Hosting"},
        "geo": {"country": "Germany", "country_code": "DE", "city": "Frankfurt"},
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    data = {
        "enrichment_entity": {
            "id": obs_id,
            "standard_id": obs_id,
            "entity_type": "IPv4-Addr",
            "value": "203.0.113.10",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:CLEAR",
                    "standard_id": f"marking-definition--{uuid.uuid4()}",
                }
            ],
        }
    }
    data["stix_entity"] = {"type": "ipv4-addr", "id": obs_id, "value": "203.0.113.10"}

    result = connector._process_message(data)
    assert connector.client.get_ip_reputation.called
    assert "Sent STIX bundle" in result or "objects" in result
    mock_helper.api.stix_cyber_observable.update_field.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_connector_process_message_tlp_skip(mock_helper_cls):
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = False

    connector = LamisNetworkConnector()
    connector.client = MagicMock()

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    data = {
        "enrichment_entity": {
            "id": obs_id,
            "standard_id": obs_id,
            "entity_type": "IPv4-Addr",
            "value": "198.51.100.99",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:RED",
                    "standard_id": stix2.TLP_RED.id,
                }
            ],
        }
    }

    result = connector._process_message(data)
    assert "skipped due to TLP restrictions" in result
    # External API MUST NOT be called when TLP exceeds limit
    assert not connector.client.get_ip_reputation.called


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_mixed_tlp_never_calls_external_api(mock_helper_cls):
    mock_helper_cls.return_value = MagicMock()
    mock_helper_cls.check_max_tlp.side_effect = lambda tlp, maximum: tlp != "TLP:RED"
    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    for markings in (
        [stix2.TLP_GREEN, stix2.TLP_RED],
        [stix2.TLP_RED, stix2.TLP_GREEN],
    ):
        result = connector._process_message(
            {
                "enrichment_entity": {
                    "id": obs_id,
                    "standard_id": obs_id,
                    "entity_type": "IPv4-Addr",
                    "value": "198.51.100.99",
                    "objectMarking": [
                        {
                            "definition_type": "TLP",
                            "definition": _MARKING_ID_TO_TLP.get(
                                marking.id, "TLP:CLEAR"
                            ),
                            "standard_id": marking.id,
                        }
                        for marking in markings
                    ],
                }
            }
        )
        assert "skipped" in result
    connector.client.get_ip_reputation.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_connector_process_message_api_failure_preserves_knowledge(mock_helper_cls):
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = None  # Simulating 500/timeout

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    data = {
        "enrichment_entity": {
            "id": obs_id,
            "standard_id": obs_id,
            "entity_type": "IPv4-Addr",
            "value": "198.51.100.50",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:CLEAR",
                    "standard_id": f"marking-definition--{uuid.uuid4()}",
                }
            ],
        },
        "stix_entity": {
            "type": "ipv4-addr",
            "id": obs_id,
            "value": "198.51.100.50",
        },
    }

    result = connector._process_message(data)
    assert "no intelligence available" in result
    # Existing knowledge must not be cleared
    mock_helper.api.stix_cyber_observable.update_field.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        {"error": "temporarily unavailable"},
        {"fraud_score": -1},
        {"fraud_score": 101},
        {"fraud_score": 50.0},
        {"fraud_score": True},
        {"fraud_score": "90"},
        {"fraud_score": 42, "is_vpn": "not-a-boolean"},
        {"fraud_score": 42, "asn": "bad"},
        {"fraud_score": 42, "ip": "198.51.100.2"},
    ],
)
@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_invalid_api_response_causes_no_writes(mock_helper_cls, payload):
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = payload
    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.1",
            },
            "stix_entity": {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.1"},
        }
    )
    assert "no intelligence available" in result
    mock_helper.stix2_create_bundle.assert_not_called()
    mock_helper.send_stix2_bundle.assert_not_called()
    mock_helper.api.stix_cyber_observable.update_field.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_false_config_disables_indicator_and_relationships(mock_helper_cls):
    mock_helper_cls.return_value = MagicMock()
    mock_helper_cls.check_max_tlp.return_value = True
    with patch.dict(
        "os.environ",
        {
            "LAMIS_NETWORK_CREATE_INDICATOR": "false",
            "LAMIS_NETWORK_ADD_RELATIONSHIPS": "false",
        },
    ):
        connector = LamisNetworkConnector()
    assert connector.create_indicator is False
    assert connector.add_relationships is False


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_connector_process_ipv6_success(mock_helper_cls):
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "2001:4860:4860::8888",
        "fraud_score": 85,
        "is_datacenter": True,
        "asn_number": 15169,
        "asn_name": "Google LLC",
    }

    obs_id = f"ipv6-addr--{uuid.uuid4()}"
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv6-Addr",
                "value": "2001:4860:4860::8888",
            },
            "stix_entity": {
                "type": "ipv6-addr",
                "id": obs_id,
                "value": "2001:4860:4860::8888",
            },
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    indicators = [o for o in bundle_objs if getattr(o, "type", None) == "indicator"]
    assert len(indicators) == 1
    assert indicators[0].pattern == "[ipv6-addr:value = '2001:4860:4860::8888']"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_connector_ip_family_mismatch(mock_helper_cls):
    mock_helper_cls.return_value = MagicMock()
    connector = LamisNetworkConnector()

    obs_id1 = f"ipv4-addr--{uuid.uuid4()}"
    with pytest.raises(
        ValueError, match="IP address family does not match observable type"
    ):
        connector._process_message(
            {
                "enrichment_entity": {
                    "id": obs_id1,
                    "standard_id": obs_id1,
                    "entity_type": "IPv4-Addr",
                    "value": "2001:4860:4860::8888",
                },
                "stix_entity": {
                    "type": "ipv4-addr",
                    "id": obs_id1,
                    "value": "2001:4860:4860::8888",
                },
            }
        )

    obs_id2 = f"ipv6-addr--{uuid.uuid4()}"
    with pytest.raises(
        ValueError, match="IP address family does not match observable type"
    ):
        connector._process_message(
            {
                "enrichment_entity": {
                    "id": obs_id2,
                    "standard_id": obs_id2,
                    "entity_type": "IPv6-Addr",
                    "value": "8.8.8.8",
                },
                "stix_entity": {
                    "type": "ipv6-addr",
                    "id": obs_id2,
                    "value": "8.8.8.8",
                },
            }
        )


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_playbook_passthrough_on_tlp_skip(mock_helper_cls):
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = False
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    existing_objects = [
        {"id": obs_id, "type": "ipv4-addr", "value": "198.51.100.5"},
        {"id": f"incident--{uuid.uuid4()}", "type": "incident", "name": "Test"},
    ]
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.5",
            },
            "stix_objects": existing_objects,
        }
    )
    assert "skipped" in result
    mock_helper.send_stix2_bundle.assert_called_once()
    sent_bundle = mock_helper.stix2_create_bundle.call_args[0][0]
    assert sent_bundle == existing_objects
    connector.client.get_ip_reputation.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_playbook_bundle_preserves_existing_objects(mock_helper_cls):
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.10",
        "fraud_score": 80,
        "asn": {"asn": 64500, "name": "Test ASN"},
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    incident_id = f"incident--{uuid.uuid4()}"
    existing_stix_entity = {
        "id": obs_id,
        "type": "ipv4-addr",
        "value": "198.51.100.10",
    }
    existing_incident = {"id": incident_id, "type": "incident", "name": "Alert 1"}
    existing_bundle = [existing_stix_entity, existing_incident]

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.10",
            },
            "stix_entity": existing_stix_entity,
            "stix_objects": existing_bundle,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    incidents = [
        o for o in bundle_objs if (getattr(o, "id", None) or o.get("id")) == incident_id
    ]
    assert len(incidents) == 1

    observables = [
        o for o in bundle_objs if (getattr(o, "id", None) or o.get("id")) == obs_id
    ]
    assert len(observables) == 1


@pytest.mark.parametrize(
    "invalid_payload",
    [
        {"fraud_score": 50, "geo": {"country_code": 7}},
        {"fraud_score": 50, "geo": {"city": ["NotAString"]}},
        {"fraud_score": 50, "asn": {"name": 123}},
        {"fraud_score": 50, "asn": {"asn": True}},
        {"fraud_score": 50, "asn": {"asn": 5000000000}},
        {"fraud_score": 50, "asn": {"asn": "InvalidAS"}},
    ],
)
def test_invalid_geo_or_asn_field_types_rejected(invalid_payload):
    assert _validated_response(invalid_payload, "198.51.100.1") is None


# ==============================================================================
# P1 — stix_entity TLP enforcement (architect audit fix)
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_stix_entity_tlp_red_blocks_external_api(mock_helper_cls):
    """P1: enrichment_entity has no markings, but stix_entity carries TLP:RED.
    The external API must NOT be called — the IP must not be disclosed."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.side_effect = lambda level, max_tlp: (
        level in ("TLP:CLEAR", "TLP:WHITE", "TLP:GREEN")
        if max_tlp == "TLP:AMBER"
        else True
    )

    connector = LamisNetworkConnector()
    connector.client = MagicMock()

    # TLP:RED marking ref from the global map
    tlp_red_ref = stix2.TLP_RED.id

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "192.0.2.99",
                # No objectMarking / object_marking_refs on enrichment_entity
            },
            "stix_entity": {
                "type": "ipv4-addr",
                "id": obs_id,
                "value": "192.0.2.99",
                # stix_entity carries TLP:RED
                "object_marking_refs": [tlp_red_ref],
            },
        }
    )
    # Must be skipped — external API must never be called
    connector.client.get_ip_reputation.assert_not_called()
    assert "skipped" in result.lower() or "tlp" in result.lower()


# ==============================================================================
# P2 — analyst labels are preserved on re-enrichment (architect audit fix)
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_analyst_labels_preserved_on_re_enrichment(mock_helper_cls):
    """[P2] R13: Existing labels (e.g. analyst-assigned 'vpn' or 'malicious-activity')
    must be preserved intact on re-enrichment since SCO labels do not carry
    author provenance and must not be stripped."""
    from pycti import STIX_EXT_OCTI_SCO

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    # API now returns a low-risk score with NO infrastructure flags (vpn cleared)
    connector.client.get_ip_reputation.return_value = {
        "ip": "203.0.113.5",
        "fraud_score": 10,
        "is_datacenter": False,
        "is_vpn": False,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    # stix_entity already has an analyst label ("malicious-activity") and an
    # existing label ("vpn") stored in the OpenCTI SCO extension.
    stix_entity = {
        "type": "ipv4-addr",
        "id": obs_id,
        "value": "203.0.113.5",
        "x_lamis_network_labels": ["vpn"],
        "extensions": {
            STIX_EXT_OCTI_SCO: {
                "extension_type": "property-extension",
                "labels": ["malicious-activity", "vpn"],
                "x_lamis_network_labels": ["vpn"],
            }
        },
    }

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "203.0.113.5",
            },
            "stix_entity": stix_entity,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    enriched = next(
        (o for o in bundle_objs if (getattr(o, "id", None) or o.get("id")) == obs_id),
        None,
    )
    assert enriched is not None, "Enriched observable missing from bundle"

    ext = (
        (enriched if isinstance(enriched, dict) else dict(enriched))
        .get("extensions", {})
        .get(STIX_EXT_OCTI_SCO, {})
    )
    labels = ext.get("labels", [])
    # Analyst label must be preserved, while stale connector label 'vpn' is reconciled out
    assert (
        "malicious-activity" in labels
    ), f"Analyst label 'malicious-activity' was destroyed. Labels: {labels}"
    assert (
        "vpn" not in labels
    ), f"Stale connector label 'vpn' was not reconciled out. Labels: {labels}"


# ==============================================================================
# P1a — unknown stix_entity marking ref blocks API call (architect audit R2)
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_unknown_stix_entity_marking_ref_blocks_api(mock_helper_cls):
    """P1a: stix_entity.object_marking_refs contains an ID that is not in
    _MARKING_ID_TO_TLP (custom/unknown marking). The connector must treat this
    as a failed TLP check and never call the external API."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True

    connector = LamisNetworkConnector()
    connector.client = MagicMock()

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "192.0.2.1",
                # No markings on enrichment_entity
            },
            "stix_entity": {
                "type": "ipv4-addr",
                "id": obs_id,
                "value": "192.0.2.1",
                # Custom/unknown marking ID not present in _MARKING_ID_TO_TLP
                "object_marking_refs": ["marking-definition--unknown-custom-id"],
            },
        }
    )
    connector.client.get_ip_reputation.assert_not_called()
    assert "skipped" in result.lower() or "tlp" in result.lower()


# ==============================================================================
# P1b — generated objects carry stricter union marking (architect audit R3)
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_generated_objects_carry_stricter_union_marking(mock_helper_cls):
    """P1 R3: When enrichment_entity has TLP:GREEN but stix_entity has TLP:AMBER,
    generated ASN/location objects must carry BOTH (the stricter TLP:AMBER must
    be present), not just TLP:GREEN."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.5",
        "fraud_score": 20,
        "asn": {"asn": 64502, "name": "Test ASN"},
        "geo": {"country": "Austria", "country_code": "AT"},
    }

    tlp_green_ref = stix2.TLP_GREEN.id
    tlp_amber_ref = stix2.TLP_AMBER.id
    obs_id = f"ipv4-addr--{uuid.uuid4()}"

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.5",
                # enrichment_entity has only TLP:GREEN
                "objectMarking": [
                    {
                        "standard_id": tlp_green_ref,
                        "definition_type": "TLP",
                        "definition": "GREEN",
                    }
                ],
                "object_marking_refs": [tlp_green_ref],
            },
            "stix_entity": {
                "type": "ipv4-addr",
                "id": obs_id,
                "value": "198.51.100.5",
                # stix_entity carries stricter TLP:AMBER
                "object_marking_refs": [tlp_amber_ref],
            },
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Generated objects (ASN, Location, Relationship) must carry TLP:AMBER
    for obj in bundle_objs:
        obj_dict = obj if isinstance(obj, dict) else dict(obj)
        obj_type = obj_dict.get("type", "")
        if obj_type in ("autonomous-system", "location", "relationship"):
            refs = obj_dict.get("object_marking_refs", [])
            assert (
                tlp_amber_ref in refs
            ), f"Generated {obj_type} is missing TLP:AMBER. Got: {refs}"


# ==============================================================================
# P1b — generated objects inherit stix_entity TLP (architect audit R2)
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_generated_objects_inherit_stix_entity_tlp(mock_helper_cls):
    """P1b: When enrichment_entity has no markings but stix_entity carries
    TLP:AMBER, generated ASN/location/indicator objects must receive TLP:AMBER,
    not fall back to the connector's default TLP:CLEAR."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.1",
        "fraud_score": 80,
        "asn": {"asn": 64501, "name": "Test ASN"},
        "geo": {"country": "Germany", "country_code": "DE"},
    }

    tlp_amber_ref = stix2.TLP_AMBER.id
    obs_id = f"ipv4-addr--{uuid.uuid4()}"

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.1",
                # No markings on enrichment_entity
            },
            "stix_entity": {
                "type": "ipv4-addr",
                "id": obs_id,
                "value": "198.51.100.1",
                "object_marking_refs": [tlp_amber_ref],
            },
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # All generated objects (ASN, Location) must carry TLP:AMBER, not TLP:CLEAR
    for obj in bundle_objs:
        obj_dict = obj if isinstance(obj, dict) else dict(obj)
        obj_type = obj_dict.get("type", "")
        if obj_type in ("autonomous-system", "location", "relationship"):
            refs = obj_dict.get("object_marking_refs", [])
            assert tlp_amber_ref in refs, (
                f"Generated {obj_type} object has wrong markings: {refs} "
                f"(expected TLP:AMBER {tlp_amber_ref})"
            )


# ==============================================================================
# P2 — flat object_marking_refs on enrichment_entity not downgraded (R2)
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_flat_observable_marking_refs_not_downgraded(mock_helper_cls):
    """P2: enrichment_entity carries TLP:AMBER as a flat string in
    object_marking_refs (not the dict objectMarking format). The enriched SCO
    must inherit TLP:AMBER, not be downgraded to the default TLP:CLEAR."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.2",
        "fraud_score": 20,
    }

    tlp_amber_ref = stix2.TLP_AMBER.id
    obs_id = f"ipv4-addr--{uuid.uuid4()}"

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.2",
                # Flat string marking refs — no objectMarking dicts
                "object_marking_refs": [tlp_amber_ref],
            },
            "stix_entity": {
                "type": "ipv4-addr",
                "id": obs_id,
                "value": "198.51.100.2",
                # stix_entity has NO object_marking_refs
            },
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    enriched = next(
        (o for o in bundle_objs if (getattr(o, "id", None) or o.get("id")) == obs_id),
        None,
    )
    assert enriched is not None, "Enriched observable missing from bundle"
    enriched_dict = enriched if isinstance(enriched, dict) else dict(enriched)
    marking_refs = enriched_dict.get("object_marking_refs", [])
    assert (
        tlp_amber_ref in marking_refs
    ), f"Flat TLP:AMBER marking was downgraded. Got markings: {marking_refs}"


# ==============================================================================
# P1 R4 — Enriched observable preserves stricter marking union
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_enriched_observable_preserves_stricter_marking_union(mock_helper_cls):
    """P1 R4: When enrichment_entity has TLP:AMBER and stix_entity has TLP:GREEN,
    the enriched SCO in the bundle must contain TLP:AMBER (not just GREEN)."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.8",
        "fraud_score": 15,
    }

    tlp_green_ref = stix2.TLP_GREEN.id
    tlp_amber_ref = stix2.TLP_AMBER.id
    obs_id = f"ipv4-addr--{uuid.uuid4()}"

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.8",
                # enrichment_entity has TLP:AMBER
                "objectMarking": [
                    {
                        "standard_id": tlp_amber_ref,
                        "definition_type": "TLP",
                        "definition": "AMBER",
                    }
                ],
                "object_marking_refs": [tlp_amber_ref],
            },
            "stix_entity": {
                "type": "ipv4-addr",
                "id": obs_id,
                "value": "198.51.100.8",
                # stix_entity only has TLP:GREEN
                "object_marking_refs": [tlp_green_ref],
            },
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    enriched = next(
        (o for o in bundle_objs if (getattr(o, "id", None) or o.get("id")) == obs_id),
        None,
    )
    assert enriched is not None, "Enriched observable missing from bundle"
    enriched_dict = enriched if isinstance(enriched, dict) else dict(enriched)
    marking_refs = enriched_dict.get("object_marking_refs", [])
    # The enriched observable must contain the stricter TLP:AMBER
    assert (
        tlp_amber_ref in marking_refs
    ), f"Enriched observable missing stricter TLP:AMBER. Got: {marking_refs}"


# ==============================================================================
# P2 R4 — Non-TLP (PAP) marking in stix_entity is not rejected
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_pap_non_tlp_marking_in_stix_entity_not_rejected(mock_helper_cls):
    """P2 R4: When an observable has a PAP marking in objectMarking and
    stix_entity carries that PAP marking ref, it must be recognized as non-TLP
    and skipped rather than treated as an unknown marking that blocks enrichment."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.9",
        "fraud_score": 10,
    }

    pap_marking_id = f"marking-definition--{uuid.uuid4()}"
    tlp_clear_ref = stix2.TLP_WHITE.id
    obs_id = f"ipv4-addr--{uuid.uuid4()}"

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.9",
                "objectMarking": [
                    {
                        "standard_id": pap_marking_id,
                        "definition_type": "PAP",
                        "definition": "AMBER",
                    },
                    {
                        "standard_id": tlp_clear_ref,
                        "definition_type": "TLP",
                        "definition": "CLEAR",
                    },
                ],
                "object_marking_refs": [pap_marking_id, tlp_clear_ref],
            },
            "stix_entity": {
                "type": "ipv4-addr",
                "id": obs_id,
                "value": "198.51.100.9",
                "object_marking_refs": [pap_marking_id, tlp_clear_ref],
            },
        }
    )
    # The API call must have succeeded (not rejected due to PAP marking)
    connector.client.get_ip_reputation.assert_called_once_with("198.51.100.9")
    assert "Sent STIX bundle" in result


# ==============================================================================
# P2 R5 — Obsolete ASN and Geolocation relationships replaced on re-enrichment
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_obsolete_asn_and_geo_relationships_replaced_on_re_enrichment(mock_helper_cls):
    """P2 R5: When an IP changes ASN or location on re-enrichment, previous
    belongs-to and located-at relationships created by Lamis Network are
    replaced rather than leaving duplicate contradictory links."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    # New API response: AS 200 (Cloudflare), Location: Germany
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.20",
        "fraud_score": 10,
        "asn": {"asn": 200, "name": "New ASN"},
        "geo": {"country": "Germany", "country_code": "DE"},
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    old_asn_id = "autonomous-system--old-asn"
    old_loc_id = "location--old-loc"

    # Pre-existing relationships created by this author in the bundle
    old_belongs_to = {
        "id": f"relationship--{uuid.uuid4()}",
        "type": "relationship",
        "relationship_type": "belongs-to",
        "source_ref": obs_id,
        "target_ref": old_asn_id,
        "created_by_ref": connector.author.id,
    }
    old_located_at = {
        "id": f"relationship--{uuid.uuid4()}",
        "type": "relationship",
        "relationship_type": "located-at",
        "source_ref": obs_id,
        "target_ref": old_loc_id,
        "created_by_ref": connector.author.id,
    }
    # Third-party relationship that must NOT be removed
    third_party_rel = {
        "id": f"relationship--{uuid.uuid4()}",
        "type": "relationship",
        "relationship_type": "located-at",
        "source_ref": obs_id,
        "target_ref": "location--analyst-loc",
        "created_by_ref": "identity--analyst-author",
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.20"}
    stix_objects = [stix_entity, old_belongs_to, old_located_at, third_party_rel]

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.20",
            },
            "stix_entity": stix_entity,
            "stix_objects": stix_objects,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Verify old relationships from Lamis Network are gone
    rel_ids = [
        getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
        for o in bundle_objs
    ]
    assert (
        old_belongs_to["id"] not in rel_ids
    ), "Obsolete belongs-to relationship was not removed"
    assert (
        old_located_at["id"] not in rel_ids
    ), "Obsolete located-at relationship was not removed"
    # Third-party relationship must be retained
    assert (
        third_party_rel["id"] in rel_ids
    ), "Third-party relationship was erroneously removed"


# ==============================================================================
# P2 R5 — Indicator retired when score falls below threshold on re-enrichment
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_indicator_retired_when_score_falls_below_threshold(mock_helper_cls):
    """P2 R5: When an IP previously scored above the risk threshold and had an
    indicator, a re-enrichment with a lower score retires (revokes) the indicator
    rather than leaving an active high-risk indicator."""
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    # Now returns benign score of 15 (well below default suspicious threshold of 75)
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.30",
        "fraud_score": 15,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.30')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    # Existing active indicator and based-on relationship in the playbook bundle
    existing_indicator = {
        "id": ind_id,
        "type": "indicator",
        "name": "198.51.100.30",
        "pattern": pattern,
        "created_by_ref": connector.author.id,
        "revoked": False,
    }
    existing_based_on = {
        "id": f"relationship--{uuid.uuid4()}",
        "type": "relationship",
        "relationship_type": "based-on",
        "source_ref": ind_id,
        "target_ref": obs_id,
        "created_by_ref": connector.author.id,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.30"}
    stix_objects = [stix_entity, existing_indicator, existing_based_on]

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.30",
            },
            "stix_entity": stix_entity,
            "stix_objects": stix_objects,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Find the indicator in the bundle
    retired_ind = next(
        (
            o
            for o in bundle_objs
            if (
                getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
            )
            == ind_id
        ),
        None,
    )
    assert retired_ind is not None, "Indicator was not found in bundle"
    is_revoked = getattr(retired_ind, "revoked", None) or (
        retired_ind.get("revoked") if isinstance(retired_ind, dict) else False
    )
    assert (
        is_revoked is False
    ), "Indicator must not be permanently revoked (revoked=True) to allow reactivation"
    valid_until = getattr(retired_ind, "valid_until", None) or (
        retired_ind.get("valid_until") if isinstance(retired_ind, dict) else None
    )
    assert valid_until is not None, "Retired indicator must have valid_until set"
    score = getattr(retired_ind, "x_opencti_score", None)
    if score is None and isinstance(retired_ind, dict):
        score = retired_ind.get("x_opencti_score")
    assert score == 0, "Retired indicator score must be set to 0"

    # Verify obsolete based-on relationship was removed
    rel_ids = [
        getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
        for o in bundle_objs
    ]
    assert (
        existing_based_on["id"] not in rel_ids
    ), "Obsolete based-on relationship was not removed"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_indicator_retired_via_opencti_read_when_not_in_bundle(mock_helper_cls):
    """P2 R6: When an IP previously scored above the threshold and had an
    indicator created in OpenCTI, a later event that does NOT include the old
    indicator in stix_objects looks it up via helper.api.indicator.read by its
    deterministic ID and emits a revoked indicator."""
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.40",
        "fraud_score": 10,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.40')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    # OpenCTI API returns the existing indicator created by Lamis Network
    mock_helper.api.indicator.read.return_value = {
        "id": ind_id,
        "standard_id": ind_id,
        "name": "198.51.100.40",
        "created_by_ref": connector.author.id,
        "createdBy": {"standard_id": connector.author.id},
    }
    # OpenCTI API returns an existing based-on relationship created by Lamis Network
    mock_rel_id = f"relationship--{uuid.uuid4()}"
    mock_helper.api.stix_core_relationship.list.return_value = [
        {
            "id": mock_rel_id,
            "standard_id": mock_rel_id,
            "created_by_ref": connector.author.id,
            "createdBy": {"standard_id": connector.author.id},
        }
    ]

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.40"}
    # Note: stix_objects does NOT contain the indicator!
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.40",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    mock_helper.api.indicator.read.assert_called_once_with(id=ind_id)
    mock_helper.api.stix_core_relationship.delete.assert_not_called()

    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    retired_ind = next(
        (
            o
            for o in bundle_objs
            if (
                getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
            )
            == ind_id
        ),
        None,
    )
    assert (
        retired_ind is not None
    ), "Indicator was not emitted as revoked into the bundle"
    is_revoked = getattr(retired_ind, "revoked", None) or (
        retired_ind.get("revoked") if isinstance(retired_ind, dict) else False
    )
    assert (
        is_revoked is False
    ), "Indicator must not be permanently revoked (revoked=True)"
    valid_until = getattr(retired_ind, "valid_until", None) or (
        retired_ind.get("valid_until") if isinstance(retired_ind, dict) else None
    )
    assert valid_until is not None, "Retired indicator must have valid_until set"
    score = getattr(retired_ind, "x_opencti_score", None)
    if score is None and isinstance(retired_ind, dict):
        score = retired_ind.get("x_opencti_score")
    assert score == 0, "Retired indicator score must be set to 0"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_indicator_not_retired_if_owned_by_another_creator(mock_helper_cls):
    """P1 R7: When an indicator with matching pattern exists in OpenCTI or
    bundle but was created by an analyst or third party, Lamis Network must NOT
    revoke it or delete its based-on relationship."""
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.50",
        "fraud_score": 10,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.50')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    # Indicator in OpenCTI created by an analyst, NOT by Lamis Network
    mock_helper.api.indicator.read.return_value = {
        "id": ind_id,
        "standard_id": ind_id,
        "name": "198.51.100.50",
        "created_by_ref": "identity--analyst-creator",
        "createdBy": {"standard_id": "identity--analyst-creator"},
    }
    mock_rel_id = f"relationship--{uuid.uuid4()}"
    mock_helper.api.stix_core_relationship.list.return_value = [
        {
            "id": mock_rel_id,
            "standard_id": mock_rel_id,
            "created_by_ref": "identity--analyst-creator",
            "createdBy": {"standard_id": "identity--analyst-creator"},
        }
    ]

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.50"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.50",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result

    # The third-party relationship must NOT have been deleted
    mock_helper.api.stix_core_relationship.delete.assert_not_called()

    # The third-party indicator must NOT have been revoked in the bundle
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    revoked_inds = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == ind_id
    ]
    assert len(revoked_inds) == 0, "Third-party indicator was erroneously revoked!"


# ==============================================================================
# P1 R8 — Indicator reactivation after transient retirement
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_indicator_reactivated_when_score_rises_again(mock_helper_cls):
    """P1 R8: When an IP previously retired due to a benign score later scores high,
    the indicator is reactivated with an active state, updated score, and a based-on relationship.
    """
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    # High risk score (88 >= 75)
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.60",
        "fraud_score": 88,
        "is_vpn": True,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.60')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    # Previously retired indicator in bundle (valid_until set, score 0, not revoked)
    now_past = "2026-09-24T00:00:00Z"
    previously_retired_indicator = {
        "id": ind_id,
        "type": "indicator",
        "name": "198.51.100.60",
        "pattern": pattern,
        "created_by_ref": connector.author.id,
        "revoked": False,
        "valid_until": now_past,
        "x_opencti_score": 0,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.60"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.60",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity, previously_retired_indicator],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Find the reactivated indicator
    reactivated_ind = next(
        (
            o
            for o in bundle_objs
            if (
                getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
            )
            == ind_id
        ),
        None,
    )
    assert reactivated_ind is not None, "Indicator was not generated in the bundle"
    is_revoked = getattr(reactivated_ind, "revoked", None) or (
        reactivated_ind.get("revoked") if isinstance(reactivated_ind, dict) else False
    )
    assert is_revoked is False, "Reactivated indicator must not be revoked"
    valid_until = getattr(reactivated_ind, "valid_until", None) or (
        reactivated_ind.get("valid_until")
        if isinstance(reactivated_ind, dict)
        else None
    )
    assert valid_until is None, "Active indicator must not have valid_until"
    custom_props = getattr(reactivated_ind, "custom_properties", None) or (
        reactivated_ind.get("custom_properties")
        if isinstance(reactivated_ind, dict)
        else {}
    )
    score = getattr(reactivated_ind, "x_opencti_score", None) or custom_props.get(
        "x_opencti_score"
    )
    assert score == 88, f"Expected score 88, got {score}"

    # Verify based-on relationship exists
    based_on_rels = [
        o
        for o in bundle_objs
        if (
            getattr(o, "type", None) or (o.get("type") if isinstance(o, dict) else None)
        )
        == "relationship"
        and (
            getattr(o, "relationship_type", None)
            or (o.get("relationship_type") if isinstance(o, dict) else None)
        )
        == "based-on"
    ]
    assert len(based_on_rels) == 1, "Expected 1 based-on relationship"


# ==============================================================================
# P1 R9 — Bundle completeness: all referenced markings and author included
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_bundle_includes_all_referenced_markings_and_author(mock_helper_cls):
    """P1 R9: STIX bundle contains the connector author identity and all basic TLP
    marking definitions so cleanup_inconsistent_bundle does not strip them."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.70",
        "fraud_score": 10,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.70"}

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.70",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Verify author is present in the bundle
    author_objs = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == connector.author.id
    ]
    assert len(author_objs) == 1, "Connector author identity must be present in bundle"

    # Verify all basic TLP marking definitions are present in the bundle
    from lamis_network.builder import _TLP_MAP

    bundle_ids = {
        getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
        for o in bundle_objs
    }
    for tlp_name, marking in _TLP_MAP.items():
        assert (
            marking.id in bundle_ids
        ), f"Marking definition for {tlp_name} ({marking.id}) missing from bundle"


# ==============================================================================
# P1 R9 — Indicator not created/overwritten if owned by another creator
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_indicator_not_created_if_owned_by_another_creator(mock_helper_cls):
    """P1 R9: When an IP has a high fraud score but an existing indicator is owned
    by an analyst or third party, Lamis Network must NOT overwrite it or emit a colliding ID.
    """
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    # High score (95) would normally trigger indicator creation
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.75",
        "fraud_score": 95,
        "is_vpn": True,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.75')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    # Indicator in OpenCTI owned by an analyst
    mock_helper.api.indicator.read.return_value = {
        "id": ind_id,
        "standard_id": ind_id,
        "name": "198.51.100.75",
        "created_by_ref": "identity--analyst-author",
        "createdBy": {"standard_id": "identity--analyst-author"},
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.75"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.75",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Colliding indicator must NOT have been emitted into the bundle
    colliding_inds = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == ind_id
    ]
    assert (
        len(colliding_inds) == 0
    ), "Third-party indicator was overwritten with a colliding indicator!"


# ==============================================================================
# P2 R9 — Retain location links for partial geo responses
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_partial_geo_retains_existing_location_links(mock_helper_cls):
    """P2 R9: When API returns partial geo data without country_code, existing
    located-at relationships from Lamis Network are retained rather than destroyed."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    # Partial geo data: country name only, missing country_code
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.85",
        "fraud_score": 10,
        "geo": {"country": "Germany"},
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    old_loc_id = "location--existing-country"
    existing_located_at = {
        "id": f"relationship--{uuid.uuid4()}",
        "type": "relationship",
        "relationship_type": "located-at",
        "source_ref": obs_id,
        "target_ref": old_loc_id,
        "created_by_ref": connector.author.id,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.85"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.85",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity, existing_located_at],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Existing located-at relationship must be preserved in the bundle
    rel_ids = [
        getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
        for o in bundle_objs
    ]
    assert (
        existing_located_at["id"] in rel_ids
    ), "Existing located-at relationship was erroneously removed on partial geo data!"


# ==============================================================================
# P1 R9 — Prohibit direct API mutations outside bundle flow
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_no_direct_api_mutations_outside_bundle_flow(mock_helper_cls):
    """P1 R9: In accordance with docs/03-internal-enrichment-specifications.md:723-725,
    enrichment is delivered strictly via STIX bundle; no direct API deletions or mutations occur.
    """
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.90",
        "fraud_score": 10,
        "asn": {"asn": 13335, "name": "Cloudflare"},
        "geo": {"country": "Austria", "country_code": "AT"},
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.90"}

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.90",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    mock_helper.send_stix2_bundle.assert_called_once()
    mock_helper.api.stix_core_relationship.delete.assert_not_called()


# ==============================================================================
# Round 11 Tests — Fail closed, passthrough markings, relationship retirement
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_indicator_not_created_when_ownership_check_raises_exception(
    mock_helper_cls,
):
    """[P1] R11: When indicator ownership verification raises an exception,
    the connector fails closed and skips creating the indicator to prevent
    overwriting third-party indicators.
    """
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }
    # Ownership check raises an error (API unreachable, network timeout, etc.)
    mock_helper.api.indicator.read.side_effect = Exception(
        "OpenCTI GraphQL connection timeout"
    )

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.95",
        "fraud_score": 95,
        "is_vpn": True,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.95"}

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.95",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.95')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    # Indicator must NOT be in bundle because ownership verification failed closed
    ind_in_bundle = any(
        (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == ind_id
        for o in bundle_objs
    )
    assert (
        not ind_in_bundle
    ), "Indicator was created despite ownership check exception (did not fail closed)!"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_passthrough_bundles_preserve_markings_without_cleanup(mock_helper_cls):
    """[P2] R11: Pass-through bundles (TLP skip, invalid response, unsupported type)
    must be sent with cleanup_inconsistent_bundle=False so that platform markings
    are never stripped.
    """
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = False
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    stix_objects = [
        {
            "id": obs_id,
            "type": "ipv4-addr",
            "value": "198.51.100.96",
            "object_marking_refs": ["marking-definition--custom-red"],
        }
    ]

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.96",
            },
            "stix_objects": stix_objects,
        }
    )
    assert "skipped" in result
    mock_helper.send_stix2_bundle.assert_called_once()
    _, kwargs = mock_helper.send_stix2_bundle.call_args
    assert (
        kwargs.get("cleanup_inconsistent_bundle") is False
    ), "Pass-through bundle must have cleanup_inconsistent_bundle=False!"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_obsolete_relationships_retired_and_deleted_from_opencti(
    mock_helper_cls,
):
    """[P2] R11: When an observable is re-enriched with changed ASN or location,
    or when an indicator is revoked, obsolete persisted relationships in OpenCTI
    are queried via api.stix_core_relationship.list and deleted via
    api.stix_core_relationship.delete.
    """
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    author_id = connector.author.id

    old_asn_rel_id = f"relationship--{uuid.uuid4()}"
    mock_asn_rel = {
        "id": old_asn_rel_id,
        "standard_id": old_asn_rel_id,
        "relationship_type": "belongs-to",
        "createdBy": {"standard_id": author_id},
        "from": {"standard_id": obs_id},
        "to": {"standard_id": "autonomous-system--old-asn"},
    }

    mock_helper.api.stix_core_relationship.list.side_effect = lambda **kwargs: (
        [mock_asn_rel] if kwargs.get("relationship_type") == "belongs-to" else []
    )
    # Re-enriching with a new ASN (65001)
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.97",
        "fraud_score": 10,
        "asn": {"asn": 65001, "name": "New ASN"},
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.97"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.97",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    mock_helper.send_stix2_bundle.assert_called_once()
    _, kwargs = mock_helper.send_stix2_bundle.call_args
    assert (
        kwargs.get("cleanup_inconsistent_bundle") is False
    ), "Enriched bundle must be sent with cleanup_inconsistent_bundle=False!"

    # Obsolete relationship must be retired in the bundle with stop_time set, NOT deleted directly via API
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    retired_rel = next(
        (
            o
            for o in bundle_objs
            if (
                getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
            )
            == old_asn_rel_id
        ),
        None,
    )
    assert (
        retired_rel is not None
    ), "Obsolete belongs-to relationship was not included in bundle for retirement!"
    stop_time = getattr(retired_rel, "stop_time", None) or (
        retired_rel.get("stop_time") if isinstance(retired_rel, dict) else None
    )
    assert stop_time is not None, "Retired relationship must have stop_time set!"
    mock_helper.api.stix_core_relationship.delete.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_changed_geo_deletes_old_located_at_in_opencti(mock_helper_cls):
    """[P1/P2] R11: When an observable is re-enriched with a new location,
    obsolete located-at relationships pointing to old locations are retired
    with stop_time in the bundle rather than deleted via separate immediate API calls.
    """
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    author_id = connector.author.id

    old_geo_rel_id = f"relationship--{uuid.uuid4()}"
    mock_geo_rel = {
        "id": old_geo_rel_id,
        "standard_id": old_geo_rel_id,
        "relationship_type": "located-at",
        "createdBy": {"standard_id": author_id},
        "from": {"standard_id": obs_id},
        "to": {"standard_id": "location--old-country"},
    }

    mock_helper.api.stix_core_relationship.list.side_effect = lambda **kwargs: (
        [mock_geo_rel] if kwargs.get("relationship_type") == "located-at" else []
    )
    # Re-enriching with France
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.98",
        "fraud_score": 10,
        "geo": {"country": "France", "country_code": "FR"},
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.98"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.98",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    mock_helper.send_stix2_bundle.assert_called_once()

    # The obsolete located-at relationship must be retired in the bundle
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    retired_rel = next(
        (
            o
            for o in bundle_objs
            if (
                getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
            )
            == old_geo_rel_id
        ),
        None,
    )
    assert (
        retired_rel is not None
    ), "Obsolete located-at relationship was not included in bundle for retirement!"
    stop_time = getattr(retired_rel, "stop_time", None) or (
        retired_rel.get("stop_time") if isinstance(retired_rel, dict) else None
    )
    assert (
        stop_time is not None
    ), "Retired located-at relationship must have stop_time set!"
    mock_helper.api.stix_core_relationship.delete.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_revoked_indicator_deletes_based_on_relationship_in_opencti(
    mock_helper_cls,
):
    """[P1/P2] R11: When an indicator is revoked due to low risk score,
    the obsolete based-on relationship between the indicator and the observable
    is retired in the bundle with stop_time set rather than deleted via separate API mutation.
    """
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    author_id = connector.author.id

    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.99')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    mock_helper.api.indicator.read.return_value = {
        "id": ind_id,
        "standard_id": ind_id,
        "createdBy": {"standard_id": author_id},
    }

    old_based_on_rel_id = f"relationship--{uuid.uuid4()}"
    mock_based_on_rel = {
        "id": old_based_on_rel_id,
        "standard_id": old_based_on_rel_id,
        "relationship_type": "based-on",
        "createdBy": {"standard_id": author_id},
        "from": {"standard_id": ind_id},
        "to": {"standard_id": obs_id},
    }

    mock_helper.api.stix_core_relationship.list.side_effect = lambda **kwargs: (
        [mock_based_on_rel] if kwargs.get("relationship_type") == "based-on" else []
    )
    # Score drops to 10 (below threshold 75)
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.99",
        "fraud_score": 10,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.99"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.99",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    mock_helper.send_stix2_bundle.assert_called_once()

    # The based-on relationship must be retired in the bundle with stop_time set
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    retired_rel = next(
        (
            o
            for o in bundle_objs
            if (
                getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
            )
            == old_based_on_rel_id
        ),
        None,
    )
    assert (
        retired_rel is not None
    ), "Obsolete based-on relationship was not included in bundle for retirement!"
    stop_time = getattr(retired_rel, "stop_time", None) or (
        retired_rel.get("stop_time") if isinstance(retired_rel, dict) else None
    )
    assert (
        stop_time is not None
    ), "Retired based-on relationship must have stop_time set!"
    mock_helper.api.stix_core_relationship.delete.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_enriched_bundle_preserves_non_tlp_markings(mock_helper_cls):
    """[P1] R11: Enriched bundles include non-TLP markings (e.g. PAP) from OpenCTI
    and send with cleanup_inconsistent_bundle=False to prevent stripping.
    """
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    # Simulate PAP marking definition in OpenCTI platform
    pap_id = f"marking-definition--{uuid.uuid4()}"
    mock_helper.api.marking_definition.read.return_value = {
        "id": pap_id,
        "definition_type": "statement",
        "definition": "PAP:AMBER",
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.100",
        "fraud_score": 10,
        "asn": {"asn": 15169, "name": "Google LLC"},
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    stix_entity = {
        "type": "ipv4-addr",
        "id": obs_id,
        "value": "198.51.100.100",
        "object_marking_refs": [pap_id],
    }

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.100",
                "object_marking_refs": [pap_id],
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    mock_helper.send_stix2_bundle.assert_called_once()
    _, kwargs = mock_helper.send_stix2_bundle.call_args
    assert kwargs.get("cleanup_inconsistent_bundle") is False

    # The PAP marking definition must be added to the bundle
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    pap_in_bundle = any(
        (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == pap_id
        for o in bundle_objs
    )
    assert pap_in_bundle, "PAP marking definition was not attached to bundle!"

    # P2 R12: Default TLP must also be applied when source has only non-TLP markings
    from lamis_network.builder import _TLP_MAP

    clear_id = _TLP_MAP["TLP:CLEAR"].id
    clear_in_bundle = any(
        (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == clear_id
        for o in bundle_objs
    )
    assert (
        clear_in_bundle
    ), "Default TLP was not applied to bundle when observable has only non-TLP markings!"


# ==============================================================================
# Round 12 Tests — Unowned indicator conflict & non-TLP default marking
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_indicator_not_created_when_existing_indicator_has_no_creator(mock_helper_cls):
    """[P1] R12: When an indicator with matching pattern exists in OpenCTI or bundle
    but its createdBy is unset/null, treat it as a conflict and do NOT overwrite it.
    """
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.105",
        "fraud_score": 95,
        "is_vpn": True,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.105')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    # Existing indicator in OpenCTI with NO creator (createdBy is None / unset)
    mock_helper.api.indicator.read.return_value = {
        "id": ind_id,
        "standard_id": ind_id,
        "name": "198.51.100.105",
        "createdBy": None,
        "created_by_ref": None,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.105"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.105",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Colliding indicator must NOT have been emitted into the bundle
    colliding_inds = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == ind_id
    ]
    assert (
        len(colliding_inds) == 0
    ), "Unowned indicator without creator was overwritten with a colliding indicator!"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_indicator_not_created_when_in_bundle_indicator_has_no_creator(
    mock_helper_cls,
):
    """[P1] R12: When an indicator with matching pattern exists in the in-memory bundle
    with no created_by_ref, treat it as a conflict and do NOT overwrite it.
    """
    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.106",
        "fraud_score": 95,
        "is_vpn": True,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.106')}']"
    ind_id = PyctiIndicator.generate_id(pattern)

    # In-memory bundle contains an indicator with no created_by_ref
    unowned_indicator = {
        "id": ind_id,
        "type": "indicator",
        "name": "198.51.100.106",
        "pattern": pattern,
        "created_by_ref": None,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.106"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.106",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity, unowned_indicator],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Verify connector did not emit a replacement indicator claiming authorship
    author_indicators = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == ind_id
        and (
            getattr(o, "created_by_ref", None)
            or (o.get("created_by_ref") if isinstance(o, dict) else None)
        )
        == connector.author.id
    ]
    assert (
        len(author_indicators) == 0
    ), "Connector should not overwrite an unowned indicator in bundle!"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_re_enrichment_preserves_indicator_valid_from_in_bundle(mock_helper_cls):
    """[P2] R14: Re-enrichment with high score preserves valid_from of indicator in bundle."""
    from datetime import datetime, timezone

    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.110",
        "fraud_score": 90,
        "is_vpn": True,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.110')}']"
    ind_id = PyctiIndicator.generate_id(pattern)
    original_valid_from = "2024-01-15T10:30:00.000Z"

    existing_indicator = {
        "id": ind_id,
        "type": "indicator",
        "name": "198.51.100.110",
        "pattern": pattern,
        "created_by_ref": connector.author.id,
        "valid_from": original_valid_from,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.110"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.110",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity, existing_indicator],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    emitted_inds = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == ind_id
    ]
    assert len(emitted_inds) == 1
    vf = getattr(emitted_inds[0], "valid_from", None) or emitted_inds[0].get(
        "valid_from"
    )
    expected_dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    if isinstance(vf, datetime):
        assert vf == expected_dt
    else:
        assert "2024-01-15T10:30:00" in str(vf)


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_re_enrichment_preserves_indicator_valid_from_from_opencti_api(mock_helper_cls):
    """[P2] R14: Re-enrichment with high score preserves valid_from when indicator fetched from OpenCTI API."""
    from datetime import datetime, timezone

    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.111",
        "fraud_score": 90,
        "is_vpn": True,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.111')}']"
    ind_id = PyctiIndicator.generate_id(pattern)
    original_valid_from = "2023-11-20T08:15:30.000Z"

    mock_helper.api.indicator.read.return_value = {
        "id": ind_id,
        "standard_id": ind_id,
        "name": "198.51.100.111",
        "created_by_ref": connector.author.id,
        "createdBy": {"standard_id": connector.author.id},
        "valid_from": original_valid_from,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.111"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.111",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    emitted_inds = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == ind_id
    ]
    assert len(emitted_inds) == 1
    vf = getattr(emitted_inds[0], "valid_from", None) or emitted_inds[0].get(
        "valid_from"
    )
    expected_dt = datetime(2023, 11, 20, 8, 15, 30, tzinfo=timezone.utc)
    if isinstance(vf, datetime):
        assert vf == expected_dt
    else:
        assert "2023-11-20T08:15:30" in str(vf)


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_revoke_indicator_preserves_valid_from_from_opencti_api(mock_helper_cls):
    """[P2] R14: Revoking an indicator fetched via OpenCTI API preserves its original valid_from."""
    from datetime import datetime, timezone

    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.112",
        "fraud_score": 10,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.112')}']"
    ind_id = PyctiIndicator.generate_id(pattern)
    original_valid_from = "2022-05-10T14:00:00.000Z"

    mock_helper.api.indicator.read.return_value = {
        "id": ind_id,
        "standard_id": ind_id,
        "name": "198.51.100.112",
        "created_by_ref": connector.author.id,
        "createdBy": {"standard_id": connector.author.id},
        "valid_from": original_valid_from,
    }
    mock_helper.api.stix_core_relationship.list.return_value = []

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.112"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.112",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    emitted_inds = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == ind_id
    ]
    assert len(emitted_inds) == 1
    revoked = emitted_inds[0]
    vf = getattr(revoked, "valid_from", None) or revoked.get("valid_from")
    expected_dt = datetime(2022, 5, 10, 14, 0, 0, tzinfo=timezone.utc)
    if isinstance(vf, datetime):
        assert vf == expected_dt
    else:
        assert "2022-05-10T14:00:00" in str(vf)
    vu = getattr(revoked, "valid_until", None) or revoked.get("valid_until")
    assert vu is not None


def test_description_asn_prefix_not_doubled():
    """[P3] R14: ASN description formatting strips 'AS' prefix and avoids 'ASAS13335'."""
    connector = LamisNetworkConnector(config=MagicMock(), helper=MagicMock())

    # Case 1: String with 'AS' prefix
    desc1 = connector._format_description(
        "1.1.1.1",
        {"asn": {"asn": "AS13335", "name": "Cloudflare, Inc."}},
        85,
    )
    assert "- **Autonomous System:** `AS13335` (Cloudflare, Inc.)" in desc1
    assert "ASAS" not in desc1

    # Case 2: String with lowercase 'as' prefix
    desc2 = connector._format_description(
        "1.1.1.1",
        {"asn": {"asn": "as13335", "name": "Cloudflare, Inc."}},
        85,
    )
    assert "- **Autonomous System:** `AS13335` (Cloudflare, Inc.)" in desc2
    assert "asAS" not in desc2
    assert "ASas" not in desc2

    # Case 3: Integer ASN
    desc3 = connector._format_description(
        "1.1.1.1",
        {"asn": {"asn": 13335, "name": "Cloudflare, Inc."}},
        85,
    )
    assert "- **Autonomous System:** `AS13335` (Cloudflare, Inc.)" in desc3

    # Case 4: asn_number fallback with 'AS'
    desc4 = connector._format_description(
        "1.1.1.1",
        {"asn_number": "AS15169", "asn_name": "Google LLC"},
        85,
    )
    assert "- **Autonomous System:** `AS15169` (Google LLC)" in desc4
    assert "ASAS" not in desc4


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_preserve_city_links_when_geo_response_omits_city(mock_helper_cls):
    """[P2] R15: When an IP already has a city link and a subsequent API response
    supplies only country_code and country (omits city), retain the city link
    rather than retiring it.
    """
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    # Geo response supplies Germany without city
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.120",
        "fraud_score": 10,
        "geo": {"country": "Germany", "country_code": "DE"},
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    city_loc_id = "location--berlin"
    city_location = {
        "id": city_loc_id,
        "type": "location",
        "name": "Berlin",
        "city": "Berlin",
        "country": "DE",
        "custom_properties": {"x_opencti_location_type": "City"},
    }
    city_rel_id = f"relationship--{uuid.uuid4()}"
    existing_city_rel = {
        "id": city_rel_id,
        "type": "relationship",
        "relationship_type": "located-at",
        "source_ref": obs_id,
        "target_ref": city_loc_id,
        "created_by_ref": connector.author.id,
    }

    stix_entity = {"type": "ipv4-addr", "id": obs_id, "value": "198.51.100.120"}
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.120",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity, city_location, existing_city_rel],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]

    # Verify that the existing city relationship is NOT retired (not given stop_time)
    retired_city_rels = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == city_rel_id
        and (
            getattr(o, "stop_time", None)
            or (o.get("stop_time") if isinstance(o, dict) else None)
        )
    ]
    assert (
        len(retired_city_rels) == 0
    ), "Existing city relationship was erroneously retired on omitted city!"

    # Verify existing city relationship is retained in bundle
    retained_city_rels = [
        o
        for o in bundle_objs
        if (getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None))
        == city_rel_id
    ]
    assert (
        len(retained_city_rels) == 1
    ), "Existing city relationship was dropped from the bundle!"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_reconcile_stale_risk_labels_on_score_drop_and_flag_change(mock_helper_cls):
    """[P2] R15: Reconcile stale risk labels (suspicious, vpn, datacenter) when score
    drops below threshold and infrastructure flags change to false, while preserving
    analyst labels.
    """
    from pycti import STIX_EXT_OCTI_SCO

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.121",
        "fraud_score": 15,  # below suspicious_threshold (75)
        "is_vpn": False,
        "is_datacenter": False,
        "is_proxy": False,
        "is_tor": False,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    stix_entity = {
        "type": "ipv4-addr",
        "id": obs_id,
        "value": "198.51.100.121",
        "x_lamis_network_labels": ["vpn", "suspicious", "datacenter"],
        "extensions": {
            STIX_EXT_OCTI_SCO: {
                "extension_type": "property-extension",
                "labels": ["custom-analyst-tag", "vpn", "suspicious", "datacenter"],
                "x_lamis_network_labels": ["vpn", "suspicious", "datacenter"],
            }
        },
    }

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.121",
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    enriched = next(
        (o for o in bundle_objs if (getattr(o, "id", None) or o.get("id")) == obs_id),
        None,
    )
    assert enriched is not None
    ext = (
        (enriched if isinstance(enriched, dict) else dict(enriched))
        .get("extensions", {})
        .get(STIX_EXT_OCTI_SCO, {})
    )
    labels = ext.get("labels", [])

    # Analyst label must be preserved
    assert "custom-analyst-tag" in labels, f"Analyst label was lost: {labels}"

    # Stale connector labels must be reconciled out
    assert "vpn" not in labels, f"Stale 'vpn' label was retained: {labels}"
    assert (
        "suspicious" not in labels
    ), f"Stale 'suspicious' label was retained: {labels}"
    assert (
        "datacenter" not in labels
    ), f"Stale 'datacenter' label was retained: {labels}"


# ==============================================================================
# Round 16 / 17: P2 fixes
# 1. Preserve analyst labels sharing connector names when untracked
# 2. Retain infrastructure labels when flags are omitted
# 3. Avoid replacing named country with code-only location
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_preserve_analyst_labels_sharing_connector_names(mock_helper_cls):
    """[P2] R16: Analyst labels that share names with connector-managed labels
    (e.g., 'vpn', 'suspicious') must NOT be stripped when connector evaluates
    them to False, if the connector did not previously track them."""
    from pycti import STIX_EXT_OCTI_SCO

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.50",
        "fraud_score": 10,  # below suspicious threshold
        "is_vpn": False,
        "is_datacenter": False,
        "is_proxy": False,
        "is_tor": False,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    # Analyst manually added 'vpn' and 'suspicious' prior to connector run.
    # Note that x_lamis_network_labels is absent.
    stix_entity = {
        "type": "ipv4-addr",
        "id": obs_id,
        "value": "198.51.100.50",
        "extensions": {
            STIX_EXT_OCTI_SCO: {
                "extension_type": "property-extension",
                "labels": ["analyst-note", "vpn", "suspicious"],
            }
        },
    }

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.50",
            },
            "stix_entity": stix_entity,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    enriched = next(
        (o for o in bundle_objs if (getattr(o, "id", None) or o.get("id")) == obs_id),
        None,
    )
    assert enriched is not None
    ext = (
        (enriched if isinstance(enriched, dict) else dict(enriched))
        .get("extensions", {})
        .get(STIX_EXT_OCTI_SCO, {})
    )
    labels = ext.get("labels", [])

    # All analyst labels must be preserved intact!
    assert "analyst-note" in labels
    assert "vpn" in labels
    assert "suspicious" in labels


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_retain_infrastructure_labels_when_flags_omitted(mock_helper_cls):
    """[P2] R16: Partial API responses (e.g. /v1/score fallback) that omit
    infrastructure flags must retain previously applied connector labels,
    rather than treating omitted flags as False."""
    from pycti import STIX_EXT_OCTI_SCO

    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    # Partial score-only response (omitting is_vpn, is_datacenter, etc.)
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.60",
        "fraud_score": 25,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    # Entity was previously enriched and tracked 'vpn' and 'datacenter'
    stix_entity = {
        "type": "ipv4-addr",
        "id": obs_id,
        "value": "198.51.100.60",
        "x_lamis_network_labels": ["vpn", "datacenter"],
        "extensions": {
            STIX_EXT_OCTI_SCO: {
                "extension_type": "property-extension",
                "labels": ["custom-analyst-tag", "vpn", "datacenter"],
                "x_lamis_network_labels": ["vpn", "datacenter"],
            }
        },
    }

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.60",
            },
            "stix_entity": stix_entity,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    enriched = next(
        (o for o in bundle_objs if (getattr(o, "id", None) or o.get("id")) == obs_id),
        None,
    )
    assert enriched is not None
    ext = (
        (enriched if isinstance(enriched, dict) else dict(enriched))
        .get("extensions", {})
        .get(STIX_EXT_OCTI_SCO, {})
    )
    labels = ext.get("labels", [])

    # Infrastructure labels must be retained because flags were omitted, not False
    assert "custom-analyst-tag" in labels
    assert "vpn" in labels
    assert "datacenter" in labels
    tracked_after = enriched.get("x_lamis_network_labels", [])
    assert "vpn" in tracked_after
    assert "datacenter" in tracked_after


def test_code_only_country_preserves_existing_named_country(
    mock_helper, dummy_author, dummy_observable
):
    """[P2] R16: A partial or code-only country response (e.g. country_code='AT'
    without country_name) must resolve the full country name ('Austria') and
    preserve the existing located-at relationship rather than creating a duplicate 'AT'.
    """
    from pycti import Location as PyctiLocation

    obs_id = dummy_observable["standard_id"]
    austria_id = PyctiLocation.generate_id("Austria", "Country")
    at_code_id = PyctiLocation.generate_id("AT", "Country")

    # Observable has an existing relationship to Austria
    existing_country = {
        "type": "location",
        "id": austria_id,
        "name": "Austria",
        "country": "AT",
        "x_opencti_location_type": "Country",
    }
    existing_rel = {
        "type": "relationship",
        "id": f"relationship--{uuid.uuid4()}",
        "relationship_type": "located-at",
        "source_ref": obs_id,
        "target_ref": austria_id,
        "created_by_ref": dummy_author.id,
    }

    builder = LamisNetworkBuilder(
        mock_helper,
        dummy_author,
        dummy_observable,
        stix_objects=[existing_country, existing_rel],
    )

    # API returns only country_code 'AT' (no country_name)
    builder.add_geolocation({"country_code": "AT"})

    locations = [
        o
        for o in builder.bundle
        if (getattr(o, "type", None) or o.get("type")) == "location"
    ]
    # Check that location name is 'Austria', not 'AT'
    assert len(locations) == 1
    loc = locations[0]
    loc_name = getattr(loc, "name", None) or loc.get("name")
    loc_id = getattr(loc, "id", None) or loc.get("id")
    assert loc_name == "Austria"
    assert loc_id == austria_id
    assert loc_id != at_code_id

    # Check that retired relationships do not include austria_id
    retired_rels = [
        o
        for o in builder.bundle
        if (getattr(o, "type", None) or o.get("type")) == "relationship"
        and (getattr(o, "stop_time", None) or o.get("stop_time")) is not None
    ]
    for r in retired_rels:
        t_ref = getattr(r, "target_ref", None) or r.get("target_ref")
        assert t_ref != austria_id, "Relationship to Austria was incorrectly retired!"


def test_iso_3166_resolves_name_when_country_name_omitted(
    mock_helper, dummy_author, dummy_observable
):
    """[P2] R16: Even on first enrichment without prior links, a code-only
    country_code 'DE' resolves to 'Germany' via ISO 3166-1 alpha-2."""
    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    builder.add_geolocation({"country_code": "DE"})

    locations = [
        o
        for o in builder.bundle
        if (getattr(o, "type", None) or o.get("type")) == "location"
    ]
    assert len(locations) == 1
    loc = locations[0]
    loc_name = getattr(loc, "name", None) or loc.get("name")
    assert loc_name == "Germany"


def test_skip_location_retirement_when_target_discovery_fails(
    mock_helper, dummy_author, dummy_observable
):
    """[P2] R17: If target discovery fails due to OpenCTI API error,
    location relationship retirement must be skipped/aborted to preserve existing links.
    """
    mock_helper.api = MagicMock()
    mock_helper.api.stix_core_relationship.list.side_effect = Exception(
        "OpenCTI API timeout"
    )

    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    # add_geolocation receives a country-only response (city omitted)
    builder.add_geolocation({"country_code": "AT"})

    # Ensure no relationship is retired with stop_time
    retired_rels = [
        o
        for o in builder.bundle
        if (getattr(o, "type", None) or o.get("type")) == "relationship"
        and (getattr(o, "stop_time", None) or o.get("stop_time")) is not None
    ]
    assert (
        len(retired_rels) == 0
    ), "Retirement was executed despite target discovery failure!"

    # Ensure country location was still created
    locations = [
        o
        for o in builder.bundle
        if (getattr(o, "type", None) or o.get("type")) == "location"
    ]
    assert len(locations) == 1


def test_retirement_query_failure_raises_runtime_error(
    mock_helper, dummy_author, dummy_observable
):
    """[P2] R17: When OpenCTI's relationship-list request fails during retirement,
    it must retry and raise RuntimeError, failing the enrichment rather than silently
    completing an incomplete replacement."""
    mock_helper.api = MagicMock()
    mock_helper.api.stix_core_relationship.list.side_effect = Exception(
        "Database connection lost"
    )

    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    with pytest.raises(
        RuntimeError, match="Failed to query existing belongs-to relationships"
    ):
        builder.add_asn({"asn": 13335, "name": "Cloudflare"})


# ==============================================================================
# Round 18: P2 — Preserve existing labels on managed indicator
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_preserve_indicator_labels_when_flags_omitted(mock_helper_cls):
    """[P2] R18: When a previously created high-risk indicator is re-enriched
    from a score-only response that omits infrastructure flags, the indicator
    must retain its earlier vpn/datacenter labels rather than replacing them
    with only 'suspicious'."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    author_id = connector.author.id

    # Partial score-only response: omits is_vpn, is_datacenter, etc.
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.70",
        "fraud_score": 85,  # above suspicious_threshold
    }

    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.70')}']"
    indicator_id = PyctiIndicator.generate_id(pattern)

    # Simulate existing indicator in OpenCTI with vpn and datacenter labels
    mock_helper.api.indicator.read.return_value = {
        "id": indicator_id,
        "standard_id": indicator_id,
        "createdBy": {"standard_id": author_id, "id": author_id},
        "created_by_ref": author_id,
        "labels": ["vpn", "datacenter", "suspicious"],
        "x_lamis_network_labels": ["vpn", "datacenter", "suspicious"],
        "valid_from": "2026-01-01T00:00:00Z",
    }

    stix_entity = {
        "type": "ipv4-addr",
        "id": obs_id,
        "value": "198.51.100.70",
    }

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.70",
            },
            "stix_entity": stix_entity,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    indicators = [o for o in bundle_objs if getattr(o, "type", None) == "indicator"]
    assert len(indicators) == 1
    ind = indicators[0]
    ind_labels = list(ind.labels) if hasattr(ind, "labels") else []

    # Previously applied vpn & datacenter must be preserved (flags omitted, not False)
    assert "vpn" in ind_labels, f"'vpn' label was lost: {ind_labels}"
    assert "datacenter" in ind_labels, f"'datacenter' label was lost: {ind_labels}"
    assert "suspicious" in ind_labels, f"'suspicious' label was lost: {ind_labels}"

    # x_lamis_network_labels must track the active connector labels
    tracked = getattr(ind, "x_lamis_network_labels", None)
    assert tracked is not None, "x_lamis_network_labels missing from indicator"
    assert "vpn" in tracked
    assert "datacenter" in tracked
    assert "suspicious" in tracked


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_preserve_analyst_labels_on_indicator(mock_helper_cls):
    """[P2] R18: Analyst-added labels on an existing indicator must not be
    removed during re-enrichment. Only connector-managed labels explicitly
    evaluated as False may be removed."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    author_id = connector.author.id

    # Full response: vpn=False now, datacenter still True
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.71",
        "fraud_score": 90,
        "is_vpn": False,
        "is_datacenter": True,
        "is_proxy": False,
        "is_tor": False,
    }

    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.71')}']"
    indicator_id = PyctiIndicator.generate_id(pattern)

    # Existing indicator has analyst tag + vpn + datacenter + suspicious
    mock_helper.api.indicator.read.return_value = {
        "id": indicator_id,
        "standard_id": indicator_id,
        "createdBy": {"standard_id": author_id, "id": author_id},
        "created_by_ref": author_id,
        "labels": ["analyst-tagged", "vpn", "datacenter", "suspicious"],
        "x_lamis_network_labels": ["vpn", "datacenter", "suspicious"],
        "valid_from": "2026-01-01T00:00:00Z",
    }

    stix_entity = {
        "type": "ipv4-addr",
        "id": obs_id,
        "value": "198.51.100.71",
    }

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.71",
            },
            "stix_entity": stix_entity,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    indicators = [o for o in bundle_objs if getattr(o, "type", None) == "indicator"]
    assert len(indicators) == 1
    ind = indicators[0]
    ind_labels = list(ind.labels) if hasattr(ind, "labels") else []

    # Analyst label must survive
    assert "analyst-tagged" in ind_labels, f"Analyst label was lost: {ind_labels}"
    # datacenter is still True, suspicious is True (score 90 >= 75)
    assert "datacenter" in ind_labels, f"'datacenter' was lost: {ind_labels}"
    assert "suspicious" in ind_labels, f"'suspicious' was lost: {ind_labels}"
    # vpn was explicitly False — must be removed
    assert "vpn" not in ind_labels, f"Stale 'vpn' was retained: {ind_labels}"

    # Tracked labels must reflect current state (no vpn)
    tracked = getattr(ind, "x_lamis_network_labels", None)
    assert tracked is not None
    assert "vpn" not in tracked
    assert "datacenter" in tracked
    assert "suspicious" in tracked


# ==============================================================================
# Round 19: P2 — Preserve untracked analyst labels on indicator +
#                 Validate STIX entity before external API call
# ==============================================================================


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_preserve_untracked_analyst_labels_on_indicator(mock_helper_cls):
    """[P2] R19: When an existing Lamis-owned indicator has no
    x_lamis_network_labels metadata, analyst labels that share managed
    names (e.g. 'vpn') must NOT be removed even if the flag is False."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    author_id = connector.author.id

    # Full response: vpn=False now
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.72",
        "fraud_score": 85,
        "is_vpn": False,
        "is_datacenter": False,
        "is_proxy": False,
        "is_tor": False,
    }

    from lamis_network.builder import _stix_quote
    from pycti import Indicator as PyctiIndicator

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    pattern = f"[ipv4-addr:value = '{_stix_quote('198.51.100.72')}']"
    indicator_id = PyctiIndicator.generate_id(pattern)

    # Existing indicator has 'vpn' label but NO x_lamis_network_labels
    # (analyst-added or from pre-tracking era)
    mock_helper.api.indicator.read.return_value = {
        "id": indicator_id,
        "standard_id": indicator_id,
        "createdBy": {"standard_id": author_id, "id": author_id},
        "created_by_ref": author_id,
        "labels": ["vpn", "analyst-custom"],
    }

    stix_entity = {
        "type": "ipv4-addr",
        "id": obs_id,
        "value": "198.51.100.72",
    }

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.72",
            },
            "stix_entity": stix_entity,
        }
    )
    assert "Sent STIX bundle" in result
    bundle_objs = mock_helper.stix2_create_bundle.call_args[0][0]
    indicators = [o for o in bundle_objs if getattr(o, "type", None) == "indicator"]
    assert len(indicators) == 1
    ind = indicators[0]
    ind_labels = list(ind.labels) if hasattr(ind, "labels") else []

    # Both labels must be preserved — no tracking metadata means we cannot
    # claim ownership, even for managed-named labels.
    assert "vpn" in ind_labels, f"Untracked 'vpn' label was lost: {ind_labels}"
    assert "analyst-custom" in ind_labels, f"Analyst label was lost: {ind_labels}"
    assert "suspicious" in ind_labels, f"'suspicious' label missing: {ind_labels}"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_missing_stix_entity_raises_before_api_call(mock_helper_cls):
    """[P2] R19: When stix_entity is missing from the enrichment event,
    the connector must raise ValueError before calling the external API."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True

    connector = LamisNetworkConnector()
    connector.client = MagicMock()

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    with pytest.raises(ValueError, match="Missing stix_entity"):
        connector._process_message(
            {
                "enrichment_entity": {
                    "id": obs_id,
                    "standard_id": obs_id,
                    "entity_type": "IPv4-Addr",
                    "value": "198.51.100.80",
                },
            }
        )
    # External API must NOT have been called
    connector.client.get_ip_reputation.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_mismatched_stix_entity_value_raises_before_api_call(mock_helper_cls):
    """[P2] R19: When stix_entity.value differs from the enrichment_entity
    IP, the connector must raise ValueError before calling the external API."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True

    connector = LamisNetworkConnector()
    connector.client = MagicMock()

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    with pytest.raises(ValueError, match="does not match"):
        connector._process_message(
            {
                "enrichment_entity": {
                    "id": obs_id,
                    "standard_id": obs_id,
                    "entity_type": "IPv4-Addr",
                    "value": "198.51.100.80",
                },
                "stix_entity": {
                    "type": "ipv4-addr",
                    "id": obs_id,
                    "value": "10.0.0.1",  # Different IP!
                },
            }
        )
    # External API must NOT have been called
    connector.client.get_ip_reputation.assert_not_called()


# ==============================================================================
# Round 20: P1 & P2 Fixes
# 1. Pass scalar IDs to relationship list API
# 2. Fail closed on malformed STIX marking references
# 3. Normalize observable ID before querying
# 4. Require STIX type and value before querying
# 5. Compare parsed IP values rather than text
# ==============================================================================


def test_scalar_ids_passed_to_relationship_list_api(
    mock_helper, dummy_author, dummy_observable
):
    """[P1] R20: Verify that _retire_relationships calls PyCTI's
    stix_core_relationship.list with scalar strings for fromId/toId,
    never with lists."""
    mock_helper.api = MagicMock()
    mock_helper.api.stix_core_relationship.list.return_value = []

    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    # add_asn passes obs_identifiers (list with [standard_id, uuid])
    builder.add_asn({"asn": 13335, "name": "Cloudflare"})

    # Check all calls made to list()
    list_calls = mock_helper.api.stix_core_relationship.list.call_args_list
    assert len(list_calls) > 0
    for call in list_calls:
        kwargs = call[1]
        if "fromId" in kwargs:
            assert isinstance(
                kwargs["fromId"], str
            ), f"fromId was not scalar string: {kwargs['fromId']!r}"
        if "toId" in kwargs:
            assert isinstance(
                kwargs["toId"], str
            ), f"toId was not scalar string: {kwargs['toId']!r}"


def test_scalar_ids_passed_in_location_discovery(
    mock_helper, dummy_author, dummy_observable
):
    """[P1] R20: Verify that _find_existing_located_at_targets calls
    stix_core_relationship.list with scalar fromId."""
    mock_helper.api = MagicMock()
    mock_helper.api.stix_core_relationship.list.return_value = []

    builder = LamisNetworkBuilder(mock_helper, dummy_author, dummy_observable)
    obs_identifiers = [dummy_observable["standard_id"], dummy_observable["id"]]
    builder._find_existing_located_at_targets(obs_identifiers)

    list_calls = mock_helper.api.stix_core_relationship.list.call_args_list
    assert len(list_calls) == len(obs_identifiers)
    for call in list_calls:
        kwargs = call[1]
        assert isinstance(
            kwargs.get("fromId"), str
        ), f"fromId in location discovery was not scalar: {kwargs.get('fromId')!r}"


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_fail_closed_on_malformed_stix_marking_refs(mock_helper_cls):
    """[P2] R20: Reject malformed object_marking_refs on stix_entity before external API call."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True

    connector = LamisNetworkConnector()
    connector.client = MagicMock()

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    with pytest.raises(ValueError, match="Malformed object_marking_refs"):
        connector._process_message(
            {
                "enrichment_entity": {
                    "id": obs_id,
                    "standard_id": obs_id,
                    "entity_type": "IPv4-Addr",
                    "value": "198.51.100.80",
                },
                "stix_entity": {
                    "type": "ipv4-addr",
                    "id": obs_id,
                    "value": "198.51.100.80",
                    "object_marking_refs": "NOT_A_LIST",  # Malformed!
                },
            }
        )
    connector.client.get_ip_reputation.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_normalize_observable_id_when_standard_id_absent(mock_helper_cls):
    """[P2] R20: When enrichment_entity has id but no standard_id, normalize it
    so builder.enrich_observable succeeds without raising."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "198.51.100.81",
        "fraud_score": 10,
    }

    obs_id = f"ipv4-addr--{uuid.uuid4()}"
    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,  # No standard_id!
                "entity_type": "IPv4-Addr",
                "value": "198.51.100.81",
            },
            "stix_entity": {
                "type": "ipv4-addr",
                "id": obs_id,
                "value": "198.51.100.81",
            },
        }
    )
    assert "Sent STIX bundle" in result
    connector.client.get_ip_reputation.assert_called_once_with("198.51.100.81")


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_missing_stix_value_or_type_raises_before_api_call(mock_helper_cls):
    """[P2] R20: If stix_entity omits value or type, raise ValueError before querying."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True

    connector = LamisNetworkConnector()
    connector.client = MagicMock()

    obs_id = f"ipv4-addr--{uuid.uuid4()}"

    # Missing value
    with pytest.raises(ValueError, match="Missing or invalid 'value'"):
        connector._process_message(
            {
                "enrichment_entity": {
                    "id": obs_id,
                    "standard_id": obs_id,
                    "entity_type": "IPv4-Addr",
                    "value": "198.51.100.82",
                },
                "stix_entity": {
                    "type": "ipv4-addr",
                    "id": obs_id,
                    # value omitted!
                },
            }
        )
    connector.client.get_ip_reputation.assert_not_called()

    # Missing type
    with pytest.raises(ValueError, match="STIX entity type"):
        connector._process_message(
            {
                "enrichment_entity": {
                    "id": obs_id,
                    "standard_id": obs_id,
                    "entity_type": "IPv4-Addr",
                    "value": "198.51.100.82",
                },
                "stix_entity": {
                    "id": obs_id,
                    "value": "198.51.100.82",
                    # type omitted!
                },
            }
        )
    connector.client.get_ip_reputation.assert_not_called()


@patch("lamis_network.connector.OpenCTIConnectorHelper")
def test_equivalent_ipv6_spellings_accepted(mock_helper_cls):
    """[P2] R20: Different valid spellings of the same IPv6 address (expanded vs compressed)
    must be accepted via parsed IP comparison."""
    mock_helper = MagicMock()
    mock_helper_cls.return_value = mock_helper
    mock_helper_cls.check_max_tlp.return_value = True
    mock_helper.stix2_create_bundle.side_effect = lambda objs: {
        "type": "bundle",
        "objects": objs,
    }

    connector = LamisNetworkConnector()
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {
        "ip": "2001:db8::1",
        "fraud_score": 15,
    }

    obs_id = f"ipv6-addr--{uuid.uuid4()}"
    expanded_ip = "2001:0db8:0000:0000:0000:0000:0000:0001"
    compressed_ip = "2001:db8::1"

    result = connector._process_message(
        {
            "enrichment_entity": {
                "id": obs_id,
                "standard_id": obs_id,
                "entity_type": "IPv6-Addr",
                "value": expanded_ip,
            },
            "stix_entity": {
                "type": "ipv6-addr",
                "id": obs_id,
                "value": compressed_ip,
            },
        }
    )
    assert "Sent STIX bundle" in result
    connector.client.get_ip_reputation.assert_called_once_with(expanded_ip)
