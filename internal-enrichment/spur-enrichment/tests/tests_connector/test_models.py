from ipaddress import IPv4Address, IPv6Address

import pytest
from pydantic import ValidationError
from spur_client import IPContext, TagMetadata


def test_ip_context_should_accept_a_full_response():
    # Given a response with every documented field
    response = {
        "ip": "89.39.106.191",
        "as": {"number": 49981, "organization": "WorldStream B.V."},
        "organization": "WorldStream B.V.",
        "infrastructure": "DATACENTER",
        "location": {"city": "Amsterdam", "state": "North Holland", "country": "NL"},
        "risks": ["CALLBACK_PROXY", "TUNNEL"],
        "services": ["OPENVPN"],
        "tunnels": [
            {
                "anonymous": True,
                "entries": ["89.39.106.82"],
                "exits": [],
                "operator": "PROTON_VPN",
                "type": "VPN",
            }
        ],
        "client": {
            "behaviors": ["FILE_SHARING"],
            "concentration": {
                "city": "Naaldwijk",
                "country": "NL",
                "density": 1,
                "geohash": "u14zzc",
                "skew": 63,
                "state": "South Holland",
            },
            "count": 5,
            "countries": 1,
            "proxies": ["OXYLABS_PROXY"],
            "spread": 1500,
            "types": ["MOBILE", "DESKTOP"],
        },
        "ai": {"operator": "OPENAI", "types": ["CRAWLER"]},
    }

    # When validating it
    ip_context = IPContext.model_validate(response)

    # Then every field is typed
    assert ip_context.ip == IPv4Address("89.39.106.191")
    assert ip_context.autonomous_system.number == 49981
    assert ip_context.location.state == "North Holland"
    assert ip_context.tunnels[0].operator == "PROTON_VPN"
    assert ip_context.tunnels[0].anonymous is True
    assert ip_context.client.concentration.density == 1
    assert ip_context.client.proxies == ["OXYLABS_PROXY"]
    assert ip_context.ai.types == ["CRAWLER"]


def test_ip_context_should_accept_a_response_without_optional_fields():
    # Given an anycast IP: no client, no risks, no tunnels (e.g. 2606:4700:4700::1111)
    response = {
        "ip": "2606:4700:4700::1111",
        "as": {"number": 13335, "organization": "Cloudflare, Inc."},
        "infrastructure": "DATACENTER",
        "location": {"city": "Anycast", "country": "ZZ", "state": "Anycast"},
    }

    # When validating it
    ip_context = IPContext.model_validate(response)

    # Then the missing fields are empty
    assert ip_context.ip == IPv6Address("2606:4700:4700::1111")
    assert ip_context.client is None
    assert ip_context.risks == []
    assert ip_context.tunnels == []


def test_ip_context_should_accept_a_tunnel_without_entries_and_exits():
    # Given a Tor tunnel, which Spur returns without entries nor exits
    response = {
        "ip": "185.220.101.1",
        "tunnels": [{"anonymous": True, "operator": "TOR_PROXY", "type": "PROXY"}],
    }

    # When validating it
    ip_context = IPContext.model_validate(response)

    # Then the node lists are empty
    assert ip_context.tunnels[0].entries == []
    assert ip_context.tunnels[0].exits == []


def test_ip_context_should_accept_unknown_values_and_fields():
    # Given a response with a risk and a field unknown to the connector
    response = {"ip": "1.2.3.4", "risks": ["NEW_RISK"], "new_field": {"a": 1}}

    # When validating it
    ip_context = IPContext.model_validate(response)

    # Then the new value is kept and the unknown field ignored
    assert ip_context.risks == ["NEW_RISK"]
    assert not hasattr(ip_context, "new_field")


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({}, id="missing_ip"),
        pytest.param({"ip": "not-an-ip"}, id="invalid_ip"),
        pytest.param({"ip": "1.2.3.4", "as": {"number": "AS123"}}, id="invalid_as"),
        pytest.param({"ip": "1.2.3.4", "risks": "TUNNEL"}, id="risks_not_a_list"),
        pytest.param(
            {"ip": "1.2.3.4", "tunnels": [{"anonymous": "maybe"}]},
            id="invalid_anonymous",
        ),
        pytest.param(
            {"ip": "1.2.3.4", "client": {"count": "many"}}, id="invalid_client_count"
        ),
    ],
)
def test_ip_context_should_reject_an_invalid_response(response):
    with pytest.raises(ValidationError):
        IPContext.model_validate(response)


def test_tag_metadata_should_accept_a_full_response():
    # Given a tag metadata response with camelCase fields (trimmed real response)
    response = {
        "tag": "OXYLABS_PROXY",
        "name": "Oxylabs",
        "description": "Oxylabs is the second largest proxy provider tracked.",
        "allTags": ["OXYLABS_PROXY"],
        "categories": ["RESIDENTIAL_PROXY", "ISP_PROXY"],
        "isAnonymous": True,
        "isCallbackProxy": True,
        "isNoLog": True,
        "isTracked": True,
        "allowsWhiteLabel": True,
        "maxAgeDays": 3,
        "metrics": {"distinctIPs": 11230722, "churnRate": 0.0856},
        "platforms": ["ROUTER"],
        "protocols": ["HTTP", "SOCKS"],
        "resoldBy": ["SMARTPROXY_PROXY"],
        "resells": [{"tag": "OTHER_PROXY", "products": ["RESIDENTIAL"]}],
        "targetingTypes": ["CITY", "ASN"],
    }

    # When validating it
    metadata = TagMetadata.model_validate(response)

    # Then every field is typed, with snake_case names
    assert metadata.tag == "OXYLABS_PROXY"
    assert metadata.categories == ["RESIDENTIAL_PROXY", "ISP_PROXY"]
    assert metadata.is_callback_proxy is True
    assert metadata.allows_white_label is True
    assert metadata.max_age_days == 3
    assert metadata.metrics == {"distinctIPs": 11230722, "churnRate": 0.0856}
    assert metadata.resold_by == ["SMARTPROXY_PROXY"]
    assert metadata.resells[0].products == ["RESIDENTIAL"]
    assert metadata.targeting_types == ["CITY", "ASN"]


def test_tag_metadata_should_accept_a_response_without_optional_fields():
    # Given a response with only the tag (Spur omits fields its doc marks as required)
    metadata = TagMetadata.model_validate({"tag": "PROTON_VPN"})

    # Then the missing fields are empty
    assert metadata.description is None
    assert metadata.website is None
    assert metadata.categories == []
    assert metadata.metrics == {}


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({"name": "Proton VPN"}, id="missing_tag"),
        pytest.param({"tag": "X", "categories": "VPN"}, id="categories_not_a_list"),
        pytest.param({"tag": "X", "isNoLog": "maybe"}, id="invalid_boolean"),
        pytest.param({"tag": "X", "metrics": {"distinctIPs": "many"}}, id="bad_metric"),
    ],
)
def test_tag_metadata_should_reject_an_invalid_response(response):
    with pytest.raises(ValidationError):
        TagMetadata.model_validate(response)
