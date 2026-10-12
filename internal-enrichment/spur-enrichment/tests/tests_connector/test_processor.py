from unittest.mock import MagicMock

import pytest
import requests
from connector import SpurIPProcessor
from connectors_sdk import ApiUnauthorizedError, EnrichmentMessage
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import IPV4Address, IPV6Address
from pydantic import ValidationError
from spur_client import IPContext, SpurClient

IP_CONTEXT = {
    "ip": "89.39.106.191",
    "as": {"number": 49981, "organization": "WorldStream B.V."},
    "organization": "Proton AG",
    "infrastructure": "DATACENTER",
    "location": {"city": "Amsterdam", "state": "North Holland", "country": "NL"},
    "risks": ["CALLBACK_PROXY", "TUNNEL", "GEO_MISMATCH"],
    "services": ["OPENVPN", "IPSEC"],
    "tunnels": [
        {
            "type": "VPN",
            "operator": "PROTON_VPN",
            "anonymous": True,
            "entries": ["1.1.1.1"],
            "exits": ["89.39.106.191"],
        }
    ],
    "client": {
        "behaviors": ["TOR_PROXY_USER"],
        "concentration": {
            "city": "Paris",
            "state": "Ile-de-France",
            "country": "FR",
            "density": 0.42,
            "geohash": "u09t",
            "skew": 430,
        },
        "count": 12,
        "countries": 3,
        "proxies": ["NETNUT_PROXY"],
        "spread": 1500,
        "types": ["DESKTOP", "MOBILE"],
    },
    "ai": {"operator": "OPENAI", "types": ["CRAWLER"]},
}


@pytest.fixture
def processor(settings) -> SpurIPProcessor:
    processor = SpurIPProcessor()
    processor.inject_dependencies(settings=settings, helper=MagicMock())
    processor.post_init()
    processor.client = MagicMock(spec=SpurClient)
    return processor


def _make_message(
    value: str = "89.39.106.191",
    entity_type: str = "IPv4-Addr",
    entity_id: str | None = None,
    **extra,
) -> EnrichmentMessage:
    ip_class = IPV6Address if entity_type == "IPv6-Addr" else IPV4Address
    stix_entity = {
        "type": entity_type.lower(),
        "id": entity_id or ip_class(value=value).id,
        "value": value,
        **extra,
    }
    return EnrichmentMessage(
        entity_id=stix_entity["id"],
        enrichment_entity={"entity_type": entity_type, "objectMarking": []},
        stix_entity=stix_entity,
        stix_objects=[stix_entity],
        is_playbook=False,
    )


def _context(data: dict) -> IPContext:
    """Validate a Spur response, the IP being optional in tests."""
    return IPContext.model_validate({"ip": "89.39.106.191", **data})


def _by_type(objects: list) -> dict[str, list[dict]]:
    stix_objects: dict[str, list[dict]] = {}
    for obj in objects:
        stix_object = obj.to_stix2_object()
        stix_objects.setdefault(stix_object["type"], []).append(stix_object)
    return stix_objects


def _links(stix_objects: dict[str, list[dict]], relationship_type: str) -> list[tuple]:
    return [
        (rel["source_ref"], rel["target_ref"])
        for rel in stix_objects.get("relationship", [])
        if rel["relationship_type"] == relationship_type
    ]


# ----------------------------------------------------------------------
# collect()
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, queried_ip",
    [
        ("1.2.3.4", "1.2.3.4"),
        ("1.2.3.4/32", "1.2.3.4"),
        ("2001:db8::1/128", "2001:db8::1"),
    ],
)
def test_collect_should_query_a_single_ip(processor, value, queried_ip):
    # Given an IP, with or without a single-address CIDR
    ip_context = IPContext(ip=queried_ip)
    processor.client.get_ip_context.return_value = ip_context

    # When collecting
    data = processor.collect(_make_message(value, entity_id="ipv4-addr--test"))

    # Then Spur is queried with the bare IP
    processor.client.get_ip_context.assert_called_once_with(queried_ip)
    assert data == ip_context


@pytest.mark.parametrize("value", ["1.2.3.0/24", "not-an-ip"])
def test_collect_should_skip_networks_and_invalid_values(processor, value):
    # Given a network or an invalid value
    message = _make_message(value, entity_id="ipv4-addr--test")

    # When collecting
    data = processor.collect(message)

    # Then Spur is not queried
    processor.client.get_ip_context.assert_not_called()
    assert data is None


def test_collect_should_return_none_when_spur_rejects_the_ip(processor):
    # Given Spur rejects the IP
    processor.client.get_ip_context.return_value = None

    # When / Then nothing is collected
    assert processor.collect(_make_message("1.2.3.4")) is None


@pytest.mark.parametrize(
    "error",
    [ApiUnauthorizedError("Unauthorized"), requests.ConnectionError("down")],
)
def test_collect_should_raise_data_retrieval_error_on_api_failure(processor, error):
    # Given the Spur API fails
    processor.client.get_ip_context.side_effect = error

    # When / Then a DataRetrievalError is raised from the original error
    with pytest.raises(DataRetrievalError) as exc_info:
        processor.collect(_make_message("1.2.3.4"))
    assert exc_info.value.__cause__ is error


def test_collect_should_raise_data_retrieval_error_on_invalid_response(processor):
    # Given Spur returns a response that is not a valid IP context
    processor.client.get_ip_context.side_effect = lambda ip: IPContext.model_validate(
        {"ip": ip, "as": {"number": "not-a-number"}}
    )

    # When / Then a DataRetrievalError is raised from the validation error
    with pytest.raises(DataRetrievalError) as exc_info:
        processor.collect(_make_message("1.2.3.4"))
    assert isinstance(exc_info.value.__cause__, ValidationError)


# ----------------------------------------------------------------------
# transform()
# ----------------------------------------------------------------------


def test_transform_should_return_nothing_without_data(processor):
    assert processor.transform(None, _make_message()) == []


def test_transform_should_enrich_the_ip_with_labels_and_score(processor):
    # Given a full Spur IP context
    message = _make_message()

    # When transforming
    objects = processor.transform(_context(IP_CONTEXT), message)

    # Then the enriched IP keeps its id, with the Spur labels and score
    ip = _by_type(objects)["ipv4-addr"][0]
    assert ip["id"] == message.entity_id
    assert ip["x_opencti_score"] == 75
    assert ip["x_opencti_labels"] == [
        "spur-tunnel-type:vpn",
        "spur-tunnel-anonymous:true",
        "spur-risk:callback_proxy",
        "spur-risk:tunnel",
        "spur-risk:geo_mismatch",
        "spur-service:openvpn",
        "spur-service:ipsec",
        "spur-infrastructure:datacenter",
        "spur-behavior:tor_proxy_user",
        "spur-client-type:desktop",
        "spur-client-type:mobile",
        "spur-ai-type:crawler",
    ]
    # Neither author nor marking: those of the existing entity are kept
    assert "x_opencti_created_by_ref" not in ip
    assert "object_marking_refs" not in ip


def test_transform_should_link_the_ip_to_its_spur_page(processor):
    objects = processor.transform(_context({}), _make_message())

    ip = _by_type(objects)["ipv4-addr"][0]
    assert ip["x_opencti_external_references"] == [
        {
            "source_name": "Spur",
            "description": "Spur IP context",
            "url": "https://spur.us/context/89.39.106.191",
        }
    ]


def test_transform_should_keep_the_existing_labels(processor):
    message = _make_message(x_opencti_labels=["existing", "spur-risk:tunnel"])

    objects = processor.transform(_context({"risks": ["TUNNEL"]}), message)

    ip = _by_type(objects)["ipv4-addr"][0]
    assert ip["x_opencti_labels"] == ["existing", "spur-risk:tunnel"]


def test_transform_should_handle_ipv6(processor):
    message = _make_message("2001:db8::1", entity_type="IPv6-Addr")

    objects = processor.transform(_context({"ip": "2001:db8::1"}), message)

    assert _by_type(objects)["ipv6-addr"][0]["id"] == message.entity_id


@pytest.mark.parametrize(
    "ip_context, score",
    [
        pytest.param({}, None, id="no_risk"),
        pytest.param({"tunnels": [{"type": "VPN"}]}, None, id="tunnel_only"),
        pytest.param({"risks": ["TUNNEL", "GEO_MISMATCH"]}, None, id="no_offensive"),
        pytest.param({"risks": ["TUNNEL", "AD_FRAUD"]}, 75, id="one_offensive"),
        pytest.param(
            {"risks": ["LOGIN_BRUTEFORCE", "WEB_SCRAPING"]}, 80, id="two_offensive"
        ),
    ],
)
def test_transform_should_score_only_offensive_risks(processor, ip_context, score):
    objects = processor.transform(_context(ip_context), _make_message())

    assert _by_type(objects)["ipv4-addr"][0].get("x_opencti_score") == score


def test_transform_should_cap_the_score(processor):
    # Given a high base score and four offensive risks
    processor.default_score = 90
    ip_context = _context(
        {"risks": ["AD_FRAUD", "CALLBACK_PROXY", "LOGIN_BRUTEFORCE", "WEB_SCRAPING"]}
    )

    # When transforming
    objects = processor.transform(ip_context, _make_message())

    # Then the score does not exceed 100
    assert _by_type(objects)["ipv4-addr"][0]["x_opencti_score"] == 100


def test_transform_should_always_include_the_author_and_the_marking(processor):
    objects = processor.transform(_context({"ip": "1.2.3.4"}), _make_message())

    stix_objects = _by_type(objects)
    assert stix_objects["identity"][0]["name"] == "Spur"
    assert stix_objects["marking-definition"][0]["name"] == "TLP:AMBER"
    assert set(stix_objects) == {"identity", "marking-definition", "ipv4-addr"}


def test_transform_should_link_the_autonomous_system(processor):
    message = _make_message()

    stix_objects = _by_type(processor.transform(_context(IP_CONTEXT), message))

    autonomous_system = stix_objects["autonomous-system"][0]
    assert autonomous_system["number"] == 49981
    assert autonomous_system["name"] == "WorldStream B.V."
    assert _links(stix_objects, "belongs-to") == [
        (message.entity_id, autonomous_system["id"])
    ]


def test_transform_should_chain_the_locations(processor):
    message = _make_message()

    stix_objects = _by_type(processor.transform(_context(IP_CONTEXT), message))

    locations = {
        location["x_opencti_location_type"]: location
        for location in stix_objects["location"]
    }
    assert locations["City"]["name"] == "Amsterdam"
    assert locations["Administrative-Area"]["name"] == "North Holland"
    assert locations["Country"]["name"] == "Netherlands"
    assert _links(stix_objects, "located-at") == [
        (message.entity_id, locations["City"]["id"]),
        (locations["City"]["id"], locations["Administrative-Area"]["id"]),
        (locations["Administrative-Area"]["id"], locations["Country"]["id"]),
    ]


def test_transform_should_link_the_ip_to_the_country_only(processor):
    message = _make_message()

    stix_objects = _by_type(
        processor.transform(_context({"location": {"country": "DE"}}), message)
    )

    country = stix_objects["location"][0]
    assert country["name"] == "Germany"
    assert _links(stix_objects, "located-at") == [(message.entity_id, country["id"])]


@pytest.mark.parametrize(
    "location",
    [
        pytest.param(
            {"city": "Anycast", "country": "ZZ", "state": "Anycast"}, id="anycast"
        ),
        pytest.param({"country": "XX"}, id="unknown_country_code"),
    ],
)
def test_transform_should_skip_unknown_locations(processor, location):
    # Given a Spur location without a real place (e.g. 8.8.8.8 is anycast)
    ip_context = _context({"location": location})

    # When transforming
    stix_objects = _by_type(processor.transform(ip_context, _make_message()))

    # Then no location is created
    assert "location" not in stix_objects
    assert "relationship" not in stix_objects


def test_transform_should_link_the_tunnel_operator_to_the_ip(processor):
    message = _make_message()

    stix_objects = _by_type(processor.transform(_context(IP_CONTEXT), message))

    infrastructure = _infrastructure(stix_objects, "PROTON_VPN")
    assert infrastructure["infrastructure_types"] == ["anonymization"]
    assert infrastructure["labels"] == ["spur-infra:anonymous"]
    assert infrastructure["description"] == (
        "Services seen by Spur on 89.39.106.191: OPENVPN, IPSEC"
    )
    assert (infrastructure["id"], message.entity_id) in _links(
        stix_objects, "consists-of"
    )


def test_transform_should_not_flag_a_non_anonymous_tunnel(processor):
    ip_context = _context({"tunnels": [{"operator": "CORP_VPN", "anonymous": False}]})

    stix_objects = _by_type(processor.transform(ip_context, _make_message()))

    infrastructure = _infrastructure(stix_objects, "CORP_VPN")
    assert "labels" not in infrastructure
    assert "description" not in infrastructure


def test_transform_should_relate_the_client_proxies_to_the_ip(processor):
    message = _make_message()

    stix_objects = _by_type(processor.transform(_context(IP_CONTEXT), message))

    infrastructure = _infrastructure(stix_objects, "NETNUT_PROXY")
    assert infrastructure["infrastructure_types"] == ["anonymization"]
    assert _links(stix_objects, "related-to") == [
        (infrastructure["id"], message.entity_id)
    ]


def test_transform_should_link_the_ai_operator_to_the_ip(processor):
    message = _make_message()

    stix_objects = _by_type(processor.transform(_context(IP_CONTEXT), message))

    infrastructure = _infrastructure(stix_objects, "OPENAI")
    assert "infrastructure_types" not in infrastructure
    assert (infrastructure["id"], message.entity_id) in _links(
        stix_objects, "consists-of"
    )


def test_transform_should_deduplicate_infrastructures(processor):
    # Given the same service tag as tunnel operator, client proxy and AI operator
    ip_context = _context(
        {
            "tunnels": [{"operator": "PROTON_VPN"}, {"operator": "PROTON_VPN"}],
            "client": {"proxies": ["PROTON_VPN"]},
            "ai": {"operator": "PROTON_VPN"},
        }
    )

    # When transforming
    stix_objects = _by_type(processor.transform(ip_context, _make_message()))

    # Then a single infrastructure is linked once, as tunnel operator
    assert len(stix_objects["infrastructure"]) == 1
    assert len(_links(stix_objects, "consists-of")) == 1
    assert _links(stix_objects, "related-to") == []


# ----------------------------------------------------------------------
# transform(): tunnel entry and exit nodes
# ----------------------------------------------------------------------


def test_transform_should_link_the_tunnel_nodes_to_the_infrastructure(processor):
    # Given a tunnel whose exit node is the enriched IP itself
    message = _make_message()

    # When transforming
    stix_objects = _by_type(processor.transform(_context(IP_CONTEXT), message))

    # Then only the other node is created, with its role in the relationship
    node = _node(stix_objects, "1.1.1.1")
    infrastructure = _infrastructure(stix_objects, "PROTON_VPN")
    assert [ip["value"] for ip in stix_objects["ipv4-addr"]] == [
        "89.39.106.191",
        "1.1.1.1",
    ]
    assert _relationship(stix_objects, infrastructure["id"], node["id"]) == {
        "relationship_type": "consists-of",
        "description": "Entry node",
    }


def test_transform_should_not_score_nor_label_the_tunnel_nodes(processor):
    stix_objects = _by_type(processor.transform(_context(IP_CONTEXT), _make_message()))

    node = _node(stix_objects, "1.1.1.1")
    assert "x_opencti_score" not in node
    assert "x_opencti_labels" not in node
    assert node["x_opencti_created_by_ref"] == stix_objects["identity"][0]["id"]


def test_transform_should_describe_a_node_that_is_both_entry_and_exit(processor):
    ip_context = _context(
        {"tunnels": [{"operator": "TOR", "entries": ["2.2.2.2"], "exits": ["2.2.2.2"]}]}
    )

    stix_objects = _by_type(processor.transform(ip_context, _make_message()))

    node = _node(stix_objects, "2.2.2.2")
    infrastructure = _infrastructure(stix_objects, "TOR")
    assert _relationship(stix_objects, infrastructure["id"], node["id"]) == {
        "relationship_type": "consists-of",
        "description": "Entry and exit node",
    }


def test_transform_should_create_ipv6_tunnel_nodes(processor):
    ip_context = _context(
        {"tunnels": [{"operator": "TOR", "exits": ["2001:0db8:0000::0001"]}]}
    )

    stix_objects = _by_type(processor.transform(ip_context, _make_message()))

    assert [ip["value"] for ip in stix_objects["ipv6-addr"]] == ["2001:db8::1"]


def test_transform_should_skip_invalid_tunnel_nodes(processor):
    # Given a tunnel with an invalid node
    processor.logger = MagicMock()
    ip_context = _context(
        {"tunnels": [{"operator": "TOR", "entries": ["not-an-ip", "2.2.2.2"]}]}
    )

    # When transforming
    stix_objects = _by_type(processor.transform(ip_context, _make_message()))

    # Then the invalid node is skipped and logged
    assert [ip["value"] for ip in stix_objects["ipv4-addr"]] == [
        "89.39.106.191",
        "2.2.2.2",
    ]
    processor.logger.warning.assert_called_once()


def test_transform_should_limit_the_tunnel_nodes(processor):
    # Given a tunnel with more nodes than the limit
    entries = [f"10.0.0.{index}" for index in range(1, 61)]
    ip_context = _context({"tunnels": [{"operator": "TOR", "entries": entries}]})

    # When transforming
    stix_objects = _by_type(processor.transform(ip_context, _make_message()))

    # Then only the first 50 nodes are linked
    assert len(stix_objects["ipv4-addr"]) == 1 + 50


def test_transform_should_ignore_the_nodes_of_a_tunnel_without_operator(processor):
    ip_context = _context({"tunnels": [{"type": "VPN", "entries": ["2.2.2.2"]}]})

    stix_objects = _by_type(processor.transform(ip_context, _make_message()))

    assert [ip["value"] for ip in stix_objects["ipv4-addr"]] == ["89.39.106.191"]


def test_transform_should_build_a_deterministic_note(processor):
    message = _make_message()

    first = _by_type(processor.transform(_context(IP_CONTEXT), message))["note"]
    second = _by_type(processor.transform(_context(IP_CONTEXT), message))["note"]

    assert len(first) == 1
    note = first[0]
    assert note["id"] == second[0]["id"]
    assert note["object_refs"] == [message.entity_id]
    assert note["abstract"] == "Spur IP context for 89.39.106.191"
    assert "- **Organization**: Proton AG" in note["content"]
    assert "- **Client count**: 12" in note["content"]
    assert "- **Client concentration**: Paris, Ile-de-France, FR" in note["content"]
    assert "- **Concentration density**: 0.42" in note["content"]


def _infrastructure(stix_objects: dict[str, list[dict]], name: str) -> dict:
    return next(
        infra for infra in stix_objects["infrastructure"] if infra["name"] == name
    )


def _node(stix_objects: dict[str, list[dict]], value: str) -> dict:
    return next(ip for ip in stix_objects["ipv4-addr"] if ip["value"] == value)


def _relationship(
    stix_objects: dict[str, list[dict]], source_id: str, target_id: str
) -> dict:
    relationship = next(
        rel
        for rel in stix_objects["relationship"]
        if (rel["source_ref"], rel["target_ref"]) == (source_id, target_id)
    )
    return {
        "relationship_type": relationship["relationship_type"],
        "description": relationship.get("description"),
    }
