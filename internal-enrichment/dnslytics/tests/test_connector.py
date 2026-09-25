import pytest
from conftest import (
    INDICATOR_ID,
    RFC_QUERY,
    FakeResponse,
    FakeSession,
    default_routes,
    indicator_event,
    make_helper,
    make_settings,
)
from connector import DnslyticsConnector
from connector.connector import NOT_A_DNSLYTICS_QUERY
from connectors_sdk.models import TLPMarking


def make_connector(routes=None, **dnslytics):
    helper = make_helper()
    connector = DnslyticsConnector(config=make_settings(**dnslytics), helper=helper)
    connector.client.session = FakeSession(routes or default_routes())
    return connector, helper


def sent_objects(helper) -> list[dict]:
    """Objects of the last bundle given to `send_stix2_bundle`."""
    bundle = helper.send_stix2_bundle.call_args.args[0]
    return bundle["objects"]


def as_dicts(objects) -> list[dict]:
    return [dict(obj) if not isinstance(obj, dict) else obj for obj in objects]


def by_type(objects, type_: str) -> list[dict]:
    return [obj for obj in as_dicts(objects) if obj["type"] == type_]


def relationships(objects, relationship_type: str) -> list[dict]:
    return [
        obj
        for obj in by_type(objects, "relationship")
        if obj["relationship_type"] == relationship_type
    ]


def domain(objects, value: str) -> dict:
    return next(obj for obj in by_type(objects, "domain-name") if obj["value"] == value)


def test_rfc_query_makes_one_call_and_links_domains_to_indicator(fake_dns):
    connector, helper = make_connector()

    message = connector.process_message(indicator_event())

    session = connector.client.session
    dataset_calls = session.calls_to("/v2/dataset/domains")
    assert len(dataset_calls) == 1
    # Query sent verbatim, page 1 only
    assert dataset_calls[0][1]["q"] == RFC_QUERY
    assert dataset_calls[0][1]["page"] == 1

    objects = sent_objects(helper)
    domains = by_type(objects, "domain-name")
    assert len(domains) == 5
    based_on = relationships(objects, "based-on")
    # Indicator -> Domain-Name: the only direction OpenCTI accepts for based-on
    assert {rel["source_ref"] for rel in based_on} == {INDICATOR_ID}
    assert {rel["target_ref"] for rel in based_on} == {d["id"] for d in domains}
    assert by_type(objects, "note") == []
    assert message == "created 5 of 5 matches, 10 credits"


def test_enriched_indicator_is_sent_back_for_playbooks(fake_dns):
    connector, helper = make_connector()
    event = indicator_event(event_type=None)

    connector.process_message(event)

    assert event["stix_entity"] in sent_objects(helper)


def test_armeniadaily_gets_ip_as_and_hostinger_provider_label(fake_dns):
    connector, helper = make_connector()

    connector.process_message(indicator_event())

    objects = sent_objects(helper)
    armeniadaily = domain(objects, "armeniadaily.am")
    assert armeniadaily["x_opencti_labels"] == [
        "dnslytics:active",
        "provider:Hostinger International Limited",
    ]
    assert armeniadaily["x_opencti_external_references"][0]["url"] == (
        "https://search.dnslytics.com/domain/armeniadaily.am"
    )
    resolves_to = [
        rel
        for rel in relationships(objects, "resolves-to")
        if rel["source_ref"] == armeniadaily["id"]
    ]
    ip_ids = {rel["target_ref"] for rel in resolves_to}
    ips = [obj for obj in by_type(objects, "ipv4-addr") + by_type(objects, "ipv6-addr")]
    assert {ip["value"] for ip in ips if ip["id"] in ip_ids} == {
        "45.84.204.99",
        "2a02:4780:9:1582:0:26f7:e9b3:2",
    }
    hostinger = next(
        obj for obj in by_type(objects, "autonomous-system") if obj["number"] == 47583
    )
    assert hostinger["name"] == "Hostinger International Limited"
    belongs_to = {
        (rel["source_ref"], rel["target_ref"])
        for rel in relationships(objects, "belongs-to")
    }
    assert {(ip_id, hostinger["id"]) for ip_id in ip_ids} <= belongs_to


def test_ips_are_deduplicated_before_as_lookup(fake_dns):
    connector, _ = make_connector()

    connector.process_message(indicator_event())

    session = connector.client.session
    # armeniadaily.am and armenianews.example share 45.84.204.99
    assert len(session.calls_to("/v1/ip2asn/45.84.204.99")) == 1
    assert len([c for c in session.calls if "/v1/ip2asn/" in c[0]]) == 3


def test_provider_label_is_trimmed(fake_dns):
    connector, helper = make_connector()

    connector.process_message(indicator_event())

    assert (
        "provider:Example Hosting Ltd"
        in domain(sent_objects(helper), "newsarmenia.example")["x_opencti_labels"]
    )


def test_dropped_domain_gets_dropped_label_only(fake_dns):
    connector, helper = make_connector()

    connector.process_message(indicator_event())

    objects = sent_objects(helper)
    dropped = domain(objects, "dailyarmenia.example")
    assert dropped["x_opencti_labels"] == ["dnslytics:dropped"]
    assert not [
        rel
        for rel in relationships(objects, "resolves-to")
        if rel["source_ref"] == dropped["id"]
    ]


def test_active_domain_that_does_not_resolve_is_not_a_failure(fake_dns):
    connector, helper = make_connector()

    connector.process_message(indicator_event())

    assert domain(sent_objects(helper), "armenia-daily.example")[
        "x_opencti_labels"
    ] == ["dnslytics:active"]


def test_resolve_hosting_false_creates_domains_and_labels_only(fake_dns):
    connector, helper = make_connector(resolve_hosting=False)

    connector.process_message(indicator_event())

    objects = sent_objects(helper)
    assert len(by_type(objects, "domain-name")) == 5
    assert by_type(objects, "ipv4-addr") == []
    assert by_type(objects, "autonomous-system") == []
    assert [c for c in connector.client.session.calls if "/v1/ip2asn/" in c[0]] == []


def test_40000_matches_ingests_page_one_only(fake_dns):
    dataset = {
        "status": "succeed",
        "data": {
            "question": {"query": RFC_QUERY, "page": 1},
            "typeinfo": "dataset/domains",
            "ndomains": 40000,
            "domains": [
                {"domain": f"armenia-news-{i}.example", "active": False}
                for i in range(1000)
            ],
        },
    }
    connector, helper = make_connector(routes=default_routes(dataset))

    message = connector.process_message(indicator_event())

    assert len(connector.client.session.calls_to("/v2/dataset/domains")) == 1
    assert len(by_type(sent_objects(helper), "domain-name")) == 1000
    assert message.startswith("created 1000 of 40000 matches")


@pytest.mark.parametrize(
    "ip2asn_answer, reason",
    [
        pytest.param(
            FakeResponse(403, {"status": "error", "data": "Forbidden access denied!"}),
            "IP2ASN failed",
            id="ip2asn_failed",
        ),
        pytest.param(
            {"ip": "45.84.204.99", "announced": True, "asn": 47583, "shortname": ""},
            "no provider label",
            id="missing_provider_name",
        ),
    ],
)
def test_active_domain_missing_hosting_fails_the_enrichment(
    fake_dns, ip2asn_answer, reason
):
    routes = default_routes()
    routes["/v1/ip2asn/45.84.204.99"] = ip2asn_answer
    routes["/v1/ip2asn/2a02:4780:9:1582:0:26f7:e9b3:2"] = ip2asn_answer
    connector, helper = make_connector(routes=routes)

    with pytest.raises(ValueError, match=reason) as err:
        connector.process_message(indicator_event())

    assert "armeniadaily.am" in str(err.value)
    # The data is kept: the bundle was sent before failing the work
    helper.send_stix2_bundle.assert_called_once()


def test_domain_on_unannounced_ip_is_a_warning_not_a_failure(fake_dns):
    routes = default_routes()
    unannounced = {"ip": "45.84.204.99", "announced": False}
    routes["/v1/ip2asn/45.84.204.99"] = unannounced
    routes["/v1/ip2asn/2a02:4780:9:1582:0:26f7:e9b3:2"] = {
        "ip": "2a02:4780:9:1582:0:26f7:e9b3:2",
        "announced": False,
    }
    connector, helper = make_connector(routes=routes)

    message = connector.process_message(indicator_event())

    assert message.startswith("created 5 of 5 matches, 10 credits; warning: ")
    assert "armeniadaily.am: not announced, no AS for 45.84.204.99" in message
    objects = sent_objects(helper)
    armeniadaily = domain(objects, "armeniadaily.am")
    # Still linked to its IPs, just without AS and provider label
    assert armeniadaily["x_opencti_labels"] == ["dnslytics:active"]
    assert [
        rel
        for rel in relationships(objects, "resolves-to")
        if rel["source_ref"] == armeniadaily["id"]
    ]
    helper.connector_logger.warning.assert_called()


def test_every_run_makes_the_same_ids_so_reruns_create_no_duplicates(fake_dns):
    connector, helper = make_connector()

    connector.process_message(indicator_event())
    first = {obj["id"] for obj in as_dicts(sent_objects(helper))}
    connector.process_message(indicator_event())
    second = {obj["id"] for obj in as_dicts(sent_objects(helper))}

    assert first == second


@pytest.mark.parametrize("output_tlp", ["clear", "green"])
def test_every_created_object_carries_output_tlp(fake_dns, output_tlp):
    connector, helper = make_connector(output_tlp_level=output_tlp)

    connector.process_message(indicator_event())

    objects = as_dicts(sent_objects(helper))
    expected = TLPMarking(level=output_tlp).id
    marking = next(obj for obj in objects if obj["type"] == "marking-definition")
    assert marking["id"] == expected
    created = [
        obj
        for obj in objects
        if obj["type"] != "marking-definition" and obj["id"] != INDICATOR_ID
    ]
    assert created
    for obj in created:
        marking_refs = obj.get("object_marking_refs")
        assert marking_refs == [marking["id"]], obj["id"]


@pytest.mark.parametrize("pattern_type", ["yara", "stix"])
def test_other_pattern_types_spend_no_credits(pattern_type):
    connector, helper = make_connector()

    message = connector.process_message(
        indicator_event(
            pattern="[domain-name:value = 'x.am']", pattern_type=pattern_type
        )
    )

    assert message == NOT_A_DNSLYTICS_QUERY
    assert connector.client.session.calls == []
    helper.send_stix2_bundle.assert_not_called()


def test_other_pattern_type_in_playbook_sends_bundle_back_unchanged():
    connector, helper = make_connector()
    event = indicator_event(pattern_type="yara", event_type=None)

    assert connector.process_message(event) == NOT_A_DNSLYTICS_QUERY

    assert sent_objects(helper) == event["stix_objects"]
    assert connector.client.session.calls == []


def test_indicator_above_max_tlp_is_not_enriched():
    connector, _ = make_connector()
    markings = [{"definition_type": "TLP", "definition": "TLP:AMBER"}]

    with pytest.raises(ValueError, match="MAX TLP"):
        connector.process_message(indicator_event(markings=markings))

    assert connector.client.session.calls == []


def test_default_max_tlp_accepts_green(fake_dns):
    connector, _ = make_connector()
    markings = [{"definition_type": "TLP", "definition": "TLP:GREEN"}]

    connector.process_message(indicator_event(markings=markings))

    assert len(connector.client.session.calls_to("/v2/dataset/domains")) == 1


def test_dnslytics_error_fails_the_work_with_its_reason():
    routes = default_routes()
    from conftest import FakeResponse, load_fixture

    routes["/v2/dataset/domains"] = FakeResponse(
        403, load_fixture("error_forbidden.json")
    )
    connector, helper = make_connector(routes=routes)

    with pytest.raises(Exception, match="Forbidden access denied!"):
        connector.process_message(indicator_event())

    # 403 is never retried
    assert len(connector.client.session.calls_to("/v2/dataset/domains")) == 1
    helper.send_stix2_bundle.assert_not_called()


def test_vocabulary_entry_is_not_recreated_when_present():
    connector, helper = make_connector()

    connector.ensure_pattern_type_vocabulary()

    helper.api.vocabulary.create.assert_not_called()


def test_vocabulary_entry_is_created_when_missing():
    connector, helper = make_connector()
    helper.api.vocabulary.read.return_value = None

    connector.ensure_pattern_type_vocabulary()

    helper.api.vocabulary.create.assert_called_once()
    kwargs = helper.api.vocabulary.create.call_args.kwargs
    assert kwargs["name"] == "dnslytics"
    assert kwargs["category"] == "pattern_type_ov"
    assert kwargs["description"]
    filters = helper.api.vocabulary.read.call_args.kwargs["filters"]["filters"]
    assert {"key": "category", "values": ["pattern_type_ov"]} in filters


def test_vocabulary_without_capability_logs_the_fix_and_keeps_running():
    connector, helper = make_connector()
    helper.api.vocabulary.read.return_value = None
    helper.api.vocabulary.create.side_effect = ValueError("ForbiddenAccess")

    connector.ensure_pattern_type_vocabulary()

    warning = helper.connector_logger.warning.call_args.args[0]
    assert "Settings > Vocabularies > pattern_type_ov" in warning


def test_domain_with_one_nameless_as_fails_even_if_another_as_is_named(fake_dns):
    routes = default_routes()
    # IPv4 keeps its named AS (Hostinger), IPv6 gets an AS without a name
    routes["/v1/ip2asn/2a02:4780:9:1582:0:26f7:e9b3:2"] = {
        "ip": "2a02:4780:9:1582:0:26f7:e9b3:2",
        "announced": True,
        "asn": 64501,
        "shortname": "",
    }
    connector, _ = make_connector(routes=routes)

    with pytest.raises(ValueError, match="armeniadaily.am: AS has no name"):
        connector.process_message(indicator_event())


def test_playbook_gets_original_bundle_when_the_api_fails():
    routes = default_routes()
    routes["/v2/dataset/domains"] = FakeResponse(
        403, {"status": "error", "data": "Forbidden access denied!"}
    )
    connector, helper = make_connector(routes=routes)
    event = indicator_event(event_type=None)
    original = list(event["stix_objects"])

    with pytest.raises(Exception, match="Forbidden access denied!"):
        connector.process_message(event)

    helper.send_stix2_bundle.assert_called_once()
    assert sent_objects(helper) == original


def test_playbook_gets_original_bundle_when_tlp_is_too_high():
    connector, helper = make_connector()
    markings = [{"definition_type": "TLP", "definition": "TLP:RED"}]
    event = indicator_event(markings=markings, event_type=None)

    with pytest.raises(ValueError, match="MAX TLP"):
        connector.process_message(event)

    assert sent_objects(helper) == event["stix_objects"]
    assert connector.client.session.calls == []


def test_playbook_failure_after_sending_does_not_send_twice(fake_dns):
    routes = default_routes()
    failed = FakeResponse(403, {"status": "error", "data": "Forbidden access denied!"})
    routes["/v1/ip2asn/45.84.204.99"] = failed
    routes["/v1/ip2asn/2a02:4780:9:1582:0:26f7:e9b3:2"] = failed
    connector, helper = make_connector(routes=routes)

    with pytest.raises(ValueError, match="IP2ASN failed"):
        connector.process_message(indicator_event(event_type=None))

    # Only the enriched bundle, not the original one on top of it
    helper.send_stix2_bundle.assert_called_once()
    assert by_type(sent_objects(helper), "domain-name")
