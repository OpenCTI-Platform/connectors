"""Tests for the enrichment flow: scope, TLP, values, playbooks and errors."""

import copy
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, NetAPIConnector
from connector.converter_to_stix import OWN_LABEL, ObservableNote
from connectors_sdk.exceptions.error import DataRetrievalError
from mock_responses import (
    CHECK_CLEAN,
    CHECK_LISTED_NOW,
    CHECK_LISTED_PAST,
    CHECK_LISTED_VIA_DOMAIN,
    RANK_NOT_IN_TOP_1M,
)
from pycti import MarkingDefinition as PyctiMarkingDefinition

DOMAIN_ID = "domain-name--11111111-1111-4111-8111-111111111111"
TLP_CLEAR_ID = PyctiMarkingDefinition.generate_id("TLP", "TLP:CLEAR")
TLP_GREEN_ID = PyctiMarkingDefinition.generate_id("TLP", "TLP:GREEN")
TLP_RED_ID = PyctiMarkingDefinition.generate_id("TLP", "TLP:RED")
TLP_ORDER = [
    "TLP:CLEAR",
    "TLP:WHITE",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
]


def make_settings(**overrides: Any) -> ConnectorSettings:
    connector = {"id": "connector-id", "max_tlp": "amber"}
    netapi: dict[str, Any] = {}
    for key, value in overrides.items():
        (connector if key in ("scope", "max_tlp", "auto") else netapi)[key] = value

    class StubSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": connector,
                    "netapi": netapi,
                }
            )

    return StubSettings()


def make_connector(check=CHECK_LISTED_NOW, rank=RANK_NOT_IN_TOP_1M, **overrides):
    helper = MagicMock()
    helper.connect_scope = "Domain-Name,Hostname,IPv4-Addr,Url"  # as pycti keeps it
    helper.check_max_tlp.side_effect = lambda tlp, max_tlp: TLP_ORDER.index(tlp) <= max(
        TLP_ORDER.index(max_tlp), 1
    )
    helper.stix2_create_bundle.side_effect = lambda objects: {"objects": objects}
    helper.send_stix2_bundle.return_value = ["bundle"]
    client = MagicMock()
    client.compromised_check.return_value = copy.deepcopy(check)
    client.domain_rank.return_value = copy.deepcopy(rank)
    connector = NetAPIConnector(make_settings(**overrides), helper, client=client)
    return connector, helper, client


def make_data(
    entity_id: str = DOMAIN_ID,
    value: str = "000359.xyz",
    stix_type: str | None = None,
    tlp: str | None = "TLP:GREEN",
    playbook: bool = False,
    entity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stix_entity = {
        "type": stix_type or entity_id.split("--")[0],
        "id": entity_id,
        "spec_version": "2.1",
        "value": value,
        **(entity or {}),
    }
    markings = [{"definition_type": "TLP", "definition": tlp}] if tlp else []
    data = {
        "entity_id": entity_id,
        "enrichment_entity": {
            "entity_type": "Domain-Name",
            "observable_value": value,
            "created_at": "2024-05-01T10:00:00.000Z",
            "objectMarking": markings,
        },
        "stix_entity": stix_entity,
        "stix_objects": [stix_entity],
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
    return data


def sent_objects(helper: MagicMock) -> list[dict[str, Any]]:
    return helper.stix2_create_bundle.call_args.args[0]


def by_type(helper: MagicMock) -> dict[str, dict[str, Any]]:
    return {obj["type"]: obj for obj in sent_objects(helper)}


# --- skipped entities ------------------------------------------------------


def test_out_of_scope_entity_is_skipped_without_a_lookup():
    connector, helper, client = make_connector()
    data = make_data(entity_id="email-addr--33333333-3333-4333-8333-333333333333")

    message = connector.process_message(data)

    assert message == "Entity type not in scope"
    client.compromised_check.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_skipped_entity_is_forwarded_unchanged_inside_a_playbook():
    connector, helper, _ = make_connector()
    data = make_data(
        entity_id="email-addr--33333333-3333-4333-8333-333333333333", playbook=True
    )

    connector.process_message(data)

    assert sent_objects(helper) == data["stix_objects"]
    assert sent_objects(helper) is not data["stix_objects"]
    helper.send_stix2_bundle.assert_called_once_with(
        {"objects": data["stix_objects"]},
        update=False,
        cleanup_inconsistent_bundle=True,
    )


@pytest.mark.parametrize("tlp", ["TLP:AMBER+STRICT", "TLP:RED"])
def test_tlp_above_the_maximum_is_never_sent_to_netapi(tlp):
    connector, helper, client = make_connector()

    message = connector.process_message(make_data(tlp=tlp))

    assert (
        message
        == f"Observable is {tlp}, above the maximum TLP:AMBER: not sent to NetAPI"
    )
    client.compromised_check.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_tlp_within_a_raised_maximum_is_enriched():
    connector, helper, client = make_connector(max_tlp="red")

    connector.process_message(make_data(tlp="TLP:RED"))

    client.compromised_check.assert_called_once_with("000359.xyz")
    helper.send_stix2_bundle.assert_called_once()


@pytest.mark.parametrize(
    "entity_id, value, reason",
    [
        ("ipv4-addr--22222222-2222-4222-8222-222222222222", "10.0.0.1", "Private"),
        ("ipv4-addr--22222222-2222-4222-8222-222222222222", "127.0.0.1", "Private"),
        ("url--44444444-4444-4444-8444-444444444444", "http://[2001:db8::1]/", "IPv6"),
        ("hostname--55555555-5555-4555-8555-555555555555", "localhost", "not a valid"),
        ("url--44444444-4444-4444-8444-444444444444", "/relative/path", "no host"),
        (DOMAIN_ID, "   ", "no host"),
    ],
)
def test_values_that_cannot_be_looked_up_are_skipped(entity_id, value, reason):
    connector, helper, client = make_connector()

    message = connector.process_message(make_data(entity_id=entity_id, value=value))

    assert reason in message
    client.compromised_check.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


# --- the value sent to NetAPI ----------------------------------------------


@pytest.mark.parametrize(
    "entity_id, value, expected",
    [
        (DOMAIN_ID, "Example.COM.", "example.com"),
        (DOMAIN_ID, "пример.рф", "xn--e1afmkfd.xn--p1ai"),
        (
            "hostname--55555555-5555-4555-8555-555555555555",
            "www.Example.org",
            "www.example.org",
        ),
        ("ipv4-addr--22222222-2222-4222-8222-222222222222", "8.8.8.8", "8.8.8.8"),
        (
            "url--44444444-4444-4444-8444-444444444444",
            "HTTPS://Sub.Example.NET:8443/a?b=c",
            "sub.example.net",
        ),
        ("url--44444444-4444-4444-8444-444444444444", "example.io/path", "example.io"),
        (
            "url--44444444-4444-4444-8444-444444444444",
            "http://user:pw@8.8.4.4/x",
            "8.8.4.4",
        ),
    ],
)
def test_the_host_of_the_observable_is_looked_up(entity_id, value, expected):
    connector, _, client = make_connector(check=CHECK_CLEAN)

    connector.process_message(make_data(entity_id=entity_id, value=value))

    client.compromised_check.assert_called_once_with(expected)


# --- results ----------------------------------------------------------------


def test_clean_value_sends_nothing_outside_a_playbook():
    connector, helper, client = make_connector(check=CHECK_CLEAN)

    message = connector.process_message(make_data(value="netapi.com"))

    assert message == "Not in the NetAPI compromised feed, now or in the past"
    client.domain_rank.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_clean_value_forwards_the_bundle_inside_a_playbook():
    connector, helper, _ = make_connector(check=CHECK_CLEAN)
    data = make_data(value="netapi.com", playbook=True)

    connector.process_message(data)

    assert sent_objects(helper) == data["stix_objects"]


def test_listed_domain_is_enriched_in_place_with_a_note():
    connector, helper, client = make_connector()
    data = make_data(
        entity={
            "object_marking_refs": [TLP_GREEN_ID],
            "x_opencti_labels": ["analyst-tag"],
        }
    )

    message = connector.process_message(data)

    assert message == (
        "NetAPI: listed now (seen in the compromised feed within the last 24 hours); "
        "observable updated and note attached"
    )
    client.compromised_check.assert_called_once_with("000359.xyz")
    client.domain_rank.assert_called_once_with("000359.xyz")

    sent = sent_objects(helper)
    assert [obj["type"] for obj in sent] == [
        "domain-name",
        "identity",
        "marking-definition",
        "note",
    ]
    observable = sent[0]
    assert observable["id"] == DOMAIN_ID
    assert observable["x_opencti_labels"] == ["analyst-tag", OWN_LABEL]
    assert "x_opencti_score" not in observable  # update_score is off by default
    assert observable["x_opencti_external_references"][-1]["source_name"] == "NetAPI"
    assert data["stix_entity"]["x_opencti_labels"] == ["analyst-tag"]  # untouched

    objects = by_type(helper)
    assert objects["identity"]["name"] == "NetAPI"
    assert objects["marking-definition"]["id"] == TLP_CLEAR_ID
    note = objects["note"]
    assert note["id"] == ObservableNote.stable_id(DOMAIN_ID)
    assert note["object_refs"] == [DOMAIN_ID]
    assert note["created_by_ref"] == objects["identity"]["id"]
    assert set(note["object_marking_refs"]) == {TLP_CLEAR_ID, TLP_GREEN_ID}
    assert "| Top 1M rank | not in the NetAPI Top 1M |" in note["content"]
    helper.send_stix2_bundle.assert_called_once_with(
        {"objects": sent}, update=True, cleanup_inconsistent_bundle=True
    )


def test_score_is_written_only_when_enabled_and_listed_now():
    connector, helper, _ = make_connector(update_score=True, score=95)
    connector.process_message(make_data())
    assert by_type(helper)["domain-name"]["x_opencti_score"] == 95

    connector, helper, _ = make_connector(
        check=CHECK_LISTED_PAST, update_score=True, score=95
    )
    connector.process_message(
        make_data(
            entity_id="ipv4-addr--22222222-2222-4222-8222-222222222222", value="1.1.1.1"
        )
    )
    assert "x_opencti_score" not in by_type(helper)["ipv4-addr"]


def test_past_listing_attaches_the_note_and_leaves_the_labels_alone():
    connector, helper, client = make_connector(check=CHECK_LISTED_PAST)
    data = make_data(
        entity_id="ipv4-addr--22222222-2222-4222-8222-222222222222",
        value="1.1.1.1",
        entity={"x_opencti_labels": [OWN_LABEL]},
    )

    message = connector.process_message(data)

    assert message.startswith("NetAPI: listed in the past (last seen 2026-06-17)")
    client.domain_rank.assert_not_called()  # the rank exists for domains only
    objects = by_type(helper)
    # an earlier label stays: OpenCTI merges labels on import, the note has the status
    assert objects["ipv4-addr"]["x_opencti_labels"] == [OWN_LABEL]
    assert (
        objects["note"]["abstract"]
        == "NetAPI - listed in the compromised feed in the past"
    )


def test_hostname_listed_through_its_domain_names_the_match():
    connector, helper, client = make_connector(check=CHECK_LISTED_VIA_DOMAIN)

    connector.process_message(
        make_data(
            entity_id="hostname--55555555-5555-4555-8555-555555555555",
            value="www.000359.xyz",
        )
    )

    client.domain_rank.assert_called_once_with("www.000359.xyz")
    assert (
        "| Matched entry | 000359.xyz (the registered domain) |"
        in by_type(helper)["note"]["content"]
    )


def test_rank_lookup_can_be_switched_off():
    connector, helper, client = make_connector(include_rank=False)

    connector.process_message(make_data())

    client.domain_rank.assert_not_called()
    assert "Top 1M" not in by_type(helper)["note"]["content"]


def test_note_marking_follows_the_configured_tlp():
    connector, helper, _ = make_connector(tlp_level="amber")

    connector.process_message(make_data())

    marking = by_type(helper)["marking-definition"]
    assert marking["id"] == PyctiMarkingDefinition.generate_id("TLP", "TLP:AMBER")


# --- errors ---------------------------------------------------------------------


def test_api_failure_is_raised_so_the_work_is_in_error():
    connector, helper, client = make_connector()
    client.compromised_check.side_effect = DataRetrievalError("NetAPI error 429")

    with pytest.raises(DataRetrievalError):
        connector.process_message(make_data())

    helper.send_stix2_bundle.assert_not_called()
    helper.connector_logger.error.assert_called_once()


def test_api_failure_inside_a_playbook_forwards_the_bundle_then_raises():
    connector, helper, client = make_connector()
    client.compromised_check.side_effect = DataRetrievalError("NetAPI error 429")
    data = make_data(playbook=True)

    with pytest.raises(DataRetrievalError):
        connector.process_message(data)

    assert sent_objects(helper) == data["stix_objects"]


def test_run_listens_with_the_message_callback():
    connector, helper, _ = make_connector()

    connector.run()

    helper.listen.assert_called_once_with(message_callback=connector.process_message)


# --- markings from both representations ----------------------------------------


def test_tlp_red_on_the_stix_entity_alone_is_never_sent_to_netapi():
    """A marking may be present only in object_marking_refs of the STIX entity."""
    connector, helper, client = make_connector()
    data = make_data(tlp=None, entity={"object_marking_refs": [TLP_RED_ID]})

    message = connector.process_message(data)

    assert (
        message
        == "Observable is TLP:RED, above the maximum TLP:AMBER: not sent to NetAPI"
    )
    client.compromised_check.assert_not_called()


def test_unresolvable_marking_is_never_sent_to_netapi():
    """A marking that cannot be resolved is refused, not treated as no marking."""
    connector, helper, client = make_connector()
    unknown = "marking-definition--99999999-9999-4999-8999-999999999999"
    data = make_data(tlp=None, entity={"object_marking_refs": [unknown]})

    message = connector.process_message(data)

    assert message == (
        f"Marking {unknown} of the observable cannot be resolved: not sent to NetAPI"
    )
    client.compromised_check.assert_not_called()


def test_bundled_non_tlp_marking_is_accepted_and_kept_on_the_note():
    connector, helper, client = make_connector()
    statement_id = "marking-definition--88888888-8888-4888-8888-888888888888"
    data = make_data(entity={"object_marking_refs": [statement_id]})
    data["stix_objects"].append(
        {
            "type": "marking-definition",
            "id": statement_id,
            "definition_type": "statement",
            "definition": {"statement": "internal"},
        }
    )

    connector.process_message(data)

    client.compromised_check.assert_called_once()
    assert statement_id in by_type(helper)["note"]["object_marking_refs"]


def test_note_gets_the_markings_of_the_opencti_entity_too():
    """objectMarking may carry a TLP that the STIX entity does not list."""
    connector, helper, _ = make_connector()

    connector.process_message(make_data(tlp="TLP:GREEN"))

    assert set(by_type(helper)["note"]["object_marking_refs"]) == {
        TLP_CLEAR_ID,
        TLP_GREEN_ID,
    }


def test_unreadable_opencti_marking_is_never_sent_to_netapi():
    connector, helper, client = make_connector()
    data = make_data(tlp=None)
    data["enrichment_entity"]["objectMarking"] = [{"standard_id": "x"}]

    message = connector.process_message(data)

    assert "cannot be read" in message
    client.compromised_check.assert_not_called()
