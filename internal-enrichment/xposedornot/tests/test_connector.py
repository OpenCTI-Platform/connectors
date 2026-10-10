import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from pycti import MarkingDefinition as PyctiMarkingDefinition
from src.xposedornot.connector import XposedOrNotConnector
from src.xposedornot.converter_to_stix import ObservableNote
from src.xposedornot.errors import EnrichmentError, XposedOrNotError

from tests.conftest import (
    BREACHED,
    EMAIL,
    OBSERVABLE_ID,
    by_type,
    make_data,
    make_helper,
    make_settings,
    sent_objects,
)

TLP_AMBER_ID = PyctiMarkingDefinition.generate_id("TLP", "TLP:AMBER")
TLP_GREEN_ID = PyctiMarkingDefinition.generate_id("TLP", "TLP:GREEN")
PAP_ID = PyctiMarkingDefinition.generate_id("PAP", "PAP:AMBER")


def make_connector(result=BREACHED, **overrides):
    helper = make_helper()
    client = MagicMock()
    client.api_key = None
    client.lookup.return_value = result
    connector = XposedOrNotConnector(make_settings(**overrides), helper, client=client)
    return connector, helper, client


def test_out_of_scope_entity_is_skipped_and_not_sent():
    connector, helper, client = make_connector()
    message = connector._message_callback(make_data(entity_type="IPv4-Addr"))
    assert message == "Unsupported entity type: IPv4-Addr"
    client.lookup.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_skipped_entity_is_forwarded_unchanged_inside_a_playbook():
    connector, helper, _ = make_connector()
    data = make_data(entity_type="IPv4-Addr", playbook=True)
    connector._message_callback(data)
    assert sent_objects(helper) == data["stix_objects"]
    assert sent_objects(helper) is not data["stix_objects"]
    helper.send_stix2_bundle.assert_called_once_with(
        "BUNDLE", update=False, cleanup_inconsistent_bundle=True
    )


@pytest.mark.parametrize("markings", [("TLP:RED",), ("TLP:GREEN", "TLP:AMBER+STRICT")])
def test_tlp_above_the_maximum_is_skipped(markings):
    connector, helper, client = make_connector()
    message = connector._message_callback(make_data(markings=markings))
    assert "above the maximum allowed (TLP:AMBER); skipping" in message
    client.lookup.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_tlp_within_the_maximum_is_enriched():
    connector, helper, client = make_connector(max_tlp="TLP:RED")
    connector._message_callback(make_data(markings=("TLP:RED",)))
    client.lookup.assert_called_once_with(EMAIL)
    helper.send_stix2_bundle.assert_called_once()


def test_invalid_email_is_skipped_without_calling_the_api():
    connector, helper, client = make_connector()
    message = connector._message_callback(make_data(email="not-an-email"))
    assert message == "The observable value is not a valid email address"
    client.lookup.assert_not_called()


def test_email_is_normalised_before_lookup():
    connector, _, client = make_connector()
    connector._message_callback(make_data(email="  Victim@Example.COM "))
    client.lookup.assert_called_once_with("victim@example.com")


def test_clean_email_sends_nothing_outside_a_playbook():
    connector, helper, _ = make_connector(result={})
    message = connector._message_callback(make_data())
    assert message == "No known breach exposure for this email address (XposedOrNot)"
    helper.send_stix2_bundle.assert_not_called()


def test_clean_email_forwards_the_bundle_inside_a_playbook():
    connector, helper, _ = make_connector(result={})
    data = make_data(playbook=True)
    connector._message_callback(data)
    assert sent_objects(helper) == data["stix_objects"]


def test_breached_email_updates_the_observable_and_attaches_a_note():
    connector, helper, _ = make_connector()
    data = make_data(
        entity={
            "x_opencti_labels": ["analyst-tag"],
            "external_references": [
                {"source_name": "Analyst", "url": "https://a.example"}
            ],
        }
    )
    message = connector._message_callback(data)

    assert message == (
        "Found 1 breach(es) (first 2024, latest 2024);"
        " observable updated and summary note attached"
    )
    objects = by_type(helper)
    observable = objects["email-addr"]
    assert observable["x_opencti_score"] == 100
    assert observable["x_opencti_labels"] == [
        "analyst-tag",
        "data-breach",
        "plaintext-password-exposure",
    ]
    assert "labels" not in observable and "external_references" not in observable
    assert [r["source_name"] for r in observable["x_opencti_external_references"]] == [
        "Analyst",
        "XposedOrNot",
    ]
    assert objects["identity"]["name"] == "XposedOrNot"
    assert objects["marking-definition"]["id"] == TLP_AMBER_ID
    note = objects["note"]
    assert note["id"] == ObservableNote.stable_id(OBSERVABLE_ID)
    assert note["object_refs"] == [OBSERVABLE_ID]
    assert note["object_marking_refs"] == [TLP_AMBER_ID]
    assert "Sysco" in note["content"] and "Sysco was breached." in note["content"]
    helper.send_stix2_bundle.assert_called_once_with(
        "BUNDLE", update=True, cleanup_inconsistent_bundle=True
    )
    assert data["stix_entity"].get("x_opencti_score") is None


def test_update_score_disabled_leaves_the_existing_score_alone():
    connector, helper, _ = make_connector(update_score=False)
    connector._message_callback(make_data(entity={"x_opencti_score": 12}))
    observable = by_type(helper)["email-addr"]
    assert observable["x_opencti_score"] == 12
    assert "data-breach" in observable["x_opencti_labels"]


def test_plus_result_without_a_score_leaves_the_existing_score_alone():
    result = {**BREACHED, "risk_label": None, "risk_score": None}
    connector, helper, _ = make_connector(result=result)
    connector._message_callback(make_data(entity={"x_opencti_score": 12}))
    assert by_type(helper)["email-addr"]["x_opencti_score"] == 12


@pytest.mark.parametrize("score", ["100", 101, -1, 7.5, True])
def test_unusable_scores_are_not_written(score):
    connector, helper, _ = make_connector(result={**BREACHED, "risk_score": score})
    connector._message_callback(make_data())
    assert "x_opencti_score" not in by_type(helper)["email-addr"]


def test_owned_labels_are_refreshed_not_duplicated():
    result = {
        **BREACHED,
        "breaches": [{**BREACHED["breaches"][0], "password_risk": "unknown"}],
    }
    connector, helper, _ = make_connector(result=result)
    connector._message_callback(
        make_data(
            entity={
                "labels": ["Data-Breach", "plaintext-password-exposure", "keep-me"],
                "x_opencti_labels": ["keep-me"],
            }
        )
    )
    assert by_type(helper)["email-addr"]["x_opencti_labels"] == [
        "keep-me",
        "data-breach",
    ]


def test_own_reference_is_replaced_and_duplicates_collapsed():
    connector, helper, _ = make_connector()
    analyst = {"source_name": "Analyst", "url": "https://a.example"}
    connector._message_callback(
        make_data(
            entity={
                "external_references": [
                    {"source_name": "XposedOrNot", "url": "https://old"},
                    analyst,
                ],
                "x_opencti_external_references": [analyst, "junk"],
            }
        )
    )
    references = by_type(helper)["email-addr"]["x_opencti_external_references"]
    assert references == [
        analyst,
        {
            "source_name": "XposedOrNot",
            "url": "https://xposedornot.com",
            "description": "XposedOrNot breach exposure check",
        },
    ]


def test_note_carries_the_configured_tlp_plus_the_observable_markings():
    connector, helper, _ = make_connector(tlp_level="red")
    connector._message_callback(
        make_data(markings=("TLP:GREEN",), object_marking_refs=[TLP_GREEN_ID, PAP_ID])
    )
    note = by_type(helper)["note"]
    red = PyctiMarkingDefinition.generate_id("TLP", "TLP:RED")
    assert note["object_marking_refs"] == [red, TLP_GREEN_ID, PAP_ID]
    assert by_type(helper)["marking-definition"]["id"] == red


def test_configured_tlp_already_on_the_observable_is_not_duplicated():
    connector, helper, _ = make_connector()
    connector._message_callback(make_data(object_marking_refs=[TLP_AMBER_ID]))
    assert by_type(helper)["note"]["object_marking_refs"] == [TLP_AMBER_ID]


def test_markings_fall_back_to_object_marking_when_the_entity_has_no_refs():
    connector, helper, _ = make_connector()
    data = make_data(markings=("TLP:GREEN",))
    data["enrichment_entity"]["objectMarking"].append(
        {"standard_id": PAP_ID, "definition_type": "PAP", "definition": "PAP:AMBER"}
    )
    connector._message_callback(data)
    assert by_type(helper)["note"]["object_marking_refs"] == [
        TLP_AMBER_ID,
        TLP_GREEN_ID,
        PAP_ID,
    ]


def test_note_is_stable_across_runs_and_its_version_advances():
    connector, helper, _ = make_connector()
    connector._message_callback(make_data())
    first = by_type(helper)["note"]
    connector._message_callback(make_data())
    second = by_type(helper)["note"]
    assert first["id"] == second["id"]
    assert first["created"] == second["created"]
    assert first["created"] == datetime(2024, 5, 1, 10, tzinfo=timezone.utc)
    assert first["created"] <= first["modified"] <= second["modified"]
    assert second["modified"] <= datetime.now(timezone.utc)


def test_observable_missing_from_the_bundle_is_appended():
    connector, helper, _ = make_connector()
    data = make_data()
    data["stix_objects"] = []
    connector._message_callback(data)
    assert by_type(helper)["email-addr"]["id"] == OBSERVABLE_ID


def test_api_error_puts_the_work_in_error_outside_a_playbook():
    connector, helper, client = make_connector()
    client.lookup.side_effect = XposedOrNotError("XposedOrNot: error response")
    with pytest.raises(
        EnrichmentError, match="XposedOrNotError: XposedOrNot: error response"
    ):
        connector._message_callback(make_data())
    helper.send_stix2_bundle.assert_not_called()
    helper.connector_logger.error.assert_called_once()


def test_api_error_forwards_the_bundle_inside_a_playbook():
    connector, helper, client = make_connector()
    client.lookup.side_effect = XposedOrNotError("boom")
    data = make_data(playbook=True)
    assert connector._message_callback(data) == "Internal error (see logs)"
    assert sent_objects(helper) == data["stix_objects"]


def test_logged_errors_never_contain_the_email_or_the_api_key():
    connector, helper, client = make_connector()
    client.api_key = "SECRET-KEY"
    client.lookup.side_effect = RuntimeError(f"failed for {EMAIL} with SECRET-KEY")
    with pytest.raises(EnrichmentError) as raised:
        connector._message_callback(make_data())
    logged = json.dumps(helper.connector_logger.error.call_args.kwargs["meta"])
    assert EMAIL not in logged and "SECRET-KEY" not in logged
    assert "<redacted>" in logged
    assert EMAIL not in str(raised.value) and "SECRET-KEY" not in str(raised.value)
    assert str(raised.value).startswith("RuntimeError: ")
    assert raised.value.__suppress_context__ is True


def test_run_listens_with_the_message_callback():
    connector, helper, _ = make_connector()
    connector.run()
    helper.listen.assert_called_once_with(message_callback=connector._message_callback)


def test_connector_builds_its_client_from_the_settings():
    helper = make_helper()
    connector = XposedOrNotConnector(make_settings(api_key="k"), helper)
    assert connector.client.api_key == "k"
    assert connector.client.base_url == "https://api.xposedornot.com"
    assert connector.converter.max_table_rows == 50


@pytest.mark.parametrize("definition", [None, "", "TLP:PINK", 7, {"level": "amber"}])
def test_unreadable_tlp_marking_is_skipped_not_treated_as_unmarked(definition):
    connector, helper, client = make_connector()
    data = make_data(markings=())
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": definition}
    ]
    message = connector._message_callback(data)
    assert "unreadable or above the maximum allowed" in message
    client.lookup.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_non_tlp_markings_do_not_gate_the_enrichment():
    connector, _, client = make_connector()
    data = make_data(markings=())
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "PAP", "definition": None},
        {"definition_type": "statement", "definition": "internal"},
    ]
    connector._message_callback(data)
    client.lookup.assert_called_once()


def test_markings_from_both_sources_are_merged_on_the_note():
    connector, helper, _ = make_connector()
    data = make_data(markings=("TLP:GREEN",), object_marking_refs=[TLP_GREEN_ID])
    data["enrichment_entity"]["objectMarking"].append(
        {"standard_id": PAP_ID, "definition_type": "PAP", "definition": "PAP:AMBER"}
    )
    connector._message_callback(data)
    assert by_type(helper)["note"]["object_marking_refs"] == [
        TLP_AMBER_ID,
        TLP_GREEN_ID,
        PAP_ID,
    ]


def test_only_exact_duplicate_references_are_collapsed():
    connector, helper, _ = make_connector()
    first = {"source_name": "Analyst", "url": "https://a.example", "description": "one"}
    second = {**first, "description": "two"}
    connector._message_callback(
        make_data(entity={"external_references": [first, second, dict(first)]})
    )
    references = by_type(helper)["email-addr"]["x_opencti_external_references"]
    assert references[:-1] == [first, second]


def test_stix_entity_of_another_type_is_skipped_despite_the_metadata():
    connector, _, client = make_connector()
    data = make_data()
    data["stix_entity"]["id"] = "ipv4-addr--11111111-1111-4111-8111-111111111111"
    message = connector._message_callback(data)
    assert message == "Unsupported entity type: Email-Addr"
    client.lookup.assert_not_called()


def test_tlp_reference_without_a_resolved_marking_still_gates():
    connector, _, client = make_connector()
    red = PyctiMarkingDefinition.generate_id("TLP", "TLP:RED")
    message = connector._message_callback(
        make_data(markings=(), object_marking_refs=[red])
    )
    assert "'TLP:RED'" in message and "skipping" in message
    client.lookup.assert_not_called()


def test_bundled_tlp_definition_behind_an_unknown_reference_gates():
    connector, _, client = make_connector()
    ref = "marking-definition--22222222-2222-4222-8222-222222222222"
    data = make_data(markings=(), object_marking_refs=[ref])
    data["stix_objects"].append(
        {
            "type": "marking-definition",
            "id": ref,
            "definition_type": "TLP",
            "name": "TLP:RED",
        }
    )
    message = connector._message_callback(data)
    assert "'TLP:RED'" in message
    client.lookup.assert_not_called()
    data["stix_objects"][-1]["name"] = "TLP:GREEN"
    connector._message_callback(data)
    client.lookup.assert_called_once()


def test_unknown_non_tlp_reference_does_not_gate():
    connector, _, client = make_connector()
    connector._message_callback(make_data(markings=(), object_marking_refs=[PAP_ID]))
    client.lookup.assert_called_once()
