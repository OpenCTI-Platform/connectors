from unittest.mock import MagicMock

import pytest
from connector import MicrosoftDefenderIncidentsConnector
from connector.case_index import CaseIncidentIndex
from connector.utils import format_datetime
from pycti import CaseIncident

_NEW_ID = "11111111-1111-4111-8111-111111111111"
_CLOSED_ID = "22222222-2222-4222-8222-222222222222"
_AUTHOR_INTERNAL_ID = "author-internal-id"

_ALERT = {
    "title": "Suspicious sign-in",
    "createdDateTime": "2026-11-20T10:30:00Z",
    "lastUpdateDateTime": "2026-11-20T11:00:00Z",
    "category": "InitialAccess",
    "description": "Test description",
    "recommendedActions": "Reset password",
    "alertWebUrl": "https://security.microsoft.com/alerts/a1",
    "id": "alert-1",
    "severity": "medium",
    "mitreTechniques": [],
    "evidence": [],
}


def _incident(**overrides) -> dict:
    incident = {
        "id": "11046",
        "displayName": "Initial access incident involving one user",
        "createdDateTime": "2026-11-20T10:00:00Z",
        "lastUpdateDateTime": "2026-11-27T12:00:00Z",
        "status": "redirected",
        "classification": "truePositive",
        "determination": "compromisedAccount",
        "severity": "medium",
        "incidentWebUrl": "https://security.microsoft.com/incidents/11046",
        "alerts": [_ALERT],
    }
    incident.update(overrides)
    return incident


def _case_node(
    internal_id, name, incident_id, status_id, labels=(), updated_at="2026-11-25"
):
    return {
        "id": internal_id,
        "standard_id": CaseIncident.generate_id(
            name, format_datetime("2026-11-20T10:00:00Z")
        ),
        "name": name,
        "updated_at": updated_at,
        "status": {"id": status_id} if status_id else None,
        "objectLabel": [{"id": f"label-{value}", "value": value} for value in labels],
        "externalReferences": {
            "edges": [
                {
                    "node": {
                        "source_name": "Microsoft Defender",
                        "external_id": incident_id,
                    }
                }
            ]
        },
    }


def _cases_answer(nodes, has_next=False, cursor=None):
    return {
        "data": {
            "caseIncidents": {
                "edges": [{"node": node} for node in nodes],
                "pageInfo": {"endCursor": cursor, "hasNextPage": has_next},
            }
        }
    }


def _statuses_answer():
    return {
        "data": {
            "statuses": {
                "edges": [
                    {"node": {"id": _NEW_ID, "template": {"name": "NEW"}}},
                    {"node": {"id": _CLOSED_ID, "template": {"name": "CLOSED"}}},
                ]
            }
        }
    }


def _route_queries(cases_pages):
    """api.query answers the statuses query, then the Case-Incident pages in order."""
    pages = list(cases_pages)

    def query(text, variables=None):
        if "CaseIncidentStatuses" in text:
            return _statuses_answer()
        return pages.pop(0)

    return query


@pytest.fixture
def connector(mock_helper, mock_config):
    mdi = mock_config.microsoft_defender_incidents
    mdi.status_mapping = (
        "active:NEW,inProgress:IN_PROGRESS,awaitingAction:IN_PROGRESS,"
        "resolved:CLOSED,redirected:CLOSED"
    )
    mdi.reconcile = True
    mdi.reconcile_max_incidents = 100
    mock_helper.get_state.return_value = {"last_incident_timestamp": 1795849074}
    mock_helper.api.identity.read.return_value = {"id": _AUTHOR_INTERNAL_ID}
    mock_helper.api.work.initiate_work.return_value = "work-id"
    mock_helper.stix2_create_bundle.side_effect = lambda objects: objects
    conn = MicrosoftDefenderIncidentsConnector(config=mock_config, helper=mock_helper)
    conn.client = MagicMock()
    conn.client.get_incidents.return_value = []
    return conn


def _sent_cases(mock_helper):
    objects = mock_helper.send_stix2_bundle.call_args.args[0]
    return [obj for obj in objects if getattr(obj, "type", None) == "case-incident"]


def test_redirected_incident_never_updated_again_is_closed_by_reconcile(
    connector, mock_helper
):
    name = "Initial access incident involving one user"
    mock_helper.api.query.side_effect = _route_queries(
        [
            _cases_answer(
                [
                    _case_node(
                        "case-1",
                        name,
                        "11046",
                        _NEW_ID,
                        labels=["defender-status:redirected"],
                    )
                ]
            )
        ]
    )
    connector.client.get_incident.return_value = _incident(status="redirected")

    connector.process_message()

    connector.client.get_incident.assert_called_once_with("11046")
    cases = _sent_cases(mock_helper)
    assert len(cases) == 1
    assert cases[0]["x_opencti_workflow_id"] == _CLOSED_ID
    # The reconciled incident is outside the window: the state does not move backwards
    saved = mock_helper.set_state.call_args
    assert saved is None or saved.args[0]["last_incident_timestamp"] >= 1795849074


def test_reconcile_skips_closed_cases_and_404(connector, mock_helper):
    mock_helper.api.query.side_effect = _route_queries(
        [
            _cases_answer(
                [
                    _case_node("case-closed", "Closed one", "100", _CLOSED_ID),
                    _case_node("case-gone", "Gone one", "200", _NEW_ID),
                ]
            )
        ]
    )
    connector.client.get_incident.return_value = None

    connector.process_message()

    connector.client.get_incident.assert_called_once_with("200")
    mock_helper.send_stix2_bundle.assert_not_called()


def test_reconcile_is_bounded_least_recently_updated_first(connector, mock_helper):
    connector.config.microsoft_defender_incidents.reconcile_max_incidents = 2
    mock_helper.api.query.side_effect = _route_queries(
        [
            _cases_answer(
                [
                    _case_node("c1", "One", "1", _NEW_ID, updated_at="2026-11-26"),
                    _case_node("c2", "Two", "2", _NEW_ID, updated_at="2026-11-21"),
                    _case_node("c3", "Three", "3", _NEW_ID, updated_at="2026-11-23"),
                ]
            )
        ]
    )
    connector.client.get_incident.return_value = None

    connector.process_message()

    called = [call.args[0] for call in connector.client.get_incident.call_args_list]
    assert called == ["2", "3"]


def test_renamed_incident_updates_the_same_case(connector, mock_helper):
    old_name = "Etienne Bonneau watch: successful sign-in"
    old_node = _case_node(
        "case-old", old_name, "11046", _NEW_ID, labels=["defender-status:active"]
    )
    mock_helper.api.query.side_effect = _route_queries([_cases_answer([old_node])])
    connector.client.get_incidents.return_value = [_incident(status="resolved")]

    connector.process_message()

    cases = _sent_cases(mock_helper)
    assert len(cases) == 1
    assert cases[0].id == old_node["standard_id"]
    assert cases[0].name == "Initial access incident involving one user"
    assert cases[0]["x_opencti_workflow_id"] == _CLOSED_ID
    connector.client.get_incident.assert_not_called()


def test_existing_rename_duplicates_both_converge_without_name_clash(
    connector, mock_helper
):
    new_name = "Initial access incident involving one user"
    old_name = "Etienne Bonneau watch: successful sign-in"
    old_node = _case_node(
        "case-old", old_name, "11046", _NEW_ID, updated_at="2026-11-24"
    )
    new_node = _case_node(
        "case-new", new_name, "11046", _NEW_ID, updated_at="2026-11-27"
    )
    mock_helper.api.query.side_effect = _route_queries(
        [_cases_answer([old_node, new_node])]
    )
    connector.client.get_incident.return_value = _incident(status="redirected")

    connector.process_message()

    cases = {case.id: case for case in _sent_cases(mock_helper)}
    assert set(cases) == {old_node["standard_id"], new_node["standard_id"]}
    assert cases[new_node["standard_id"]].name == new_name
    assert cases[old_node["standard_id"]].name == old_name
    assert all(case["x_opencti_workflow_id"] == _CLOSED_ID for case in cases.values())


def test_never_seen_incident_keeps_the_derived_id(connector, mock_helper):
    mock_helper.api.query.side_effect = _route_queries([_cases_answer([])])
    incident = _incident(id="99999", status="active")
    connector.client.get_incidents.return_value = [incident]

    connector.process_message()

    cases = _sent_cases(mock_helper)
    assert len(cases) == 1
    assert cases[0].id == CaseIncident.generate_id(
        incident["displayName"], format_datetime("2026-11-20T10:00:00Z")
    )


def test_labels_are_replaced_not_stacked(connector, mock_helper):
    node = _case_node(
        "case-1",
        "Initial access incident involving one user",
        "11046",
        _NEW_ID,
        labels=[
            "defender-status:active",
            "defender-status:resolved",
            "defender-classification:unknown",
            "defender-determination:compromisedaccount",
            "InitialAccess",
        ],
    )
    mock_helper.api.query.side_effect = _route_queries([_cases_answer([node])])
    connector.client.get_incidents.return_value = [_incident(status="resolved")]

    connector.process_message()

    removed = {
        call.kwargs["label_id"]
        for call in mock_helper.api.stix_domain_object.remove_label.call_args_list
    }
    assert removed == {
        "label-defender-status:active",
        "label-defender-classification:unknown",
    }
    for call in mock_helper.api.stix_domain_object.remove_label.call_args_list:
        assert call.kwargs["id"] == "case-1"


def test_mapping_off_behaviour_unchanged(connector, mock_helper):
    connector.config.microsoft_defender_incidents.status_mapping = ""
    connector.converter_to_stix.status_mapping = {}
    mock_helper.api.query.side_effect = _route_queries(
        [_cases_answer([_case_node("case-1", "Open", "1", None)])]
    )

    connector.process_message()

    connector.client.get_incident.assert_not_called()
    mock_helper.send_stix2_bundle.assert_not_called()


def test_reconcile_toggle_off(connector, mock_helper):
    connector.config.microsoft_defender_incidents.reconcile = False
    mock_helper.api.query.side_effect = _route_queries(
        [_cases_answer([_case_node("case-1", "Open", "1", _NEW_ID)])]
    )

    connector.process_message()

    connector.client.get_incident.assert_not_called()


def test_case_listing_failure_keeps_the_previous_behaviour(connector, mock_helper):
    def query(text, variables=None):
        if "CaseIncidentStatuses" in text:
            return _statuses_answer()
        raise RuntimeError("listing failed")

    mock_helper.api.query.side_effect = query
    incident = _incident(id="5", status="active")
    connector.client.get_incidents.return_value = [incident]

    connector.process_message()

    connector.client.get_incident.assert_not_called()
    mock_helper.api.stix_domain_object.remove_label.assert_not_called()
    cases = _sent_cases(mock_helper)
    assert cases[0].id == CaseIncident.generate_id(
        incident["displayName"], format_datetime("2026-11-20T10:00:00Z")
    )


def test_case_index_paginates_and_indexes_by_defender_id(mock_helper):
    mock_helper.api.identity.read.return_value = {"id": _AUTHOR_INTERNAL_ID}
    mock_helper.api.query.side_effect = [
        _cases_answer([_case_node("a", "A", "1", _NEW_ID)], True, "cursor-1"),
        _cases_answer([_case_node("b", "B", "2", _CLOSED_ID)]),
    ]
    index = CaseIncidentIndex(mock_helper)

    index.load("identity--x")

    assert set(index.cases) == {"1", "2"}
    second_call = mock_helper.api.query.call_args_list[1]
    assert second_call.args[1]["after"] == "cursor-1"
    first_filters = mock_helper.api.query.call_args_list[0].args[1]["filters"]
    assert first_filters["filters"][0] == {
        "key": "createdBy",
        "values": [_AUTHOR_INTERNAL_ID],
    }
    assert index.open_incident_ids({_CLOSED_ID}) == ["1"]


def test_case_index_first_run_without_author(mock_helper):
    mock_helper.api.identity.read.return_value = None
    index = CaseIncidentIndex(mock_helper)

    index.load("identity--x")

    assert index.cases == {}
    mock_helper.api.query.assert_not_called()
