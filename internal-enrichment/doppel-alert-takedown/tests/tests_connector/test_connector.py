from unittest.mock import MagicMock

import pytest
from connector.connector import DoppelConnector
from connector.converter_to_stix import ConverterToStix
from doppel_client import DoppelClientError


@pytest.fixture
def connector():
    instance = DoppelConnector.__new__(DoppelConnector)
    instance.helper = MagicMock()
    instance.helper.check_max_tlp.return_value = True
    instance.helper.connector_id = "connector--doppel-takedown"
    instance.helper.api.query.return_value = {
        "data": {
            "connector": {
                "auto": False,
                "auto_update": False,
                "connector_trigger_filters": None,
            }
        }
    }
    instance.config = MagicMock()
    instance.config.connector.scope = ["Url", "Domain-Name", "Incident"]
    instance.config.connector.auto = False
    instance.config.connector.auto_update = False
    instance.config.doppel_alert_takedown.takedown_comment = "Confirmed by OpenCTI."
    instance.config.doppel_alert_takedown.max_tlp = "TLP:RED"
    instance.config.doppel_alert_takedown.tags = []
    instance.client = MagicMock()
    instance.client.get_alert.return_value = {
        "id": "ACM-1234",
        "entity": "phishing.example",
        "archetype": "domains",
        "doppel_link": "https://app.doppel.com/alerts/ACM-1234",
        "queue_state": "monitoring",
    }
    instance.converter_to_stix = ConverterToStix(helper=instance.helper)
    instance.tlp = None
    instance.stix_objects_list = []
    return instance


def _incident(**overrides):
    incident = {
        "type": "incident",
        "id": "incident--78774b13-7c25-5ef7-9cb1-fb859691a481",
        "name": "Doppel Alert - phishing.example (ACM-1234)",
        "source": "Doppel",
        "incident_type": "doppel_domains",
        "labels": ["queue_state:monitoring"],
        "external_references": [
            {
                "source_name": "Doppel",
                "external_id": "ACM-1234",
                "url": "https://app.doppel.com/alerts/ACM-1234",
            }
        ],
    }
    incident.update(overrides)
    return incident


def test_incident_alert_reference_uses_doppel_external_id(connector):
    alert = connector._incident_alert_reference(_incident(), {})

    assert alert == {
        "id": "ACM-1234",
        "doppel_link": "https://app.doppel.com/alerts/ACM-1234",
        "entity": "Doppel Alert - phishing.example (ACM-1234)",
        "archetype": "doppel_domains",
    }


def test_incident_alert_reference_supports_resolved_opencti_references(connector):
    incident = _incident(external_references=[])
    opencti_entity = {
        "externalReferences": {
            "edges": [
                {
                    "node": {
                        "source_name": "Doppel Alert",
                        "external_id": "ACM-1234",
                    }
                }
            ]
        }
    }

    alert = connector._incident_alert_reference(incident, opencti_entity)

    assert alert["id"] == "ACM-1234"


def test_incident_alert_reference_matches_id_in_name_among_user_references(connector):
    incident = _incident(
        external_references=[
            {
                "source_name": "Customer",
                "external_id": "CASE-88",
            },
            {
                "source_name": "API",
                "external_id": "ACM-1234",
            },
        ]
    )

    alert = connector._incident_alert_reference(incident, {})

    assert alert["id"] == "ACM-1234"


def test_incident_alert_reference_rejects_non_doppel_incident(connector):
    incident = _incident(
        name="Unrelated incident",
        source="Other",
        incident_type="phishing",
    )

    with pytest.raises(ValueError, match="not managed by Doppel"):
        connector._incident_alert_reference(incident, {})


def test_incident_alert_reference_rejects_mismatched_external_id(connector):
    incident = _incident(
        external_references=[
            {
                "source_name": "Doppel",
                "external_id": "ACM-9999",
                "url": "https://app.doppel.com/alerts/ACM-9999",
            }
        ]
    )

    with pytest.raises(ValueError, match="do not match"):
        connector._incident_alert_reference(incident, {})


def test_collect_incident_takedown_updates_existing_alert_by_id(connector):
    connector.client.request_takedown.return_value = {
        "id": "ACM-1234",
        "entity": "phishing.example",
        "archetype": "domains",
        "doppel_link": "https://app.doppel.com/alerts/ACM-1234",
    }

    stix_objects = connector._collect_incident_takedown(_incident(), {})

    connector.client.get_alert.assert_called_once_with(alert_id="ACM-1234")
    connector.client.request_takedown.assert_called_once_with(
        alert_id="ACM-1234",
        comment="Confirmed by OpenCTI.",
    )
    connector.client.create_alert.assert_not_called()
    note = next(
        stix_object for stix_object in stix_objects if stix_object.type == "note"
    )
    assert "Takedown requested: Confirmed by OpenCTI." in note.content
    assert note.object_refs == ["incident--78774b13-7c25-5ef7-9cb1-fb859691a481"]


def test_collect_incident_takedown_records_failure_without_creating_alert(connector):
    connector.client.request_takedown.side_effect = DoppelClientError("failed")

    stix_objects = connector._collect_incident_takedown(_incident(), {})

    connector.client.create_alert.assert_not_called()
    note = next(
        stix_object for stix_object in stix_objects if stix_object.type == "note"
    )
    assert "Takedown request failed" in note.content


def test_collect_incident_takedown_rejects_existing_takedown_state(connector):
    connector.client.get_alert.return_value["queue_state"] = "actioned"

    with pytest.raises(ValueError, match="already in a takedown state"):
        connector._collect_incident_takedown(_incident(), {})

    connector.client.request_takedown.assert_not_called()


@pytest.mark.parametrize("queue_state", [None, "unexpected"])
def test_collect_incident_takedown_rejects_invalid_preflight_state(
    connector, queue_state
):
    connector.client.get_alert.return_value["queue_state"] = queue_state

    with pytest.raises(ValueError, match="invalid alert"):
        connector._collect_incident_takedown(_incident(), {})

    connector.client.request_takedown.assert_not_called()


def test_collect_incident_takedown_rejects_platform_trigger_filters(connector):
    connector.helper.api.query.return_value["data"]["connector"][
        "connector_trigger_filters"
    ] = '{"mode":"and","filters":[],"filterGroups":[]}'

    with pytest.raises(ValueError, match="Automatic connector triggers"):
        connector._collect_incident_takedown(_incident(), {})

    connector.client.request_takedown.assert_not_called()


def test_collect_incident_takedown_prefers_live_doppel_state_over_stale_label(
    connector,
):
    connector.client.request_takedown.return_value = {"id": "ACM-1234"}

    connector._collect_incident_takedown(
        _incident(labels=["queue_state:actioned"]),
        {},
    )

    connector.client.request_takedown.assert_called_once()


def test_collect_incident_takedown_preflights_each_repeat_request(connector):
    connector.client.request_takedown.return_value = {"id": "ACM-1234"}
    connector.client.get_alert.side_effect = [
        {"id": "ACM-1234", "queue_state": "monitoring"},
        {"id": "ACM-1234", "queue_state": "actioned"},
    ]
    incident = _incident()

    connector._collect_incident_takedown(incident, {})
    with pytest.raises(ValueError, match="already in a takedown state"):
        connector._collect_incident_takedown(incident, {})

    assert connector.client.get_alert.call_count == 2
    connector.client.request_takedown.assert_called_once()


def test_observable_takedown_prefers_created_alert_id(connector):
    connector.client.create_alert.return_value = {
        "id": "ACM-1234",
        "entity": "phishing.example",
        "archetype": "domains",
    }
    connector.client.request_takedown.return_value = {"id": "ACM-1234"}

    connector._collect_intelligence(
        "domain-name",
        "phishing.example",
        "domain-name--3f2d90f7-f3e0-5fe2-bd66-130ecb06d4eb",
    )

    connector.client.request_takedown.assert_called_once_with(
        alert_id="ACM-1234",
        entity=None,
        comment="Confirmed by OpenCTI.",
    )


def test_process_message_routes_incidents_without_reading_observable_value(connector):
    incident = _incident()
    data = {
        "stix_objects": [incident],
        "stix_entity": incident,
        "enrichment_entity": {
            "entity_type": "Incident",
            "objectMarking": [],
        },
    }
    connector._collect_incident_takedown = MagicMock(return_value=["note"])
    connector._send_bundle = MagicMock(return_value="sent")

    result = connector.process_message(data)

    assert result == "sent"
    connector._collect_incident_takedown.assert_called_once_with(
        incident, data["enrichment_entity"]
    )
