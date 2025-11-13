from unittest.mock import Mock

import pytest
from src.connector.connector import ConnectorServicenow


def test_invalid_retrieved_entity_should_be_skipped_with_warning():
    # Given
    # a connector instance with a fake api client response that return a malformed entity with invalid values
    config = Mock()
    config.servicenow.tlp_level = "clear"

    config.servicenow.api_leaky_bucket_rate = 10
    config.servicenow.api_leaky_bucket_capacity = 10

    connector_instance = ConnectorServicenow(config=config, helper=Mock())
    invalid_data = [{"get_security_incident": {"invalid": "data"}}]

    # When the connector _valid_intelligence is called
    connector_instance._valid_intelligence(invalid_data)
    # Then a warning should be emitted and the process should (continue (not raise an error)
    pass


test_observable_handling_labels = (
    {
        "sys_tags": ["tag1", "", "unknown"],
        "security_tags": ["secure1", None],
        "finding": ["find1", "unknown"],
    },
    True,
    False,
    False,
    ["tag1", "secure1", "find1"],
)

test_task_handling_labels = (
    {
        "sys_tags": ["tag2", ""],
        "security_tags": ["unknown", "secure2"],
    },
    False,
    True,
    False,
    ["tag2", "secure2"],
)

test_security_incident_handling_labels = (
    {
        "subcategory": ["sub1", "unknown"],
        "sys_tags": ["tag3", None],
        "security_tags": ["secure3", ""],
        "contact_type": ["contact1"],
        "alert_sensor": [None, "sensor1"],
    },
    False,
    False,
    True,
    ["sub1", "tag3", "secure3", "contact1", "sensor1"],
)


@pytest.mark.parametrize(
    "entity_attrs, observable, task, security_incident, expected",
    [
        test_observable_handling_labels,
        test_task_handling_labels,
        test_security_incident_handling_labels,
    ],
    ids=[
        "Aggregate and filter labels for Observable entity",
        "Aggregate and filter labels for Task entity",
        "Aggregate and filter labels for Security Incident entity",
    ],
)
def test_handling_labels(entity_attrs, observable, task, security_incident, expected):
    entity = Mock()
    for key, value in entity_attrs.items():
        setattr(entity, key, value)

    result = ConnectorServicenow._handling_labels(
        entity=entity,
        observable=observable,
        task=task,
        security_incident=security_incident,
    )
    assert sorted(result) == sorted(expected)
