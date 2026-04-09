import pytest
from connector import ConnectorSettings
from connectors_sdk.models.enums import RelationshipType


def test_connector_settings_is_instantiated(mock_connector_settings):
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    assert isinstance(mock_connector_settings, ConnectorSettings)
    assert isinstance(mock_connector_settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    assert mock_connector_helper.opencti_url == "http://localhost:8080/"
    assert mock_connector_helper.opencti_token == "test-token"
    assert mock_connector_helper.connect_id == "connector-id"
    assert mock_connector_helper.connect_name == "Test Connector"
    assert mock_connector_helper.connect_scope == "test,connector"
    assert mock_connector_helper.log_level == "ERROR"
    assert mock_connector_helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(
    mock_connector, mock_connector_settings, mock_connector_helper
):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_connector: Fixture - MontySecurityC2TrackerConnector is mocked
    :param mock_connector_settings: Fixture - Connector Settings is mocked
    :param mock_connector_helper: Fixture - `OpenCTIConnectorHelper` is mocked
    """
    assert mock_connector.config == mock_connector_settings
    assert mock_connector.helper == mock_connector_helper


@pytest.mark.parametrize(
    "malware_list, ips, expected_ip_count, expected_entities",
    [
        ([], [], 0, 0),
        (['"Malware01"'], ["8.8.8.8"], 1, 5),
        (['"Malware02"'], ["2001:db8::1"], 1, 5),
        (['"Malware03"'], ["bad-ip"], 0, 3),
        (['"Malware04"'], ["1.2.3.4", "2001:db8::2"], 2, 7),
        (['"Malware05"', '"Malware06"'], ["8.8.8.8", "2001:db8::1"], 4, 12),
    ],
    ids=[
        "No_malware",
        "IPv4_single",
        "IPv6_single",
        "Invalid_IP_skipped",
        "Multi_IP_valid",
        "Multiple_malware",
    ],
)
def test_collect_intelligence(
    mock_connector, malware_list, ips, expected_ip_count, expected_entities
):

    mock_connector.client.get_malware_list.return_value = malware_list
    mock_connector.client.get_ips.return_value = ips

    entities = mock_connector._collect_intelligence()
    observable_list = [
        observable
        for observable in entities
        if observable.__class__.__name__ in ("IPV4Address", "IPV6Address")
    ]
    # Check that we have the final number of observable correct
    assert len(observable_list) == expected_ip_count

    entities_list = [
        entitie
        for entitie in entities
        if entitie.__class__.__name__
        in (
            "IPV4Address",
            "IPV6Address",
            "Malware",
            "Relationship",
            "TLPMarking",
            "OrganizationAuthor",
        )
    ]
    # Check that we have the final number of entities correct.
    assert len(entities_list) == expected_entities

    relationship_list = [
        relationship
        for relationship in entities
        if relationship.__class__.__name__ == "Relationship"
    ]
    for relationship in relationship_list:
        assert relationship.source.__class__.__name__ in ("IPV4Address", "IPV6Address")
        assert relationship.target.__class__.__name__ == "Malware"
        # Check that the relationship type is "related_to"
        assert relationship.type == RelationshipType.RELATED_TO
