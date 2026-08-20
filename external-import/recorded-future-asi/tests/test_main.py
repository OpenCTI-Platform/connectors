from connector import ConnectorSettings, RecordedFutureAsiConnector


def test_connector_settings_is_instantiated(stub_connector_settings):
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    assert isinstance(stub_connector_settings, ConnectorSettings)
    assert isinstance(stub_connector_settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(opencti_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict
    """
    assert opencti_helper.opencti_url == "http://localhost:8080/"
    assert opencti_helper.opencti_token == "test-token"
    assert opencti_helper.connect_id == "connector-id"
    assert opencti_helper.connect_name == "Test Connector"
    assert opencti_helper.connect_scope == "incident"
    assert opencti_helper.log_level == "ERROR"
    assert opencti_helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(opencti_helper, stub_connector_settings):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`
    """
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )

    assert connector.config == stub_connector_settings
    assert connector.helper == opencti_helper
