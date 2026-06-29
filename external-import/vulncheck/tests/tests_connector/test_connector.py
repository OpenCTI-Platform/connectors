from connector.settings import ConnectorSettings


def test_connector_instantiation(correct_config):
    """Test that the connector can be instantiated with correct config."""
    config = ConnectorSettings()
    assert config.vulncheck.api_key.get_secret_value() == "test_api_key"
    assert "api.vulncheck.com/v3" in str(config.vulncheck.api_base_url)
    assert config.vulncheck.data_sources == "vulncheck-kev,nist-nvd2"


def test_connector_deprecated_namespace(deprecated_config):
    """Test that the deprecated CONNECTOR_VULNCHECK_ prefix still works."""
    config = ConnectorSettings()
    assert config.vulncheck.api_key.get_secret_value() == "test_api_key"
    assert "api.vulncheck.com/v3" in str(config.vulncheck.api_base_url)
