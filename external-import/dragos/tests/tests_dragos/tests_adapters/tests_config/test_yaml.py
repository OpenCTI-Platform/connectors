"""Offer tests for the config.yaml variable configuration loader."""

import builtins
from unittest.mock import mock_open, patch

import pytest
from dragos.adapters.config.yaml import ConfigLoaderYAML
from dragos.interfaces.config import ConfigRetrievalError


@pytest.fixture
def config_yaml_at_path(tmp_path):
    """Create a simulated YAML config file."""
    mock_file = mock_open(
        read_data="""
opencti:
    url: "https://example.com"
    token: "example_token"
connector:
    id: "connector_123"
    name: "ExampleConnector"
    scope: ["scope1", "scope2"]
    log_level: "info"
    duration_period: "PT30M"
    queue_threshold: 10
    run_and_terminate: false
dragos:
    api_base_url: "https://api.dragos.com"
    api_token: "dragos_token"
    api_secret: "dragos_secret"
    import_start_date: "2023-01-01T00:00:00Z"
    tlp_level: "amber"
"""
    )

    def open_side_effect(file, *args, **kwargs):
        return mock_file(file, *args, **kwargs)

    with patch.object(builtins, "open", side_effect=open_side_effect):
        yield


def test_config_loader_yaml_loads_correctly(config_yaml_at_path):
    """Test that the ConfigLoaderYAML loads the configuration from a YAML file."""
    # Given a valid YAML configuration file
    # When loading the configuration
    # Then the configuration should be loaded without error
    _ = ConfigLoaderYAML.from_yaml_path("config.yaml")


def test_config_loader_yaml_missing_file():
    """Test that the ConfigLoaderYAML raises ConfigRetrievalError when the file is missing."""
    # Given a missing YAML configuration file
    # When loading the configuration
    # Then the configuration should raise a ConfigRetrievalError
    with pytest.raises(ConfigRetrievalError):
        _ = ConfigLoaderYAML.from_yaml_path("non_existent_config.yaml")
