import pytest
from hygiene import HygieneConnector

DEFAULT_LABEL_NAME = "hygiene"
DEFAULT_LABEL_COLOR = "#fc0341"
DEFAULT_LABEL_PARENT_NAME = "hygiene_parent"


@pytest.mark.usefixtures("mock_opencti")
def test_hygiene_connector_default_settings():
    hygiene_connector = HygieneConnector()
    assert isinstance(hygiene_connector, HygieneConnector)
    assert hygiene_connector.hygiene_label_name == DEFAULT_LABEL_NAME
    assert hygiene_connector.hygiene_label_color == DEFAULT_LABEL_COLOR
    assert hygiene_connector.hygiene_label_parent_name == DEFAULT_LABEL_PARENT_NAME
    assert hygiene_connector.hygiene_label_parent_color == DEFAULT_LABEL_COLOR


@pytest.mark.usefixtures("mock_opencti")
def test_hygiene_connector_settings_env_parsing(sample_config_path):
    hygiene_connector = HygieneConnector(sample_config_path)
    assert isinstance(hygiene_connector, HygieneConnector)
    assert hygiene_connector.hygiene_label_name == "hygiene-label-name"
    assert hygiene_connector.hygiene_label_color == "#fc0340"
    assert hygiene_connector.hygiene_label_parent_name == "hygiene-parent-label-name"
    assert hygiene_connector.hygiene_label_parent_color == "#fc0330"
