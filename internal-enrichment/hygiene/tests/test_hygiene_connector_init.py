from unittest.mock import MagicMock

import pytest
from src.connector.hygiene import HygieneConnector
from src.connector.services.config_loader import ConfigLoader

DEFAULT_WARNINGLISTS_SLOW_SEARCH = False
DEFAULT_ENRICH_SUBDOMAINS = False
DEFAULT_LABEL_NAME = "hygiene"
DEFAULT_LABEL_COLOR = "#fc0341"
DEFAULT_LABEL_PARENT_NAME = "hygiene_parent"


@pytest.mark.usefixtures("mock_opencti")
def test_hygiene_connector_default_settings(mock_config, mock_helper):
    hygiene_connector = HygieneConnector(mock_config, mock_helper)

    assert isinstance(hygiene_connector, HygieneConnector)
    assert (
        hygiene_connector.warninglists_slow_search == DEFAULT_WARNINGLISTS_SLOW_SEARCH
    )
    assert hygiene_connector.enrich_subdomains == DEFAULT_ENRICH_SUBDOMAINS
    assert hygiene_connector.hygiene_label_name == DEFAULT_LABEL_NAME
    assert hygiene_connector.hygiene_label_color == DEFAULT_LABEL_COLOR
    assert hygiene_connector.hygiene_label_parent_name == DEFAULT_LABEL_PARENT_NAME
    assert hygiene_connector.hygiene_label_parent_color == DEFAULT_LABEL_COLOR


@pytest.mark.usefixtures("mock_opencti")
def test_hygiene_connector_settings_env_parsing(sample_config_path):
    config = ConfigLoader(sample_config_path)
    helper = MagicMock()
    hygiene_connector = HygieneConnector(config, helper)
    # hygiene_connector = HygieneConnector(sample_config_path)
    assert isinstance(hygiene_connector, HygieneConnector)
    assert hygiene_connector.hygiene_label_name == "hygiene"
    assert hygiene_connector.hygiene_label_color == "#fc0341"
    assert hygiene_connector.hygiene_label_parent_name == "hygiene_parent"
    assert hygiene_connector.hygiene_label_parent_color == "#fc0341"
