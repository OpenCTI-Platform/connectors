import pytest
from base_connector import ConfigRetrievalError
from email_intel_microsoft.config import ConnectorSettings
from main import main


def test_main_invalid_configuration() -> None:
    # Make sure there s no config file loaded
    ConnectorSettings.model_config["yaml_file"] = ""
    ConnectorSettings.model_config["env_file"] = ""
    with pytest.raises(ConfigRetrievalError) as exc_info:
        main()
    assert "Invalid OpenCTI configuration." == exc_info.value.args[0]
