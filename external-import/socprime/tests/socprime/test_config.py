import pytest
from pydantic import HttpUrl
from socprime import SocprimeConnector
from socprime.config import ConnectorSettings

pytestmark = pytest.mark.usefixtures(
    "mocked_opencti_helper",
    "mock_socprime_config",
    "mocked_mitre_attack_requests",
)


def test_config_helper() -> None:
    connector = SocprimeConnector()

    assert connector.helper.opencti_url == "http://test-opencti-url/"
    assert connector.helper.opencti_token == "test-opencti-token"

    assert connector.helper.connect_id == "test-connector-id"
    assert connector.helper.connect_name == "Soc Prime"
    assert connector.helper.connect_type == "EXTERNAL_IMPORT"
    assert connector.helper.connect_scope == "socprime"
    assert connector.helper.log_level == "ERROR"


def test_config_settings() -> None:
    config = ConnectorSettings().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    assert config["opencti"]["token"] == "test-opencti-token"

    assert config["connector"]["id"] == "test-connector-id"
    assert config["connector"]["name"] == "Soc Prime"
    assert config["connector"]["type"] == "EXTERNAL_IMPORT"
    assert config["connector"]["scope"] == ["socprime"]
    assert config["connector"]["log_level"] == "error"

    assert len(config["socprime"]) == 6
    assert config["socprime"]["api_key"] == "api-key"
    assert config["socprime"]["content_list_name"] == ["name1", "name2"]
    assert config["socprime"]["job_ids"] == ["job1", "job2"]
    assert config["socprime"]["siem_type"] == ["devo", "snowflake"]
    assert config["socprime"]["indicator_siem_type"] == "ChangeMe"
    assert config["socprime"]["interval_sec"] == 2000
