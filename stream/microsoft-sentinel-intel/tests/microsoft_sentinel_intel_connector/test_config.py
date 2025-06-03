import pytest
from microsoft_sentinel_intel_connector.config import ConnectorSettings
from pydantic import HttpUrl


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_config() -> None:
    config = ConnectorSettings().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    assert config["opencti"]["token"] == "test-opencti-token"

    assert config["connector"]["id"] == "test-connector-id"
    assert config["connector"]["name"] == "External Import Connector Template"
    assert config["connector"]["scope"] == ["ChangeMe"]
    assert config["connector"]["live_stream_id"] == "live-stream-id"

    microsoft_sentinel_intel = config["microsoft_sentinel_intel"]
    assert len(microsoft_sentinel_intel) == 12
    assert microsoft_sentinel_intel["client_id"] == "ChangeMe"
    assert microsoft_sentinel_intel["client_secret"] == "ChangeMe"
    assert microsoft_sentinel_intel["delete_extensions"] == True
    assert microsoft_sentinel_intel["extra_labels"] == ["label1", "label2"]
    assert microsoft_sentinel_intel["management_api_version"] == "2025-03-01"
    assert microsoft_sentinel_intel["resource_group"] == "default"
    assert microsoft_sentinel_intel["source_system"] == "Opencti Stream Connector"
    assert microsoft_sentinel_intel["subscription_id"] == "ChangeMe"
    assert microsoft_sentinel_intel["tenant_id"] == "ChangeMe"
    assert microsoft_sentinel_intel["workspace_api_version"] == "2024-02-01-preview"
    assert microsoft_sentinel_intel["workspace_id"] == "ChangeMe"
    assert microsoft_sentinel_intel["workspace_name"] == "ChangeMe"
