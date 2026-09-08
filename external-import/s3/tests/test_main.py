from typing import Any
from unittest.mock import MagicMock

import pytest
import stix2
from pycti import OpenCTIConnectorHelper
from s3 import S3Connector
from settings import ConnectorSettings


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "S3 Bucket",
                    "scope": "s3",
                    "log_level": "error",
                    "duration_period": "PT30S",
                },
                "s3": {
                    "access_key_id": "test-access-key-id",
                    "secret_access_key": "test-secret-access-key",
                    "bucket_name": "test-bucket",
                    "region": "eu-west-3",
                    "endpoint_url": "https://s3.example.org",
                    "bucket_prefixes": "ACI_TI, ACI_Vuln",
                    "marking": "TLP:AMBER",
                    "interval": 60,
                    "attach_original_file": True,
                    "delete_after_import": False,
                    "no_split_bundles": False,
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "S3 Bucket"
    assert helper.connect_scope == "s3"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT30S"


def test_connector_is_instantiated(monkeypatch, mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`
        - the values read from `self.config` MUST be forwarded to the boto3 S3 client

    `S3Connector.__init__` builds its own `ConnectorSettings` and its own boto3 client, so
    `s3.ConnectorSettings` and `s3.boto3.client` are patched to keep the test hermetic and
    focused on the config/helper wiring.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    mocked_boto3_client = MagicMock()
    monkeypatch.setattr("s3.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("s3.boto3.client", mocked_boto3_client)

    connector = S3Connector()

    assert isinstance(connector.config, ConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.s3_bucket_name == "test-bucket"
    assert connector.s3_bucket_prefixes == ["ACI_TI", "ACI_Vuln"]
    assert connector.s3_marking == stix2.TLP_AMBER
    assert connector.s3_attach_original_file is True
    assert connector.s3_delete_after_import is False
    assert connector.s3_no_split_bundles is False
    assert connector.get_interval() == 60

    mocked_boto3_client.assert_called_once_with(
        "s3",
        aws_access_key_id="test-access-key-id",
        aws_secret_access_key="test-secret-access-key",
        endpoint_url="https://s3.example.org",
        region_name="eu-west-3",
    )
