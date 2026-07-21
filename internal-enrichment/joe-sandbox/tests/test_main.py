from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, JoeSandboxConnector
from pycti import OpenCTIConnectorHelper


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
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "joe_sandbox": {
                    "report_types": "executive,html,iochtml,iocjson,iocxml,unpackpe,stix,ida,pdf,pdfexecutive,misp,pcap,maec,memdumps,json,lightjsonfixed,xml,lightxml,pcapunified,pcapsslinspection",
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    "api_key": "test-api-key",
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                    "accept_tac": True,
                    "api_timeout": 30,
                    "verify_ssl": True,
                    "api_retries": 5,
                    "proxies": None,
                    "user_agent": "OpenCTI",
                    "systems": "w10x64_office",
                    "analysis_time": 300,
                    "internet_access": True,
                    "internet_simulation": False,
                    "hybrid_code_analysis": True,
                    "hybrid_decompilation": True,
                    "report_cache": False,
                    "apk_instrumentation": True,
                    "amsi_unpacking": True,
                    "ssl_inspection": True,
                    "vba_instrumentation": False,
                    "js_instrumentation": False,
                    "java_jar_tracing": False,
                    "dotnet_tracing": False,
                    "start_as_normal_user": False,
                    "system_date": None,
                    "language_and_locale": None,
                    "localized_internet_country": None,
                    "email_notification": None,
                    "archive_no_unpack": False,
                    "hypervisor_based_inspection": False,
                    "fast_mode": False,
                    "secondary_results": True,
                    "cookbook_file_path": None,
                    "document_password": "1234",
                    "archive_password": "infected",
                    "command_line_argument": None,
                    "encrypt_with_password": None,
                    "browser": False,
                    "url_reputation": False,
                    "export_to_jbxview": False,
                    "delete_after_days": 30,
                    "priority": None,
                    "default_tlp": "TLP:CLEAR",
                    "yara_color": "#0059f7",
                    "default_color": "#54483b",
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
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "test,connector"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto == True


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = JoeSandboxConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
