from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, Misp
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


@pytest.fixture
def mock_py_misp(monkeypatch):
    """Mock MISP client, to avoid real requests to MISP API."""

    monkeypatch.setattr("api_client.client.PyMISP", MagicMock())


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
                    "duration_period": "PT5M",
                },
                "misp": {
                    "url": "http://test.com",
                    "reference_url": "http://test.com",
                    "key": "test-api-key",
                    "ssl_verify": False,
                    "client_cert": None,
                    "date_filter_field": "timestamp",
                    "datetime_attribute": "timestamp",
                    "create_reports": True,
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": False,
                    "report_description_attribute_filter": "",
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": False,
                    "author_from_tags": False,
                    "markings_from_tags": False,
                    "keep_original_tags_as_label": "",
                    "enforce_warning_list": False,
                    "report_type": "misp-event",
                    "import_from_date": "2010-01-01",
                    "import_tags": "",
                    "import_tags_not": "",
                    "import_creator_orgs": "",
                    "import_creator_orgs_not": "",
                    "import_owner_orgs": "",
                    "import_owner_orgs_not": "",
                    "import_owner_keyword": "",
                    "import_distribution_levels": "0,1,2,3",
                    "import_threat_levels": "1,2,3,4",
                    "import_only_published": False,
                    "import_with_attachments": False,
                    "import_to_ids_no_score": 40,
                    "import_unsupported_observables_as_text": False,
                    "import_unsupported_observables_as_text_transparent": True,
                    "propagate_labels": False,
                    "import_keyword": None,
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
    assert helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(mock_opencti_connector_helper, mock_py_misp):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = Misp(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
