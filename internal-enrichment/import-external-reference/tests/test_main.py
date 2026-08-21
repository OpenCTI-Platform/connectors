import importlib.util
import os
from typing import Any

from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

# The connector's entrypoint module uses a hyphenated filename
# ("import-external-reference.py") which is not a valid Python identifier,
# so it cannot be imported with a regular `import` statement. We load it
# explicitly by file path instead.
_MAIN_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "import-external-reference.py"
)
_spec = importlib.util.spec_from_file_location(
    "import_external_reference_main", _MAIN_PATH
)
main_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(main_module)

ImportExternalReferenceConnector = main_module.ImportExternalReferenceConnector


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
                    "name": "ImportExternalReference",
                    "scope": "External-Reference",
                    "log_level": "error",
                    "auto": False,
                },
                "import_external_reference": {
                    "import_as_pdf": True,
                    "import_as_md": True,
                    "import_pdf_as_md": True,
                    "timestamp_files": False,
                    "cache_size": 32,
                    "cache_ttl": 3600,
                    "browser_worker_count": 4,
                    "max_download_size": 52428800,
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
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "ImportExternalReference"
    assert helper.connect_scope == "External-Reference"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is False


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector's main class can be instantiated successfully.

    The `ImportExternalReferenceConnector` builds its own configuration and
    helper internally (via `ConnectorSettings`). We patch `ConnectorSettings`
    where the connector looks it up so the connector uses the stubbed config:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`
    """
    monkeypatch.setattr(main_module, "ConnectorSettings", StubConnectorSettings)

    connector = ImportExternalReferenceConnector()

    assert isinstance(connector.config, ConnectorSettings)
    assert connector.helper is not None
    assert connector.import_as_pdf is True
    assert connector.import_as_md is True
    assert connector.import_pdf_as_md is True
    assert connector.timestamp_files is False
    assert connector.cache_size == 32
    assert connector.cache_ttl == 3600
    assert connector.worker_count == 4
    assert connector.max_download_size == 52428800
