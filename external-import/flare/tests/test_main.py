"""Integration tests verifying the connector can be instantiated end-to-end."""

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connector import ConnectorSettings, FlareConnector
from connector.converter_to_stix import FlareToStixMapper
from flare_client import FlareClient
from main import main
from pycti import OpenCTIConnectorHelper


class StubConnectorSettings(ConnectorSettings):
    """ConnectorSettings subclass that loads config from a dict instead of env/file."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token-00000000-0000-0000-0000-000000000000",
                },
                "connector": {
                    "id": "aabbccdd-1234-5678-abcd-aabbccddeeff",
                    "name": "Flare",
                    "scope": "Incident,Observable,Indicator",
                    "duration_period": "PT1H",
                },
                "flare": {
                    "api_key": "fw_test_key_1234567890",
                    "api_base_url": "api.flare.io",
                    "event_types": "stealer_log,domain,ransomleak,leak",
                    "lookback_days": 30,
                    "tlp_level": "white",
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all external dependencies of OpenCTIConnectorHelper."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    """Verify ConnectorSettings can be instantiated and produces a valid helper config."""
    settings = StubConnectorSettings()
    config = settings.to_helper_config()
    assert isinstance(config, dict)
    assert config["opencti"]["url"] == "http://localhost:8080/"
    assert (
        config["opencti"]["token"] == "test-token-00000000-0000-0000-0000-000000000000"
    )
    assert config["connector"]["id"] == "aabbccdd-1234-5678-abcd-aabbccddeeff"
    assert config["connector"]["type"] == "EXTERNAL_IMPORT"


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """Verify OpenCTIConnectorHelper can be constructed from settings."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    assert helper.connect_id == "aabbccdd-1234-5678-abcd-aabbccddeeff"
    assert helper.connect_name == "Flare"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """Verify FlareConnector accepts config + helper + dependencies."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    flare_client = MagicMock(spec=FlareClient)
    mapper = MagicMock(spec=FlareToStixMapper)

    connector = FlareConnector(
        config=settings,
        helper=helper,
        flare_client=flare_client,
        mapper=mapper,
    )
    assert connector.config is settings
    assert connector.helper is helper
    assert connector.flare_client is flare_client
    assert connector.mapper is mapper


@pytest.fixture
def mocks() -> Generator[SimpleNamespace, None, None]:
    with (
        patch("main.ConnectorSettings") as m_settings,
        patch("main.OpenCTIConnectorHelper") as m_helper,
        patch("main.FlareClient") as m_client,
        patch("main.stix2") as m_stix2,
        patch("main.PyctiIdentity") as m_pycti,
        patch("main.FlareToStixMapper") as m_mapper,
        patch("main.FlareConnector") as m_connector,
    ):
        yield SimpleNamespace(
            settings_cls=m_settings,
            settings=m_settings.return_value,
            helper_cls=m_helper,
            helper=m_helper.return_value,
            client_cls=m_client,
            client=m_client.return_value,
            stix2=m_stix2,
            author_identity=m_stix2.Identity.return_value,
            pycti=m_pycti,
            mapper_cls=m_mapper,
            mapper=m_mapper.return_value,
            connector_cls=m_connector,
            connector=m_connector.return_value,
        )


class TestMain:
    def test_creates_and_runs_connector(self, mocks: SimpleNamespace) -> None:
        main()

        mocks.settings_cls.assert_called_once_with()
        mocks.helper_cls.assert_called_once_with(
            config=mocks.settings.to_helper_config.return_value
        )
        mocks.client_cls.assert_called_once_with(
            helper=mocks.helper,
            api_key=mocks.settings.flare.api_key,
            api_domain=mocks.settings.flare.api_domain,
            tenant_id=mocks.settings.flare.tenant_id,
        )
        mocks.pycti.generate_id.assert_called_once_with("Flare", "organization")
        mocks.stix2.Identity.assert_called_once_with(
            id=mocks.pycti.generate_id.return_value,
            name="Flare",
            identity_class="organization",
            description="Cyber Threat Intelligence Platform",
            object_marking_refs=[mocks.stix2.TLP_WHITE.id],
        )
        mocks.mapper_cls.assert_called_once_with(
            config=mocks.settings,
            author_identity=mocks.author_identity,
        )
        mocks.connector_cls.assert_called_once_with(
            config=mocks.settings,
            helper=mocks.helper,
            flare_client=mocks.client,
            mapper=mocks.mapper,
        )
        mocks.connector.run.assert_called_once_with()

    @pytest.mark.parametrize(
        "attr_path",
        [
            pytest.param("settings_cls.side_effect", id="settings_init_fails"),
            pytest.param("helper_cls.side_effect", id="helper_init_fails"),
            pytest.param("client_cls.side_effect", id="client_init_fails"),
            pytest.param("stix2.Identity.side_effect", id="identity_creation_fails"),
            pytest.param("pycti.generate_id.side_effect", id="generate_id_fails"),
            pytest.param("mapper_cls.side_effect", id="mapper_init_fails"),
            pytest.param("connector_cls.side_effect", id="connector_init_fails"),
            pytest.param("connector.run.side_effect", id="connector_run_fails"),
        ],
    )
    def test_exception_propagates(self, mocks: SimpleNamespace, attr_path: str) -> None:
        obj = mocks
        *parents, attr = attr_path.split(".")
        for part in parents:
            obj = getattr(obj, part)
        setattr(obj, attr, RuntimeError("failure"))

        with pytest.raises(RuntimeError, match="failure"):
            main()
