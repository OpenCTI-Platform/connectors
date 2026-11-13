import runpy
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from crtsh import CrtSHClient
from lib.external_import import ExternalImportConnector
from main import CrtshConnector
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings
from stix2 import TLP_WHITE


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
                    "name": "crt.sh",
                    "scope": "crtsh",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "crtsh": {
                    "domain": "example.com",
                    "labels": "crtsh,osint",
                    "marking_refs": "TLP:WHITE",
                    "is_expired": True,
                    "is_wildcard": False,
                },
            }
        )


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


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully.
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully
    with the connector settings converted by `to_helper_config()`.
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "crt.sh"
    assert helper.connect_scope == "crtsh"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the existing connector class builds its settings and its helper
    from `ConnectorSettings` and consumes the configured values.
    """
    monkeypatch.setattr("lib.external_import.ConnectorSettings", StubConnectorSettings)

    connector = CrtshConnector()

    assert isinstance(connector.config, ConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.interval == 3600
    assert connector._get_interval() == 3600
    assert connector.domain == "example.com"
    assert connector.labels == ["crtsh", "osint"]
    assert connector.marking_refs == "TLP:WHITE"
    assert connector.is_expired is True
    assert connector.is_wildcard is False
    assert isinstance(connector.api, CrtSHClient)
    assert connector.api.url.endswith("&exclude=expired")


def test_main_should_print_the_startup_error_and_exit(monkeypatch, capsys):
    """A startup error MUST be printed with its traceback, and the process MUST exit with 1."""
    for env_var in ("OPENCTI_URL", "OPENCTI_TOKEN", "CRTSH_DOMAIN"):
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.setattr("time.sleep", lambda _: None)

    main_path = Path(__file__).parent.parent / "src" / "main.py"
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(main_path), run_name="__main__")

    assert exit_info.value.code == 1
    stderr = capsys.readouterr().err
    assert "Traceback" in stderr
    assert "Error validating configuration" in stderr


def test_connector_should_not_mark_objects_when_marking_refs_is_unset(
    mock_opencti_connector_helper, monkeypatch
):
    """Without `CRTSH_MARKING_REFS`, the imported objects MUST have no marking (as before)."""

    class UnmarkedConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "crtsh": {"domain": "example.com"},
                }
            )

    monkeypatch.setattr(
        "lib.external_import.ConnectorSettings", UnmarkedConnectorSettings
    )

    connector = CrtshConnector()

    assert connector.marking_refs is None
    assert connector.api.marking_refs is None


# ── last_cert_id state handling ──────────────────────────────────────────────


def _run_once(monkeypatch, state, send_error=None, crtsh_result=([MagicMock()], 200)):
    """Run one connector cycle with a mocked helper and crt.sh client."""
    monkeypatch.setattr("lib.external_import.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("lib.external_import.OpenCTIConnectorHelper", MagicMock())
    connector = CrtshConnector()
    connector.helper.connect_run_and_terminate = True
    connector.helper.get_state.return_value = state
    if send_error:
        connector.helper.send_stix2_bundle.side_effect = send_error
    connector.api = MagicMock()
    connector.api.get_stix_objects.return_value = crtsh_result

    with pytest.raises(SystemExit):
        connector.run()

    return connector


def test_run_imports_after_last_cert_id_and_stores_the_new_one(monkeypatch):
    connector = _run_once(monkeypatch, state={"last_run": 1, "last_cert_id": 100})

    connector.api.get_stix_objects.assert_called_once_with(last_cert_id=100)
    saved_state = connector.helper.set_state.call_args.args[0]
    assert saved_state["last_cert_id"] == 200
    assert saved_state["last_run"] > 1


def test_run_without_last_cert_id_imports_everything(monkeypatch):
    """Upgrading from a state that only has last_run behaves like a first run."""
    connector = _run_once(monkeypatch, state={"last_run": 1})

    connector.api.get_stix_objects.assert_called_once_with(last_cert_id=None)
    assert connector.helper.set_state.call_args.args[0]["last_cert_id"] == 200


def test_run_does_not_advance_last_cert_id_when_sending_fails(monkeypatch):
    """If the bundle is not sent, the same certificates are imported next run."""
    connector = _run_once(
        monkeypatch,
        state={"last_run": 1, "last_cert_id": 100},
        send_error=RuntimeError("OpenCTI unavailable"),
    )

    assert connector.helper.set_state.call_args.args[0]["last_cert_id"] == 100


def test_run_without_any_certificate_id_does_not_store_last_cert_id(monkeypatch):
    """If crt.sh returns nothing usable on a first run, no last_cert_id is stored."""
    connector = _run_once(monkeypatch, state={"last_run": 1}, crtsh_result=([], None))

    assert "last_cert_id" not in connector.helper.set_state.call_args.args[0]


def test_base_connector_has_no_extra_state_updates_by_default():
    assert ExternalImportConnector._get_state_updates(MagicMock()) == {}


# ── Marking definition in the bundle ─────────────────────────────────────────


def _collect_with_one_certificate(monkeypatch):
    """Run _collect_intelligence with the real client on one crt.sh entry."""
    monkeypatch.setattr("lib.external_import.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("lib.external_import.OpenCTIConnectorHelper", MagicMock())
    connector = CrtshConnector()
    connector.helper.get_state.return_value = {}
    entry = {
        "issuer_ca_id": 1,
        "issuer_name": "C=US, O=Example CA, CN=Example CA",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "id": 12345,
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "serial_number": "0a1b2c3d",
    }
    monkeypatch.setattr(connector.api, "_request_data", lambda: [entry])
    return connector, connector._collect_intelligence()


def test_collected_objects_include_the_configured_marking_definition(monkeypatch):
    """Objects reference the marking, so it must be sent in the same bundle."""
    connector, stix_objects = _collect_with_one_certificate(monkeypatch)

    marking = connector.api.marking_refs
    assert marking == TLP_WHITE
    assert marking in stix_objects
    marked_objects = [obj for obj in stix_objects if obj.get("object_marking_refs")]
    assert marked_objects
    assert all(marking.id in obj["object_marking_refs"] for obj in marked_objects)


def test_collected_objects_have_no_marking_definition_when_none_is_configured(
    monkeypatch,
):
    monkeypatch.setattr("lib.external_import.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("lib.external_import.OpenCTIConnectorHelper", MagicMock())
    connector = CrtshConnector()
    connector.helper.get_state.return_value = {}
    connector.api.marking_refs = None
    monkeypatch.setattr(
        connector.api, "get_stix_objects", lambda last_cert_id: ([MagicMock()], 1)
    )

    stix_objects = connector._collect_intelligence()

    assert stix_objects[-1] is connector.api.author
    assert len(stix_objects) == 2
