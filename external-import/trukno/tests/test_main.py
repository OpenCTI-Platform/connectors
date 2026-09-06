import runpy

import main as main_module
import pytest
from connectors_sdk.settings.exceptions import ConfigValidationError
from trukno_connector.client import TruKnoClient
from trukno_connector.settings import ConnectorSettings
from trukno_connector.state import ConnectorState


def test_entrypoint_imports():
    assert main_module is not None
    assert TruKnoClient is not None
    assert ConnectorSettings is not None
    assert ConnectorState is not None


@pytest.mark.parametrize("canonical", [False, True])
@pytest.mark.parametrize("interval", ["0", "-1", "abc", "1.5", ""])
def test_startup_invalid_interval_does_not_disclose_credentials(
    required_environment, monkeypatch, capsys, caplog, canonical, interval
):
    monkeypatch.setenv("OPENCTI_TOKEN", "OTK-SENTINEL")
    monkeypatch.setenv("TRUKNO_API_KEY", "TKN-SENTINEL")
    monkeypatch.setenv("TRUKNO_INTERVAL_MINUTES", interval)
    if canonical:
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT1H")

    with pytest.raises(SystemExit) as error:
        runpy.run_path(main_module.__file__, run_name="__main__")

    assert error.value.code == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err + caplog.text
    assert "TKN-SENTINEL" not in output
    assert "OTK-SENTINEL" not in output
    assert "Traceback" not in output
    assert "TRUKNO_INTERVAL_MINUTES" in captured.err
    assert "positive integer" in captured.err


def test_startup_legacy_config_path_is_rejected_with_redacted_guidance(
    required_environment, monkeypatch, capsys, caplog
):
    monkeypatch.setenv("TRUKNO_CONNECTOR_CONFIG", "/private/PATH-SENTINEL/config.yml")
    # Keep startup offline even before the legacy-path guard exists.
    monkeypatch.setenv("TRUKNO_INTERVAL_MINUTES", "0")
    with pytest.raises(SystemExit) as error:
        runpy.run_path(main_module.__file__, run_name="__main__")
    assert error.value.code == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err + caplog.text
    assert "PATH-SENTINEL" not in output
    assert "trukno-secret" not in output
    assert "opencti-token" not in output
    assert "Traceback" not in output
    assert "TRUKNO_CONNECTOR_CONFIG" in captured.err
    assert "connector-root config.yml" in captured.err
    assert "environment variables" in captured.err


@pytest.mark.parametrize("error_type", [ConfigValidationError, ValueError])
def test_entrypoint_redacts_both_settings_validation_exception_forms(
    monkeypatch, capsys, caplog, error_type
):
    def invalid_settings():
        raise error_type("TKN-SENTINEL OTK-SENTINEL")

    monkeypatch.setattr(main_module, "ConnectorSettings", invalid_settings)
    monkeypatch.setattr(
        main_module, "main", lambda **kwargs: pytest.fail("runtime started")
    )
    assert main_module.entrypoint() == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err + caplog.text
    assert "TKN-SENTINEL" not in output
    assert "OTK-SENTINEL" not in output
    assert "Traceback" not in output
    assert "configuration" in captured.err.lower()
    assert "config.yml" in captured.err


@pytest.mark.parametrize("phase", ["settings", "runtime"])
def test_entrypoint_retains_traceback_for_unexpected_exceptions(
    monkeypatch, capsys, phase
):
    def unexpected_failure(**kwargs):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(main_module, "ConnectorSettings", lambda: object())
    monkeypatch.setattr(main_module, "main", unexpected_failure)
    if phase == "settings":
        monkeypatch.setattr(main_module, "ConnectorSettings", unexpected_failure)
    assert main_module.entrypoint() == 1
    assert "RuntimeError: unexpected failure" in capsys.readouterr().err


def test_entrypoint_does_not_treat_runtime_value_error_as_invalid_settings(
    monkeypatch, capsys
):
    def runtime_failure(**kwargs):
        raise ValueError("runtime failure")

    monkeypatch.setattr(main_module, "ConnectorSettings", lambda: object())
    monkeypatch.setattr(main_module, "main", runtime_failure)
    assert main_module.entrypoint() == 1
    assert "ValueError: runtime failure" in capsys.readouterr().err


def test_entrypoint_starts_runtime_with_validated_settings(
    required_environment, monkeypatch
):
    received = []
    monkeypatch.setattr(main_module, "main", lambda settings: received.append(settings))
    assert main_module.entrypoint() == 0
    assert len(received) == 1
    assert isinstance(received[0], ConnectorSettings)
    assert received[0].connector.name == "TruKno"
