"""Tests for the pytest plugin of the SDK (`connectors_sdk_pytest_plugin`)."""

import logging
from typing import Any

import pytest
from connectors_sdk.logger import configure_logging, get_logger
from connectors_sdk.settings import base_settings
from connectors_sdk.settings.base_settings import BaseConnectorSettings


class StubConnectorSettings(BaseConnectorSettings):
    """Settings built from a dict, ignoring the environment, as many connectors test."""

    @classmethod
    def _load_config_dict(cls, _: Any, handler: Any) -> Any:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "changeme",
                    "json_logging": True,
                },
                "connector": {
                    "id": "connector-poc--uid",
                    "name": "Test Connector",
                    "scope": "scope1,scope2",
                    "log_level": "info",
                },
            }
        )


def test_plugin_should_be_registered_through_its_entry_point(request):
    """Test that pytest loads the plugin without any import in the test suite."""
    assert request.config.pluginmanager.has_plugin("connectors_sdk")


def test_plugin_should_register_its_marker(request):
    """Test that `--strict-markers` accepts the marker."""
    markers = [line.split(":")[0] for line in request.config.getini("markers")]
    assert "sdk_json_logging" in markers


def test_fixture_should_skip_the_setup_made_by_the_first_record(monkeypatch, caplog):
    """Test that the first record leaves pytest's handlers alone, JSON or not."""
    # Given: The environment enables JSON logging
    monkeypatch.setenv("OPENCTI_JSON_LOGGING", "true")
    caplog.set_level(logging.INFO)

    # When: A record is logged before any settings are parsed
    get_logger("tests.test_pytest_plugin").info("First record")

    # Then: pytest still captures it
    assert caplog.handler in logging.getLogger().handlers
    assert [r.getMessage() for r in caplog.records] == ["First record"]


@pytest.mark.parametrize(
    "env_value, expected",
    [
        pytest.param(None, True, id="default"),
        pytest.param("true", True, id="true"),
        pytest.param("false", False, id="false"),
    ],
)
def test_fixture_should_not_change_the_settings_values(
    monkeypatch, env_value, expected
):
    """Test that settings read from the environment keep their values."""
    # Given: The environment of the test, with or without `OPENCTI_JSON_LOGGING`
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "changeme")
    monkeypatch.setenv("CONNECTOR_ID", "connector-poc--uid")
    monkeypatch.setenv("CONNECTOR_NAME", "Test Connector")
    monkeypatch.setenv("CONNECTOR_SCOPE", "scope1,scope2")
    if env_value is None:
        monkeypatch.delenv("OPENCTI_JSON_LOGGING", raising=False)
    else:
        monkeypatch.setenv("OPENCTI_JSON_LOGGING", env_value)

    # When: The settings are built from the environment
    settings = BaseConnectorSettings()

    # Then: They read the environment's value, not one set by the fixture
    assert settings.opencti.json_logging is expected


def test_fixture_should_keep_caplog_capturing_with_settings_enabling_json(caplog):
    """Test that settings enabling JSON logging do not replace pytest's handlers."""
    # Given: Settings ignoring the environment and enabling JSON logging
    caplog.set_level(logging.INFO)

    # When: The settings are built, then a record is logged
    settings = StubConnectorSettings()
    get_logger("tests.test_pytest_plugin").info("After settings", meta={"key": 1})

    # Then: The settings keep their value, but pytest still captures the record
    assert settings.opencti.json_logging is True
    assert caplog.handler in logging.getLogger().handlers
    record = next(r for r in caplog.records if r.getMessage() == "After settings")
    assert record.attributes == {"key": 1}


def test_fixture_should_forward_the_log_level(monkeypatch):
    """Test that the wrapped `configure_logging` keeps the level, but not JSON."""
    # Given: `logging.basicConfig()` calls are recorded
    calls = []
    monkeypatch.setattr(
        "connectors_sdk.logger._logger.logging.basicConfig",
        lambda **kwargs: calls.append(kwargs),
    )

    # When: The settings call the wrapped function with JSON logging enabled
    base_settings.configure_logging(log_level="debug", json_logging=True)

    # Then: The setup is the one without JSON (no handler replacement)
    assert calls == [{"level": "DEBUG"}]


@pytest.mark.sdk_json_logging
def test_marker_should_leave_the_logging_setup_to_the_sdk():
    """Test that a marked test runs with the SDK's logging setup, as in production."""
    # Then: The settings call the original function
    assert base_settings.configure_logging is configure_logging


def test_fixture_should_apply_to_any_test_suite(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
):
    """Test that a test suite gets the fixture with no `conftest.py`, and is undone."""
    # Given: A test suite with no `conftest.py`, where one test is marked
    pytester.makepyfile("""
        import os

        import pytest
        from connectors_sdk.logger import configure_logging
        from connectors_sdk.settings import base_settings


        def test_unmarked():
            assert "OPENCTI_JSON_LOGGING" not in os.environ
            assert base_settings.configure_logging is not configure_logging


        @pytest.mark.sdk_json_logging
        def test_marked():
            assert base_settings.configure_logging is configure_logging
        """)
    monkeypatch.delenv("OPENCTI_JSON_LOGGING", raising=False)

    # When: The test suite runs, with markers checked
    # (in a subprocess: in this process, the fixture already patched the SDK)
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider", "--strict-markers")

    # Then: Both tests pass
    result.assert_outcomes(passed=2)
