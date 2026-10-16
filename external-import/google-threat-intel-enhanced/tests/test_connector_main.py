"""Module to test the connector entry point (connector/__main__.py)."""

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connector.__main__ import (
    _add_gticonf,
    connector_run,
    load_conf,
    load_helper,
    main,
)
from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)

# =====================
# Test Cases: load_conf
# =====================


# Scenario: Load configuration successfully
def test_load_conf_success() -> None:
    """Test that load_conf returns a GlobalConfig when loading succeeds."""
    fake_global_config = MagicMock()
    with patch("connector.__main__.GlobalConfig", return_value=fake_global_config):
        result = load_conf()
    assert result is fake_global_config  # noqa: S101
    fake_global_config.add_config_class.assert_called_once()


# Scenario: Configuration loading fails and the error is re-raised
def test_load_conf_failure_reraises() -> None:
    """Test that load_conf re-raises unexpected errors from GlobalConfig()."""
    with patch("connector.__main__.GlobalConfig", side_effect=ValueError("boom")):
        with pytest.raises(ValueError, match="boom"):
            load_conf()


# =====================
# Test Cases: _add_gticonf
# =====================


# Scenario: GTI configuration is added successfully
def test_add_gticonf_success() -> None:
    """Test that _add_gticonf calls add_config_class on the given GlobalConfig."""
    fake_global_config = MagicMock()
    _add_gticonf(fake_global_config)
    fake_global_config.add_config_class.assert_called_once()


# Scenario: GTI configuration fails and the error is swallowed
def test_add_gticonf_swallows_gti_configuration_error() -> None:
    """Test that _add_gticonf logs and swallows a GTIConfigurationError."""
    fake_global_config = MagicMock()
    fake_global_config.add_config_class.side_effect = GTIConfigurationError("bad gti")
    _add_gticonf(fake_global_config)


# =====================
# Test Cases: load_helper
# =====================


# Scenario: Helper is created successfully
def test_load_helper_success() -> None:
    """Test that load_helper returns an OpenCTIConnectorHelper when creation succeeds."""
    fake_global_config = MagicMock()
    fake_helper = MagicMock()
    with patch("connector.__main__.OpenCTIConnectorHelper", return_value=fake_helper):
        result = load_helper(fake_global_config)
    assert result is fake_helper  # noqa: S101


# Scenario: Helper creation fails and the error is re-raised
def test_load_helper_failure_reraises() -> None:
    """Test that load_helper re-raises unexpected errors from OpenCTIConnectorHelper()."""
    fake_global_config = MagicMock()
    with patch(
        "connector.__main__.OpenCTIConnectorHelper", side_effect=RuntimeError("nope")
    ):
        with pytest.raises(RuntimeError, match="nope"):
            load_helper(fake_global_config)


# =====================
# Test Cases: connector_run
# =====================


# Scenario: Connector runs successfully
def test_connector_run_success() -> None:
    """Test that connector_run instantiates and runs the Connector."""
    fake_global_config = MagicMock()
    fake_helper = MagicMock()
    fake_connector = MagicMock()
    with patch("connector.__main__.Connector", return_value=fake_connector) as ctor:
        connector_run(fake_global_config, fake_helper)
    ctor.assert_called_once_with(fake_global_config, fake_helper)
    fake_connector.run.assert_called_once()


# Scenario: Connector run is interrupted by the user/system
@pytest.mark.parametrize("exc", [KeyboardInterrupt(), SystemExit()])
def test_connector_run_handles_interrupt(exc: BaseException) -> None:
    """Test that connector_run logs and swallows KeyboardInterrupt/SystemExit."""
    fake_global_config = MagicMock()
    fake_helper = MagicMock()
    fake_connector = MagicMock()
    fake_connector.run.side_effect = exc
    with patch("connector.__main__.Connector", return_value=fake_connector):
        connector_run(fake_global_config, fake_helper)


# Scenario: Connector run fails unexpectedly
def test_connector_run_handles_unexpected_error() -> None:
    """Test that connector_run logs and swallows unexpected exceptions."""
    fake_global_config = MagicMock()
    fake_helper = MagicMock()
    fake_connector = MagicMock()
    fake_connector.run.side_effect = RuntimeError("failed")
    with patch("connector.__main__.Connector", return_value=fake_connector):
        connector_run(fake_global_config, fake_helper)


# =====================
# Test Cases: main
# =====================


# Scenario: Main runs the full happy path
def test_main_happy_path() -> None:
    """Test that main() wires load_conf -> load_helper -> connector_run together."""
    fake_global_config = MagicMock()
    fake_helper = MagicMock()
    with patch(
        "connector.__main__.load_conf", return_value=fake_global_config
    ) as m_load_conf, patch(
        "connector.__main__.load_helper", return_value=fake_helper
    ) as m_load_helper, patch(
        "connector.__main__.connector_run"
    ) as m_connector_run:
        main()
    m_load_conf.assert_called_once()
    m_load_helper.assert_called_once_with(fake_global_config)
    m_connector_run.assert_called_once_with(fake_global_config, fake_helper)


# Scenario: Main exits with an error code on unexpected startup failures
def test_main_unexpected_error_exits(caplog: Any) -> None:
    """Test that main() logs and exits(1) on an unexpected startup error."""
    caplog.set_level(logging.ERROR)
    with patch(
        "connector.__main__.load_conf", side_effect=RuntimeError("startup failed")
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
    assert exc_info.value.code == 1  # noqa: S101
    assert "Unexpected startup error" in caplog.text  # noqa: S101
