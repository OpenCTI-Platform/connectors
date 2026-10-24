"""Tests for the logging setup done by `connectors_sdk.logger`."""

import json
import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager

import connectors_sdk.logger._logger as logger_module
import pytest
from _connectors_sdk_plugins import pytest_plugin
from connectors_sdk.logger import configure_logging, get_logger
from pycti.utils.opencti_logger import CustomJsonFormatter
from pycti.utils.opencti_logger import logger as pycti_logger


@pytest.fixture(autouse=True)
def logging_not_configured(monkeypatch):
    """Run each test as in a new process, where the SDK has not set up logging yet.

    In tests, the SDK's pytest plugin stops the SDK from changing the root logger.
    These tests check how the SDK changes it, so the plugin is off during each test.
    """
    pytest_plugin.pytest_unconfigure()  # Plugin off
    monkeypatch.setattr(logger_module, "_logging_configured", False)
    monkeypatch.setattr(logger_module, "_sdk_json_handler", None)
    monkeypatch.delenv("OPENCTI_JSON_LOGGING", raising=False)  # JSON logging (default)
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "info")
    root_logger = logging.getLogger()
    saved_level = root_logger.level
    root_logger.setLevel(logging.WARNING)  # Python's default

    yield

    root_logger.setLevel(saved_level)
    pytest_plugin.pytest_load_initial_conftests()  # Plugin back on


@contextmanager
def no_root_handler() -> Iterator[logging.Logger]:
    """Remove the root logger's handlers for the duration of the block.

    pytest adds its capture handlers when a test starts running, after its fixtures,
    and the SDK would take them for a configuration made by the developer. So they are
    removed in the test itself, then put back.
    """
    root_logger = logging.getLogger()
    saved_handlers = list(root_logger.handlers)
    root_logger.handlers.clear()
    try:
        yield root_logger
    finally:
        root_logger.handlers[:] = saved_handlers


def _json_handlers() -> list[logging.Handler]:
    return [
        handler
        for handler in logging.getLogger().handlers
        if isinstance(handler.formatter, CustomJsonFormatter)
    ]


def _json_lines(output: str) -> list[dict]:
    return [json.loads(line) for line in output.splitlines()]


# --- First record, JSON logging (the SDK owns the logging setup) ---


def test_first_record_should_set_up_json_logging(capsys):
    """Test that the logger works out of the box, with pycti's JSON format."""
    logger = get_logger("tests.demo")

    with no_root_handler() as root_logger:
        logger.info("Fetched indicators", meta={"count": 42})
        logger.debug("Below the level")

        assert len(_json_handlers()) == 1
        assert root_logger.level == logging.INFO

    [record] = _json_lines(capsys.readouterr().err)
    record.pop("timestamp")
    assert record == {
        "level": "INFO",
        "name": "tests.demo",
        "message": "Fetched indicators",
        "attributes": {"count": 42},
    }


def test_json_logging_should_replace_an_existing_configuration(capsys):
    """Test that JSON logging replaces every root handler, like pycti does."""
    with no_root_handler() as root_logger:
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")

        get_logger("tests.demo").info("Hello")

        assert root_logger.handlers == _json_handlers()
        assert len(root_logger.handlers) == 1
        assert root_logger.level == logging.INFO

    [record] = _json_lines(capsys.readouterr().err)
    assert record["message"] == "Hello"


def test_checking_a_level_should_set_up_logging(monkeypatch):
    """Test that `isEnabledFor()` already applies the configured level."""
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "debug")

    with no_root_handler():
        assert get_logger("tests.demo").isEnabledFor(logging.DEBUG)


def test_setup_should_run_once():
    """Test that the setup is never redone, even when its handler is gone."""
    logger = get_logger("tests.demo")

    with no_root_handler() as root_logger:
        logger.info("First record")
        root_logger.handlers.clear()
        logger.info("Second record")

        assert root_logger.handlers == []


def test_basic_config_with_force_should_replace_the_setup(capsys):
    """Test that a connector can override the setup at any time, for good."""
    logger = get_logger("tests.demo")

    with no_root_handler() as root_logger:
        logger.info("Before")
        capsys.readouterr()

        logging.basicConfig(force=True, level=logging.INFO, format="%(message)s")
        logger.info("After")

        assert _json_handlers() == []
        assert len(root_logger.handlers) == 1

    assert capsys.readouterr().err == "After\n"


# --- First record, JSON logging disabled (the developer owns the logging setup) ---


@pytest.mark.parametrize(
    "env_value, json_logging",
    [
        (None, True),
        ("", True),
        ("true", True),
        ("yes", True),
        ("1", True),
        ("unknown", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("no", False),
        ("0", False),
        (" off ", False),
    ],
)
def test_setup_should_read_json_logging_like_the_settings(
    monkeypatch, env_value, json_logging
):
    """Test that `OPENCTI_JSON_LOGGING` is disabled by the values pydantic reads as
    `False`, like the settings do. Disabled, the first record adds no handler."""
    if env_value is not None:
        monkeypatch.setenv("OPENCTI_JSON_LOGGING", env_value)

    with no_root_handler() as root_logger:
        get_logger("tests.demo").info("Hello")

        handlers = list(root_logger.handlers)
        # The level applies either way
        assert root_logger.level == logging.INFO

    if json_logging:
        [handler] = handlers
        assert isinstance(handler.formatter, CustomJsonFormatter)
    else:
        assert handlers == []


def test_disabled_json_logging_should_keep_the_handlers_and_apply_the_level(
    monkeypatch, capsys
):
    """Test that a connector's own handlers, set up first, are kept, while the level
    comes from `CONNECTOR_LOG_LEVEL`."""
    monkeypatch.setenv("OPENCTI_JSON_LOGGING", "false")
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "warning")

    with no_root_handler() as root_logger:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
        [connector_handler] = root_logger.handlers

        logger = get_logger("tests.demo")
        logger.info("Below the level")
        logger.warning("Hello")

        assert root_logger.handlers == [connector_handler]
        assert root_logger.level == logging.WARNING

    assert capsys.readouterr().err == "WARNING Hello\n"


# --- First record, level ---


@pytest.mark.parametrize(
    "env_value, expected_level",
    [
        ("debug", logging.DEBUG),
        ("INFO", logging.INFO),
        (" info ", logging.INFO),
        ("warn", logging.WARNING),
        ("warning", logging.WARNING),
        ("error", logging.ERROR),
    ],
)
def test_setup_should_read_level_from_env(monkeypatch, env_value, expected_level):
    """Test that the level comes from `CONNECTOR_LOG_LEVEL`."""
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", env_value)

    with no_root_handler() as root_logger:
        get_logger("tests.demo").info("Hello")

        assert root_logger.level == expected_level


@pytest.mark.parametrize("env_value", [None, "", "  ", "verbose"])
def test_setup_should_warn_when_the_level_is_missing_or_invalid(
    monkeypatch, capsys, env_value
):
    """Test that a missing or unknown level is reported, then the default one applies.

    The warning is written although the root level was above WARNING.
    """
    if env_value is None:
        monkeypatch.delenv("CONNECTOR_LOG_LEVEL")
    else:
        monkeypatch.setenv("CONNECTOR_LOG_LEVEL", env_value)

    with no_root_handler() as root_logger:
        root_logger.setLevel(logging.CRITICAL)  # e.g. set by the connector
        get_logger("tests.demo").info("Below the default level")

        assert root_logger.level == logging.ERROR

    [record] = _json_lines(capsys.readouterr().err)
    record.pop("timestamp")
    assert record == {
        "level": "WARNING",
        "name": "connectors_sdk.logger._logger",
        "message": (
            "Missing or invalid CONNECTOR_LOG_LEVEL: the default log level applies "
            "until the settings are parsed"
        ),
        "attributes": {"CONNECTOR_LOG_LEVEL": env_value, "applied_log_level": "error"},
    }


# --- pycti's helper ---


def test_setup_should_not_duplicate_pycti_json_handler():
    """Test that pycti's helper replaces the SDK's handler instead of adding one."""
    logger = get_logger("tests.demo")

    with no_root_handler():
        logger.info("Hello")
        [sdk_handler] = _json_handlers()

        # What `OpenCTIConnectorHelper` does on creation, with JSON logging
        pycti_logger(logging.INFO)
        logger.info("Hello again")

        [pycti_handler] = _json_handlers()

    assert pycti_handler is not sdk_handler


def test_configure_logging_should_match_pycti_plain_text_handler():
    """Test that pycti's helper keeps the default handler when JSON is disabled."""
    with no_root_handler() as root_logger:
        configure_logging(log_level="info", json_logging=False)
        [default_handler] = root_logger.handlers

        # What `OpenCTIConnectorHelper` does on creation, with JSON logging disabled
        pycti_logger(logging.INFO, False)

        assert root_logger.handlers == [default_handler]


# --- configure_logging() ---


def test_configure_logging_should_set_up_json_logging():
    """Test that JSON logging applies with a single handler, replacing the others."""
    with no_root_handler() as root_logger:
        logging.basicConfig(level=logging.ERROR, format="%(message)s")

        configure_logging(log_level="debug", json_logging=True)

        [handler] = root_logger.handlers
        assert isinstance(handler.formatter, CustomJsonFormatter)
        assert root_logger.level == logging.DEBUG


def test_configure_logging_should_undo_the_json_setup_when_json_is_disabled(
    monkeypatch,
):
    """Test that settings disabling JSON (e.g. in `config.yml`) undo the JSON setup
    made by the first record from the environment variables."""
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")

    with no_root_handler() as root_logger:
        get_logger("tests.demo").error("Before the settings")
        [env_handler] = _json_handlers()

        configure_logging(log_level=" Info ", json_logging=False)

        [settings_handler] = root_logger.handlers
        assert settings_handler is not env_handler
        assert settings_handler.formatter._fmt == logging.BASIC_FORMAT
        assert root_logger.level == logging.INFO


def test_configure_logging_without_json_should_add_python_default_handler():
    """Test that, when nothing configured logging, disabled JSON gives Python's
    default handler and the level, like `logging.basicConfig(level=...)`."""
    with no_root_handler() as root_logger:
        configure_logging(log_level="info", json_logging=False)

        [handler] = root_logger.handlers
        assert handler.formatter._fmt == logging.BASIC_FORMAT
        assert root_logger.level == logging.INFO


def test_configure_logging_without_json_should_keep_the_handlers_and_apply_the_level():
    """Test that the developer's handlers are kept, while the settings' level applies,
    unlike pycti."""
    with no_root_handler() as root_logger:
        logging.basicConfig(level=logging.ERROR, format="%(message)s")
        [connector_handler] = root_logger.handlers

        configure_logging(log_level="debug", json_logging=False)

        assert root_logger.handlers == [connector_handler]
        assert root_logger.level == logging.DEBUG


def test_configure_logging_without_json_should_keep_a_developer_json_handler():
    """Test that only the SDK's own JSON handler is removed when JSON is disabled."""
    with no_root_handler() as root_logger:
        developer_handler = logging.StreamHandler()
        developer_handler.setFormatter(CustomJsonFormatter("%(message)s"))
        root_logger.addHandler(developer_handler)

        configure_logging(log_level="info", json_logging=False)

        assert root_logger.handlers == [developer_handler]


def test_configure_logging_should_disable_the_first_record_setup():
    """Test that a record logged after `configure_logging()` sets nothing up."""
    with no_root_handler() as root_logger:
        logging.basicConfig()
        configure_logging(log_level="debug", json_logging=False)  # developer's setup
        root_logger.handlers.clear()

        get_logger("tests.demo").info("Hello")

        assert root_logger.handlers == []


def test_configure_logging_should_reject_an_unknown_level():
    """Test that an unknown level raises, and changes nothing."""
    with no_root_handler() as root_logger:
        with pytest.raises(ValueError, match="Unknown log level: verbose"):
            configure_logging(log_level="verbose")

        assert root_logger.handlers == []
        assert root_logger.level == logging.WARNING


# --- Import ---


def test_importing_the_sdk_should_not_set_up_logging():
    """Test that only the first record sets up logging, not the import."""
    # A fresh interpreter, since this process imported the SDK long ago
    script = (
        "import logging\n"
        "import connectors_sdk\n"
        "root = logging.getLogger()\n"
        "print(len(root.handlers), logging.getLevelName(root.level))\n"
        "connectors_sdk.get_logger('demo').info('Hello')\n"
        "print(len(root.handlers), logging.getLevelName(root.level))\n"
    )

    result = subprocess.run(  # noqa: S603 - fixed script, current interpreter
        [sys.executable, "-c", script],
        env={
            **os.environ,
            "CONNECTOR_LOG_LEVEL": "info",
            "OPENCTI_JSON_LOGGING": "true",
        },
        capture_output=True,
        text=True,
        check=True,
    )

    # Python's defaults (no handler, WARNING level), then the SDK's setup
    assert result.stdout.splitlines() == ["0 WARNING", "1 INFO"]
    [record] = _json_lines(result.stderr)
    assert record["message"] == "Hello"
