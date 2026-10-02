"""Tests for when the log level is read and applied.

Finding a connector's configuration files needs `__main__.__file__`. Python only sets
that attribute once it has imported the package, and the connector's modules ask for
their loggers during that import. These tests check that the level is read late enough
for the files to be found.
"""

import logging
import sys
from types import SimpleNamespace

import connectors_sdk.logger._logger as logger_module
import pytest
from connectors_sdk.logger import get_connector_logger, get_sdk_logger


@pytest.fixture(autouse=True)
def without_level_environment_variable(monkeypatch):
    """Ensure the developer's own `CONNECTOR_LOG_LEVEL` cannot influence the tests."""
    monkeypatch.delenv("CONNECTOR_LOG_LEVEL", raising=False)


@pytest.fixture
def resolution_spy(monkeypatch):
    """Count how many times the configured level is read from the environment or files.

    Returns:
        list[str | int]: One entry per read, holding the level it returned.
    """
    resolutions = []
    get_log_level = logger_module.get_log_level

    def spy():
        level = get_log_level()
        resolutions.append(level)
        return level

    monkeypatch.setattr(logger_module, "get_log_level", spy)
    return resolutions


def test_creating_a_logger_should_not_resolve_the_level(resolution_spy):
    """Test that asking for a logger reads no configuration.

    Connectors create their loggers at module level. This runs while the package is
    still being imported, which is too early for the configuration files to be found.
    """
    # Given / When: A logger is created
    get_connector_logger("test_lazy_creation")

    # Then: Nothing was read
    assert resolution_spy == []


def test_emitting_a_record_should_resolve_the_level(mock_main_path, resolution_spy):
    """Test that the level is resolved when a record is actually emitted."""
    # Given: A logger created before any configuration was read
    logger = get_connector_logger("test_lazy_emit")
    assert resolution_spy == []

    # When: A record is emitted
    logger.error("first record")

    # Then: The level was resolved
    assert len(resolution_spy) == 1


def test_emitting_more_records_should_not_resolve_the_level_again(
    mock_main_path, resolution_spy
):
    """Test that the configuration is read once, not on every record."""
    # Given: A logger that already emitted
    logger = get_connector_logger("test_resolve_once")
    logger.error("first record")

    # When: More records are emitted
    logger.error("second record")
    logger.warning("third record")

    # Then: The configuration was read only once
    assert len(resolution_spy) == 1


def test_each_namespace_should_settle_on_its_own(mock_main_path, resolution_spy):
    """Test that a logger settles the namespace it belongs to, and no other.

    A logger reads the level onto its own namespace rather than onto a list of the ones
    the SDK owns, so a namespace nothing logged through yet is left untouched.
    """
    # Given: A connector logger that already emitted
    get_connector_logger("test_own_namespace").error("first record")
    assert len(resolution_spy) == 1
    assert logging.getLogger("connectors_sdk").level == logging.NOTSET

    # When: An SDK logger emits in turn
    get_sdk_logger("test_own_namespace").error("first record")

    # Then: Its namespace settled too, on its own read
    assert len(resolution_spy) == 2
    assert logging.getLogger("connectors_sdk").level != logging.NOTSET


def test_emitting_should_apply_the_configured_level(mock_main_path):
    """Test that the level found in the connector's configuration is the one applied."""
    # Given: A connector configured to log at debug level
    (mock_main_path / "config.yml").write_text("connector:\n  log_level: debug\n")
    logger = get_connector_logger("test_applied_level")

    # When: A record is emitted, forcing resolution
    logger.debug("resolve now")

    # Then: The logger filters on that level
    assert logger.getEffectiveLevel() == logging.DEBUG


def test_resolution_should_see_an_entrypoint_set_after_the_logger_was_created(
    monkeypatch, tmp_path
):
    """Test the case `python -m src` creates, and the reason resolution is deferred.

    `runpy` imports the package before it sets `__main__.__file__`, so a connector
    module asking for a logger sees no entrypoint at all. Resolving then would fall back
    to the default level and ignore the connector's own configuration.
    """
    # Given: A connector whose entrypoint is not known yet, as during a package import
    connector_root = tmp_path / "connector"
    (connector_root / "src").mkdir(parents=True)
    (connector_root / "config.yml").write_text("connector:\n  log_level: debug\n")
    monkeypatch.setitem(sys.modules, "__main__", SimpleNamespace())

    logger = get_connector_logger("test_runpy")

    # When: The entrypoint becomes known, then a record is emitted
    monkeypatch.setitem(
        sys.modules,
        "__main__",
        SimpleNamespace(__file__=str(connector_root / "src" / "__main__.py")),
    )
    logger.debug("resolve now")

    # Then: The connector's own configuration was used
    assert logger.getEffectiveLevel() == logging.DEBUG


def test_a_preset_namespace_level_should_prevent_the_configuration_being_read(
    mock_main_path, resolution_spy
):
    """Test that a level set by hand is never silently replaced by the configured one.

    `NOTSET` is what marks a namespace as undecided, so anything that already carries a
    level is taken as deliberate and left alone.
    """
    # Given: A logger whose namespace was given a level before anything was emitted
    logger = get_connector_logger("test_no_late_resolution")
    logging.getLogger("connector").setLevel("WARNING")

    # When: A record is emitted
    logger.warning("first record")

    # Then: No configuration was read, and the level still holds
    assert resolution_spy == []
    assert logger.getEffectiveLevel() == logging.WARNING


def test_default_level_should_apply_when_nothing_is_configured(
    mock_missing_main_path,
):
    """Test that an unlocatable configuration still yields pycti's default level."""
    # Given / When: A logger in a process with no file-backed entrypoint
    logger = get_connector_logger("test_default_level")
    logger.error("resolve now")

    # Then: The level pycti defaults to is used
    assert logger.getEffectiveLevel() == logging.ERROR
