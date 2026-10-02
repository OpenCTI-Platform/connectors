"""Tests for `connectors_sdk.logger._log_level`."""

import logging

import pytest
from connectors_sdk.logger._log_level import get_log_level


@pytest.fixture(autouse=True)
def without_level_environment_variable(monkeypatch):
    """Ensure the developer's own `CONNECTOR_LOG_LEVEL` cannot influence the tests."""
    monkeypatch.delenv("CONNECTOR_LOG_LEVEL", raising=False)


def write_config_yml(connector_root, content: str) -> None:
    """Write a `config.yml` in the connector's root directory.

    Args:
        connector_root: The connector's root directory.
        content (str): The YAML document to write.
    """
    (connector_root / "config.yml").write_text(content, encoding="utf-8")


def write_dot_env(connector_root, content: str) -> None:
    """Write a `.env` in the connector's root directory.

    Args:
        connector_root: The connector's root directory.
        content (str): The file's content.
    """
    (connector_root / ".env").write_text(content, encoding="utf-8")


def test_get_log_level_should_read_the_environment_variable(monkeypatch):
    """Test that `CONNECTOR_LOG_LEVEL` configures the level."""
    # Given: The environment variable is set
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "debug")

    # When: The level name is resolved
    level_name = get_log_level()

    # Then: It comes from the environment
    assert level_name == "DEBUG"


def test_get_log_level_should_prefer_the_environment_over_files(
    monkeypatch, mock_main_path
):
    """Test that the environment variable outranks the configuration file."""
    # Given: Both the environment and a `config.yml` configure a level
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "debug")
    write_config_yml(mock_main_path, "connector:\n  log_level: error\n")

    # When: The level name is resolved
    level_name = get_log_level()

    # Then: The environment wins
    assert level_name == "DEBUG"


def test_get_log_level_should_read_config_yml(mock_main_path):
    """Test that `connector.log_level` is read from `config.yml`."""
    # Given: A `config.yml` configuring the level
    write_config_yml(mock_main_path, "connector:\n  log_level: warning\n")

    # When: The level name is resolved
    level_name = get_log_level()

    # Then: It comes from the file
    assert level_name == "WARNING"


def test_get_log_level_should_read_dot_env(mock_main_path):
    """Test that `CONNECTOR_LOG_LEVEL` is read from `.env`."""
    # Given: A `.env` configuring the level, and no `config.yml`
    write_dot_env(mock_main_path, "CONNECTOR_LOG_LEVEL=info\n")

    # When: The level name is resolved
    level_name = get_log_level()

    # Then: It comes from the file
    assert level_name == "INFO"


def test_get_log_level_should_ignore_dot_env_when_config_yml_exists(
    mock_main_path,
):
    """Test that `config.yml` and `.env` are mutually exclusive.

    This mirrors `_SettingsLoader.settings_customise_sources`, which returns as soon as a
    `config.yml` is found and never consults `.env`. Trying each source in turn instead
    would silently diverge from how the connector's own settings are loaded.
    """
    # Given: A `config.yml` without a level, alongside a `.env` that has one
    write_config_yml(mock_main_path, "connector:\n  name: demo\n")
    write_dot_env(mock_main_path, "CONNECTOR_LOG_LEVEL=debug\n")

    # When: The level name is resolved
    level_name = get_log_level()

    # Then: The `.env` is not consulted
    assert level_name == "ERROR"


@pytest.mark.parametrize(
    "document",
    [
        pytest.param("connector:\n  name: demo\n", id="no-log-level-key"),
        pytest.param("connector:\n", id="empty-connector-section"),
        pytest.param("opencti:\n  url: http://localhost\n", id="no-connector-section"),
        pytest.param("connector: not-a-mapping\n", id="connector-not-a-mapping"),
        pytest.param("- a\n- b\n", id="document-not-a-mapping"),
        pytest.param("", id="empty-document"),
        pytest.param("connector:\n  log_level: 10\n", id="level-not-a-string"),
        pytest.param("connector: [\n", id="malformed-yaml"),
    ],
)
def test_get_log_level_should_tolerate_unusable_config_yml(mock_main_path, document):
    """Test that an unusable `config.yml` never prevents logging from starting.

    Reporting configuration problems is the settings loader's job, and it does so with a
    proper validation error. Logging simply falls back to its default.
    """
    # Given: A `config.yml` that does not yield a level
    write_config_yml(mock_main_path, document)

    # When: The level name is resolved
    level_name = get_log_level()

    # Then: Nothing is returned, and nothing is raised
    assert level_name == "ERROR"


def test_get_log_level_should_tolerate_an_unreadable_config_yml(
    monkeypatch, mock_main_path
):
    """Test that a `config.yml` which disappears between discovery and reading is tolerated."""
    # Given: A configuration file path that cannot be read
    monkeypatch.setattr(
        "connectors_sdk.logger._log_level.get_config_yml_path",
        lambda: mock_main_path / "vanished.yml",
    )

    # When: The level name is resolved
    level_name = get_log_level()

    # Then: Nothing is returned, and nothing is raised
    assert level_name == "ERROR"


def test_get_log_level_should_tolerate_a_dot_env_without_the_variable(
    mock_main_path,
):
    """Test that a `.env` not mentioning the level yields `None`."""
    # Given: A `.env` configuring something else
    write_dot_env(mock_main_path, "CONNECTOR_NAME=demo\n")

    # When: The level name is resolved
    level_name = get_log_level()

    # Then: Nothing is returned
    assert level_name == "ERROR"


def test_get_log_level_should_not_log_about_a_dot_env_without_the_variable(
    caplog, mock_main_path
):
    """Test that an absent level is not reported in the connector's own log stream.

    `dotenv.get_key` runs in verbose mode, where a missing key is logged as a warning.
    `log_level` is optional, so most connectors would emit that warning on every start.
    """
    # Given: A `.env` configuring something else
    write_dot_env(mock_main_path, "CONNECTOR_NAME=demo\n")

    # When: The level name is resolved
    with caplog.at_level(logging.DEBUG):
        get_log_level()

    # Then: Nothing is logged about it
    assert caplog.records == []


def test_get_log_level_should_fall_back_to_the_default_without_configuration(
    mock_main_path,
):
    """Test that a connector with no configuration at all yields `None`."""
    # Given: Neither environment variable nor configuration file
    # When: The level name is resolved
    level_name = get_log_level()

    # Then: Nothing is returned
    assert level_name == "ERROR"


def test_get_log_level_should_fall_back_to_the_default_without_entrypoint(
    mock_missing_main_path,
):
    """Test that an unlocatable connector yields `None` rather than raising."""
    # Given: A process whose `__main__` has no `__file__`
    # When: The level name is resolved
    level_name = get_log_level()

    # Then: Nothing is returned
    assert level_name == "ERROR"
