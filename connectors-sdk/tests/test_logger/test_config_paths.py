"""Tests for `connectors_sdk._config_paths`."""

from connectors_sdk._config_paths import (
    get_config_yml_path,
    get_connector_main_path,
    get_dot_env_path,
)


def test_get_connector_main_path_should_resolve_the_entrypoint(mock_main_path):
    """Test that the running connector's `main.py` is located."""
    # Given: A connector launched from `<root>/src/main.py`
    # When: The main path is resolved
    main_path = get_connector_main_path()

    # Then: It points at the entrypoint
    assert main_path == mock_main_path / "src" / "main.py"


def test_get_connector_main_path_should_return_none_without_entrypoint(
    mock_missing_main_path,
):
    """Test that a process without a file-backed entrypoint yields `None`.

    Logging must work in an interactive interpreter or a test runner, so this never
    raises, unlike the settings loader which needs a configuration file to exist.
    """
    # Given: A process whose `__main__` has no `__file__`
    # When: The main path is resolved
    main_path = get_connector_main_path()

    # Then: Nothing is reported rather than an error being raised
    assert main_path is None


def test_get_config_yml_path_should_find_the_legacy_location(mock_main_path):
    """Test that a `config.yml` sitting next to `main.py` is found."""
    # Given: A `config.yml` in the same directory as the entrypoint
    expected_path = mock_main_path / "src" / "config.yml"
    expected_path.touch()

    # When: The configuration file is located
    config_yml_path = get_config_yml_path()

    # Then: The legacy location is returned
    assert config_yml_path == expected_path


def test_get_config_yml_path_should_find_the_current_location(mock_main_path):
    """Test that a `config.yml` one directory above `main.py` is found."""
    # Given: A `config.yml` in the connector's root directory
    expected_path = mock_main_path / "config.yml"
    expected_path.touch()

    # When: The configuration file is located
    config_yml_path = get_config_yml_path()

    # Then: The current location is returned
    assert config_yml_path == expected_path


def test_get_config_yml_path_should_prefer_the_legacy_location(mock_main_path):
    """Test that the legacy location wins when both exist."""
    # Given: A `config.yml` in both supported locations
    legacy_path = mock_main_path / "src" / "config.yml"
    legacy_path.touch()
    (mock_main_path / "config.yml").touch()

    # When: The configuration file is located
    config_yml_path = get_config_yml_path()

    # Then: The legacy location takes precedence
    assert config_yml_path == legacy_path


def test_get_config_yml_path_should_return_none_when_absent(mock_main_path):
    """Test that a connector without a `config.yml` yields `None`."""
    # Given: A connector with no configuration file
    # When: The configuration file is located
    config_yml_path = get_config_yml_path()

    # Then: Nothing is reported
    assert config_yml_path is None


def test_get_config_yml_path_should_return_none_without_entrypoint(
    mock_missing_main_path,
):
    """Test that an unlocatable connector yields no `config.yml`."""
    # Given: A process whose `__main__` has no `__file__`
    # When: The configuration file is located
    config_yml_path = get_config_yml_path()

    # Then: Nothing is reported
    assert config_yml_path is None


def test_get_dot_env_path_should_find_the_file(mock_main_path):
    """Test that a `.env` one directory above `main.py` is found."""
    # Given: A `.env` in the connector's root directory
    expected_path = mock_main_path / ".env"
    expected_path.touch()

    # When: The `.env` file is located
    dot_env_path = get_dot_env_path()

    # Then: Its path is returned
    assert dot_env_path == expected_path


def test_get_dot_env_path_should_return_none_when_absent(mock_main_path):
    """Test that a connector without a `.env` yields `None`."""
    # Given: A connector with no `.env` file
    # When: The `.env` file is located
    dot_env_path = get_dot_env_path()

    # Then: Nothing is reported
    assert dot_env_path is None


def test_get_dot_env_path_should_return_none_without_entrypoint(
    mock_missing_main_path,
):
    """Test that an unlocatable connector yields no `.env`."""
    # Given: A process whose `__main__` has no `__file__`
    # When: The `.env` file is located
    dot_env_path = get_dot_env_path()

    # Then: Nothing is reported
    assert dot_env_path is None
