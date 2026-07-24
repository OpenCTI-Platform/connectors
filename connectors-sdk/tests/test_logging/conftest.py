import builtins
from pathlib import Path

import pytest

TESTS_DATA_DIRECTORY = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture
def mock_connector_log_level_in_legacy_config_yml(mock_main_path, monkeypatch):
    """Fake presence of legacy config.yml using real data file content."""
    main_path = Path("/app/src/main.py")
    legacy_config_path = main_path.parent / "config.yml"

    # Fake the presence of legacy config.yml file
    original_is_file = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self: (self == legacy_config_path) or original_is_file(self),
    )

    # Patch open to return our test config.test.yml content instead of a real config.yml file
    original_open = open

    def _open(path, mode="r", *args, **kwargs):
        if Path(path) == legacy_config_path:
            return original_open(
                TESTS_DATA_DIRECTORY / "config.test.yml", mode, *args, **kwargs
            )
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _open)


@pytest.fixture
def mock_connector_log_level_in_config_yml(mock_main_path, monkeypatch):
    """Fake presence of new config.yml using real data file content."""
    main_path = Path("/app/src/main.py")
    new_config_path = main_path.parent.parent / "config.yml"

    # Fake the absence of legacy config.yml file and presence of new config.yml file
    original_is_file = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self: (self == new_config_path) or original_is_file(self),
    )

    # Patch open to return our test config.test.yml content instead of a real config.yml file
    original_open = open

    def _open(path, mode="r", *args, **kwargs):
        if Path(path) == new_config_path:
            return original_open(
                TESTS_DATA_DIRECTORY / "config.test.yml", mode, *args, **kwargs
            )
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _open)


@pytest.fixture
def mock_connector_log_level_in_dot_env(mock_main_path, monkeypatch):
    """Fake presence of .env file using real data file content."""
    main_path = Path("/app/src/main.py")
    dot_env_path = main_path.parent.parent / ".env"

    # Fake the absence fo config.yml files and presence of .env file
    original_is_file = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self: (self == dot_env_path) or original_is_file(self),
    )

    # Patch dotenv.get_key to read from our test .env.test file instead of a real .env file
    from dotenv import dotenv_values

    def _get_key(path: Path, key: str):
        if Path(path) == dot_env_path:
            return dotenv_values(TESTS_DATA_DIRECTORY / ".env.test").get(key)
        return None

    monkeypatch.setattr("dotenv.get_key", _get_key)
