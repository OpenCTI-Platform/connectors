"""Checks for config.yml (running without Docker): keys map to the environment variable names,
an environment variable wins over the file, empty values mean the default.

Run: python tests/test_config_file.py (or pytest).
"""

import os
import sys
import tempfile

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ["DATA_DIR"] = tempfile.mkdtemp()

from common import config  # noqa: E402  pylint: disable=wrong-import-position

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "config.yml.sample")


def _write(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _clear(*names):
    for name in names:
        os.environ.pop(name, None)


def test_keys_become_setting_names():
    _clear(
        "OPENCTI_URL",
        "EXPORT_MAX_ENTRIES",
        "CUSTOM_FEED1_NAME",
        "EXPORT_HASH_SPLIT_FILES",
    )
    path = _write(
        "opencti:\n  url: https://x.example\nexport:\n  max_entries: 100\n"
        "  hash_split_files: true\ncustom_feed1:\n  name: partner\n"
    )
    assert config.load_config_file(path) == 4
    assert os.environ["OPENCTI_URL"] == "https://x.example"
    assert os.environ["EXPORT_MAX_ENTRIES"] == "100"
    assert os.environ["EXPORT_HASH_SPLIT_FILES"] == "true"
    assert os.environ["CUSTOM_FEED1_NAME"] == "partner"


def test_environment_wins_and_empty_is_default():
    os.environ["EXPORT_MAX_ENTRIES"] = "7"
    _clear("EXPORT_MAX_ENTRIES_IP")
    path = _write("export:\n  max_entries: 100\n  max_entries_ip:\n")
    assert config.load_config_file(path) == 0
    assert os.environ["EXPORT_MAX_ENTRIES"] == "7"
    assert "EXPORT_MAX_ENTRIES_IP" not in os.environ


def test_list_values_are_comma_separated():
    _clear("EXPORT_IP_EXCLUDE")
    path = _write("export:\n  ip_exclude: [192.0.2.1, 198.51.100.0/24]\n")
    config.load_config_file(path)
    assert os.environ["EXPORT_IP_EXCLUDE"] == "192.0.2.1,198.51.100.0/24"


def test_no_file_changes_nothing():
    assert config.load_config_file("/nonexistent/config.yml") == 0


def test_bad_file_stops_startup():
    path = _write("export: [1, 2\n")
    try:
        config.load_config_file(path)
    except SystemExit as exc:
        assert "Cannot read" in str(exc)
    else:
        raise AssertionError("a broken config.yml must stop startup")


def test_sample_reads_into_valid_settings():
    """config.yml.sample, filled in, gives the same settings as the documented defaults."""
    for key in list(os.environ):
        if key.startswith(
            (
                "OPENCTI_",
                "CONNECTOR_",
                "EXPORT_",
                "CUSTOM_FEED",
                "FEED_DISTRIBUTOR_",
                "DB_",
            )
        ):
            del os.environ[key]
    config.load_config_file(SAMPLE)
    os.environ["CONNECTOR_LIVE_STREAM_ID"] = "ffa7afb2-0720-42f7-be50-cf932eb61f36"
    assert config.connector_settings().connector_name == "IOC List Distributor"
    export = config.export_settings()
    assert export.max_entries["ip"] == 5000 and export.rolling_window_minutes == 43200
    assert export.db_retention_days == 90
    assert config.feed_distributor_settings().http_port == 8080


if __name__ == "__main__":
    for name, test in list(globals().items()):
        if name.startswith("test_"):
            test()
    print("config file tests passed")
