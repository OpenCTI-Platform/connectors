"""Checks for the stream connector: event handling, storage retries, log levels and the summary,
and the CONNECTOR_LIVE_STREAM_ID check. No OpenCTI or pycti needed (the helper is faked).

Run: python tests/test_connector.py (or pytest).
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

os.environ["DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common import config  # noqa: E402
from connector import connector  # noqa: E402

OK_PATTERN = "[ipv4-addr:value = '203.0.113.7']"


class FakeLogger:
    """Stands in for helper.connector_logger: records (level, message, meta)."""

    def __init__(self):
        self.lines = []

    def _log(self, level, message, meta=None):
        self.lines.append((level, message, meta or {}))

    def debug(self, message, meta=None):
        self._log("DEBUG", message, meta)

    def info(self, message, meta=None):
        self._log("INFO", message, meta)

    def warning(self, message, meta=None):
        self._log("WARNING", message, meta)

    def error(self, message, meta=None):
        self._log("ERROR", message, meta)

    def at(self, level):
        return [line for line in self.lines if line[0] == level]


class FakeStore:
    """Fails the first `fail` calls of every write, then works."""

    def __init__(self, fail=0):
        self.fail = fail
        self.calls = []
        self.events = []

    def _maybe_fail(self, name):
        self.calls.append(name)
        if self.fail:
            self.fail -= 1
            raise RuntimeError("database is locked")

    def upsert_indicator(self, *args, **kwargs):
        self._maybe_fail("upsert_indicator")
        return 1, 0, 0

    def delete_indicator(self, *args):
        self._maybe_fail("delete_indicator")
        return 2

    def record_event(self, event, skipped):
        self.events.append((event, skipped))


def make_connector(store=None):
    """An IocStreamConnector without pycti: fake helper logger, fake store, fake clock."""
    conn = object.__new__(connector.IocStreamConnector)
    conn.settings = SimpleNamespace(
        name_fallback=False, warnings=(), live_stream_id="s", opencti_url="u"
    )
    conn.store = store or FakeStore()
    conn.logger = FakeLogger()
    conn.sleeps = []
    conn._sleep = conn.sleeps.append
    conn.now = [0.0]
    conn._clock = lambda: conn.now[0]
    conn._init_counters()
    return conn


def msg(event, pattern=OK_PATTERN, ind_id="indicator-1", **extra):
    data = {
        "type": "indicator",
        "id": "indicator--x",
        "x_opencti_id": ind_id,
        "name": "n",
        "pattern_type": "stix",
        "pattern": pattern,
        **extra,
    }
    return SimpleNamespace(id="1-0", event=event, data=json.dumps({"data": data}))


def test_routine_lines_are_debug():
    conn = make_connector()
    conn._on_message(msg("create"))
    conn._on_message(msg("update", pattern="[email-addr:value = 'a@b.c']"))
    conn._on_message(msg("update", revoked=True))
    conn._on_message(msg("delete"))
    assert not conn.logger.at("INFO"), conn.logger.at("INFO")
    assert not conn.logger.at("WARNING") and not conn.logger.at("ERROR")
    debug = [line[1] for line in conn.logger.at("DEBUG")]
    assert any("+1 added" in m for m in debug), debug
    assert any("skipped: no IP, domain, URL or hash" in m for m in debug), debug
    assert any("revoked: 2 IOC(s) removed" in m for m in debug), debug
    assert any("deleted or left the stream filters" in m for m in debug), debug
    # Structured fields, not only text.
    skip = next(line for line in conn.logger.at("DEBUG") if "skipped" in line[1])
    assert skip[2]["indicator_id"] == "indicator-1" and skip[2]["reason"], skip
    assert conn.store.events == [
        ("create", False),
        ("update", True),
        ("update", False),
        ("delete", False),
    ]


def test_summary_every_interval():
    conn = make_connector()
    conn._on_message(msg("create"))
    conn._on_message(msg("update", pattern="[email-addr:value = 'a@b.c']"))
    conn._on_message(
        msg("update", ind_id="indicator-2", pattern="[email-addr:value = 'x@y.z']")
    )
    assert not conn.logger.at("INFO")
    conn.now[0] = connector.SUMMARY_INTERVAL_SECONDS + 1
    conn._on_message(msg("delete"))
    info = conn.logger.at("INFO")
    assert len(info) == 1, info
    text, meta = info[0][1], info[0][2]
    assert text.startswith(
        "Stream: 4 indicator event(s) since the last summary (1 stored, 1 deleted, 2 skipped)"
    ), text
    assert (
        "no IP, domain, URL or hash with a valid value in the pattern (2)" in text
    ), text
    assert text.endswith("; 4 since start"), text
    assert meta["skipped"] == 2 and meta["events_since_start"] == 4, meta
    # Counters restart; nothing new -> no summary line.
    conn.now[0] += connector.SUMMARY_INTERVAL_SECONDS + 1
    conn.log_summary()
    assert len(conn.logger.at("INFO")) == 1
    conn.log_summary(force=True)
    assert len(conn.logger.at("INFO")) == 1


def test_store_retry_then_success():
    store = FakeStore(fail=2)
    conn = make_connector(store)
    conn._on_message(msg("delete"))
    assert store.calls == ["delete_indicator"] * 3, store.calls
    assert conn.sleeps == [1, 2], conn.sleeps
    warnings = conn.logger.at("WARNING")
    assert len(warnings) == 2 and "try 1 of 5" in warnings[0][1], warnings
    assert not conn.logger.at("ERROR")
    assert store.events == [("delete", False)]


def test_store_retry_gives_up():
    store = FakeStore(fail=99)
    conn = make_connector(store)
    conn._on_message(msg("delete"))
    assert store.calls == ["delete_indicator"] * 5, store.calls
    assert conn.sleeps == list(connector.STORE_RETRY_DELAYS), conn.sleeps
    errors = conn.logger.at("ERROR")
    assert len(errors) == 1 and "failed 5 times" in errors[0][1], errors
    assert store.events == [], "a failed event is not recorded as processed"
    conn.now[0] = connector.SUMMARY_INTERVAL_SECONDS + 1
    conn.log_summary()
    assert "1 failed" in conn.logger.at("INFO")[0][1]
    # The stream goes on with the next event.
    store.fail = 0
    conn._on_message(msg("create"))
    assert store.events == [("create", False)]


def test_bad_event_does_not_stop_the_stream():
    conn = make_connector()
    conn._on_message(SimpleNamespace(id="9-0", event="create", data="{not json"))
    assert len(conn.logger.at("ERROR")) == 1
    conn._on_message(msg("create"))
    assert conn.store.events == [("create", False)]


def test_other_events_ignored():
    conn = make_connector()
    conn._on_message(SimpleNamespace(id="1-0", event="heartbeat", data="{}"))
    conn._on_message(
        SimpleNamespace(
            id="1-0", event="create", data=json.dumps({"data": {"type": "malware"}})
        )
    )
    assert conn.store.calls == [] and conn.store.events == [] and not conn.logger.lines


def test_live_stream_id_check():
    assert config.check_live_stream_id("ffa7afb2-0720-42f7-be50-cf932eb61f36") == []
    for placeholder in ("ChangeMe", "changeme", "ChangeMe-stream-id"):
        try:
            config.check_live_stream_id(placeholder)
        except SystemExit as exc:
            assert "placeholder" in str(exc)
        else:
            raise AssertionError(f"{placeholder} accepted")
    for stream_id in ("live", "LIVE", "raw"):
        warnings = config.check_live_stream_id(stream_id)
        assert len(warnings) == 1 and "global stream" in warnings[0], warnings


def _connector_env(**values):
    for name in (
        "OPENCTI_URL",
        "OPENCTI_TOKEN",
        "OPENCTI_SSL_VERIFY",
        "CONNECTOR_ID",
        "CONNECTOR_NAME",
        "CONNECTOR_LIVE_STREAM_ID",
        "PARSER_NAME_FALLBACK",
    ):
        os.environ.pop(name, None)
    os.environ.update(
        {
            "OPENCTI_URL": "https://opencti.example/",
            "OPENCTI_TOKEN": "token",
            "CONNECTOR_ID": "id",
            "CONNECTOR_LIVE_STREAM_ID": "ffa7afb2-0720-42f7-be50-cf932eb61f36",
            **values,
        }
    )


def test_connector_settings_valid():
    _connector_env(OPENCTI_SSL_VERIFY="false", PARSER_NAME_FALLBACK="true")
    settings = config.connector_settings()
    assert settings.opencti_url == "https://opencti.example"
    assert settings.opencti_ssl_verify is False and settings.name_fallback is True
    assert settings.connector_name == "IOC List Distributor"
    assert settings.helper_config()["connector"]["type"] == "STREAM"


def test_connector_settings_invalid():
    for values, expected in (
        ({"OPENCTI_TOKEN": ""}, "Missing required setting: OPENCTI_TOKEN"),
        ({"CONNECTOR_ID": "   "}, "Missing required setting: CONNECTOR_ID"),
        ({"OPENCTI_SSL_VERIFY": "maybe"}, "OPENCTI_SSL_VERIFY must be true or false"),
    ):
        _connector_env(**values)
        try:
            config.connector_settings()
        except SystemExit as exc:
            assert expected in str(exc), exc
        else:
            raise AssertionError(f"{values} accepted")


if __name__ == "__main__":
    for name, func in sorted(globals().items()):
        if name.startswith("test_") and callable(func):
            func()
            print(f"ok  {name}")
    print("All connector checks passed")
