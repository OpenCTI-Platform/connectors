"""Ingestion, state and recovery tests; no network or OpenCTI server needed."""

import copy
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def connector_module(monkeypatch):
    # Load connector.py with its StixMaker dependency stubbed: state tests must
    # work without a STIX library or a running OpenCTI server.
    dependency_name = "src.bitdefender_import_feed.stixmaker"
    dependency = types.ModuleType(dependency_name)
    dependency.StixMaker = object
    monkeypatch.setitem(sys.modules, dependency_name, dependency)
    spec = importlib.util.spec_from_file_location(
        "_bitdefender_connector_under_test",
        ROOT / "src" / "bitdefender_import_feed" / "connector.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def connector_factory(connector_module, monkeypatch):
    def factory(*, initial_state=None, feeds=("ip",), now=None):
        saved = []
        helper = MagicMock()
        helper.connect_name = "Bitdefender test"
        helper.get_state.return_value = copy.deepcopy(initial_state)
        helper.set_state.side_effect = lambda state: saved.append(copy.deepcopy(state))
        config = SimpleNamespace(
            bitdefender=SimpleNamespace(
                feeds=list(feeds),
                api_key=SecretStr("test-key"),
                min_confidence=75,
                min_severity=1,
                include_revoked="false",
                include_suspicious="false",
                exclude_related_indicators=False,
                exclude_similar_files=False,
                http_timeout_seconds=30,
                verify_tls=True,
                detection=False,
            )
        )
        if now is not None:
            monkeypatch.setattr(connector_module.time, "time", lambda: now)
        return connector_module.BitdefenderFeedConnector(config, helper), helper, saved

    return factory


class RecordingStixMaker:
    instances = []
    fail_final = False

    def __init__(self, **kwargs):
        self.seen = []
        self.final_calls = 0
        self.errors = []
        self.__class__.instances.append(self)

    def fromEntry(self, line):
        self.seen.append(line)
        if line == "invalid":
            raise ValueError("invalid entry")
        return line == "flush"

    def sendFinal(self):
        self.final_calls += 1
        if self.fail_final:
            raise RuntimeError("bundle send failed")

    def sendError(self, message):
        self.errors.append(message)


@pytest.fixture
def fake_maker(connector_module, monkeypatch):
    RecordingStixMaker.instances = []
    RecordingStixMaker.fail_final = False
    monkeypatch.setattr(connector_module, "StixMaker", RecordingStixMaker)
    return RecordingStixMaker


def test_download_enqueues_time_window_without_advancing_committed_watermark(
    connector_module,
    connector_factory,
    monkeypatch,
    tmp_path,
):
    monkeypatch.chdir(tmp_path)
    initial = {"last_update": {"file": 0, "ip": 100, "web": 0}, "queue": []}
    connector, helper, saved = connector_factory(initial_state=initial, now=200)
    response = MagicMock()
    response.iter_content.return_value = [b'{"ip":"192.0.2.1"}\n', b""]
    monkeypatch.setattr(
        connector_module.requests, "get", MagicMock(return_value=response)
    )

    connector.download_feeds()

    assert connector.state["last_update"]["ip"] == 100
    assert connector.state["queue"] == [
        {"feed": "ip", "file": "ip.json", "line": 0, "until": 200}
    ]
    assert (tmp_path / "ip.json").read_bytes() == b'{"ip":"192.0.2.1"}\n'
    assert saved[-1]["queue"][0]["until"] == 200
    args = connector_module.requests.get.call_args.kwargs
    assert args["headers"]["auth-token"] == "test-key"
    assert args["params"]["last_seconds"] == 100
    assert args["params"]["feed_name"] == "ip-feed"
    response.raise_for_status.assert_called_once_with()


def test_download_caps_window_at_24_hours(
    connector_module, connector_factory, monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)
    initial = {"last_update": {"file": 0, "ip": 1, "web": 0}, "queue": []}
    connector, _, _ = connector_factory(initial_state=initial, now=200000)
    response = MagicMock()
    response.iter_content.return_value = []
    monkeypatch.setattr(
        connector_module.requests, "get", MagicMock(return_value=response)
    )
    connector.download_feeds()
    assert (
        connector_module.requests.get.call_args.kwargs["params"]["last_seconds"]
        == 86400
    )
    connector.helper.connector_logger.warning.assert_called_once()
    assert "outside" in connector.helper.connector_logger.warning.call_args.args[0]


def test_download_failure_does_not_enqueue_or_advance_watermark(
    connector_module,
    connector_factory,
    monkeypatch,
    tmp_path,
):
    monkeypatch.chdir(tmp_path)
    initial = {"last_update": {"file": 0, "ip": 100, "web": 0}, "queue": []}
    connector, helper, _ = connector_factory(initial_state=initial, now=200)
    response = MagicMock()
    response.raise_for_status.side_effect = RuntimeError("HTTP 503")
    monkeypatch.setattr(
        connector_module.requests, "get", MagicMock(return_value=response)
    )

    with pytest.raises(Exception, match="HTTP 503"):
        connector.download_feeds()

    assert connector.state == initial
    helper.connector_logger.error.assert_called()


def test_resume_skips_checkpointed_lines_and_commits_after_final(
    connector_factory,
    fake_maker,
    tmp_path,
):
    file_path = tmp_path / "ip.json"
    file_path.write_text("old1\nold2\ngood\nflush\n")
    initial = {
        "last_update": {"file": 0, "ip": 100, "web": 0},
        "queue": [{"feed": "ip", "file": str(file_path), "line": 2, "until": 200}],
    }
    connector, _, saved = connector_factory(initial_state=initial)

    connector.import_downloaded_feeds()

    maker = fake_maker.instances[0]
    assert maker.seen == ["good", "flush"]
    assert maker.final_calls == 1
    assert not file_path.exists()
    assert connector.state["last_update"]["ip"] == 200
    assert connector.state["queue"] == []
    # A durable checkpoint is saved after the flush, before the completion marker.
    assert any(
        s["queue"] and s["queue"][0]["line"] == 4 and s["last_update"]["ip"] == 100
        for s in saved
    )
    assert saved[-1]["last_update"]["ip"] == 200


def test_invalid_entry_is_skipped_but_later_lines_are_processed(
    connector_factory,
    fake_maker,
    tmp_path,
):
    file_path = tmp_path / "ip.json"
    file_path.write_text("valid\ninvalid\nflush\n")
    initial = {
        "last_update": {"file": 0, "ip": 100, "web": 0},
        "queue": [{"feed": "ip", "file": str(file_path), "line": 0, "until": 200}],
    }
    connector, helper, _ = connector_factory(initial_state=initial)

    connector.import_downloaded_feeds()

    assert fake_maker.instances[0].seen == ["valid", "invalid", "flush"]
    assert connector.state["queue"] == []
    assert any(
        "line 2" in str(call) for call in helper.connector_logger.error.call_args_list
    )


def test_lost_download_keeps_old_watermark_and_closes_work(
    connector_factory,
    fake_maker,
    tmp_path,
):
    initial = {
        "last_update": {"file": 0, "ip": 100, "web": 0},
        "queue": [
            {
                "feed": "ip",
                "file": str(tmp_path / "missing.json"),
                "line": 0,
                "until": 200,
            }
        ],
    }
    connector, _, _ = connector_factory(initial_state=initial)

    connector.import_downloaded_feeds()

    assert connector.state["last_update"]["ip"] == 100
    assert connector.state["queue"] == []
    assert fake_maker.instances[0].errors == ["Downloaded feed file is missing"]


def test_failed_final_send_retains_queue_and_marks_work_failed(
    connector_factory,
    fake_maker,
    tmp_path,
):
    file_path = tmp_path / "ip.json"
    file_path.write_text("valid\n")
    initial = {
        "last_update": {"file": 0, "ip": 100, "web": 0},
        "queue": [{"feed": "ip", "file": str(file_path), "line": 0, "until": 200}],
    }
    connector, _, _ = connector_factory(initial_state=initial)
    fake_maker.fail_final = True

    with pytest.raises(RuntimeError, match="bundle send failed"):
        connector.import_downloaded_feeds()

    assert file_path.exists()
    assert len(connector.state["queue"]) == 1
    assert connector.state["last_update"]["ip"] == 100
    assert fake_maker.instances[0].errors == ["bundle send failed"]


def test_legacy_queue_without_until_does_not_crash(
    connector_factory, fake_maker, tmp_path
):
    file_path = tmp_path / "old.json"
    file_path.write_text("valid\n")
    initial = {
        "last_update": {"file": 0, "ip": 100, "web": 0},
        "queue": [{"feed": "ip", "file": str(file_path), "line": 0}],
    }
    connector, _, _ = connector_factory(initial_state=initial)
    connector.import_downloaded_feeds()
    assert connector.state["last_update"]["ip"] == 100
    assert not connector.state["queue"]
