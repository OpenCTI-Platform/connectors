"""Tests for request recorders — targeting 100% coverage of recorders.py."""

from __future__ import annotations

import io
import json
import logging
import zipfile
from datetime import timedelta
from unittest.mock import MagicMock

import requests
from connectors_sdk.client.recorders import (
    FileSystemRecorder,
    LogRecorder,
    MultiRecorder,
    OpenCTIFileRecorder,
    RequestRecorder,
    build_exchange,
    build_recorder,
    redact_headers,
    serializable_body,
)


def _mock_response(
    *,
    status_code: int = 200,
    content: bytes = b'{"ok": true}',
    request_method: str = "GET",
    request_url: str = "https://api.example.com/test",
    request_headers: dict | None = None,
    request_body=None,
    response_headers: dict | None = None,
):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.content = content
    resp.headers = response_headers or {}
    resp.elapsed = timedelta(milliseconds=10)
    req = MagicMock(spec=requests.PreparedRequest)
    req.method = request_method
    req.url = request_url
    req.headers = request_headers or {}
    req.body = request_body
    resp.request = req
    return resp


# ===========================================================================
# Helpers
# ===========================================================================


class TestRedactHeaders:
    def test_redacts_sensitive(self):
        result = redact_headers(
            {"Authorization": "secret", "X-API-KEY": "k", "Accept": "json"}
        )
        assert result["Authorization"] == "***REDACTED***"
        assert result["X-API-KEY"] == "***REDACTED***"
        assert result["Accept"] == "json"

    def test_none_headers(self):
        assert redact_headers(None) == {}


class TestSerializableBody:
    def test_none(self):
        assert serializable_body(None) is None

    def test_json_parsed(self):
        assert serializable_body('{"a": 1}') == {"a": 1}

    def test_plain_text(self):
        assert serializable_body("not json") == "not json"

    def test_bytes_decoded_json(self):
        assert serializable_body(b'{"a": 1}') == {"a": 1}

    def test_binary_summarized(self):
        assert serializable_body(b"\xff\xfe\x00") == "<binary 3 bytes>"

    def test_truncation(self):
        result = serializable_body("x" * 50, max_chars=10)
        assert result == "x" * 10 + "...[truncated]"

    def test_non_str_non_bytes_coerced(self):
        assert serializable_body(12345) == 12345


class TestBuildExchange:
    def test_structure(self):
        resp = _mock_response(
            content=b'{"result": "ok"}',
            request_method="POST",
            request_url="https://api.example.com/x",
            request_headers={"Authorization": "secret"},
            request_body='{"a": 1}',
            response_headers={"Set-Cookie": "s=1"},
        )
        exchange = build_exchange(resp, seq=3)
        assert exchange["seq"] == 3
        assert exchange["request"]["method"] == "POST"
        assert exchange["request"]["headers"]["Authorization"] == "***REDACTED***"
        assert exchange["request"]["body"] == {"a": 1}
        assert exchange["response"]["status_code"] == 200
        assert exchange["response"]["headers"]["Set-Cookie"] == "***REDACTED***"
        assert exchange["response"]["body"] == {"result": "ok"}
        assert exchange["response"]["elapsed_ms"] == 10.0


# ===========================================================================
# FileSystemRecorder
# ===========================================================================


class TestFileSystemRecorder:
    def test_creates_session_dir(self, tmp_path):
        recorder = FileSystemRecorder(tmp_path)
        assert recorder.session_dir.exists()
        assert recorder.session_dir.parent == tmp_path
        assert recorder.session_dir.name.startswith("session_")

    def test_records_file(self, tmp_path):
        recorder = FileSystemRecorder(tmp_path)
        recorder.record({"seq": 1, "request": {"method": "get"}})
        files = list(recorder.session_dir.glob("*.json"))
        assert len(files) == 1
        assert files[0].name == "0001_GET.json"
        assert json.loads(files[0].read_text())["seq"] == 1

    def test_record_missing_method(self, tmp_path):
        recorder = FileSystemRecorder(tmp_path)
        recorder.record({"seq": 2})
        assert (recorder.session_dir / "0002_REQUEST.json").exists()

    def test_record_failure_is_swallowed(self, tmp_path):
        recorder = FileSystemRecorder(tmp_path)
        recorder.session_dir = tmp_path / "does" / "not" / "exist"
        recorder.record({"seq": 1, "request": {"method": "get"}})  # must not raise

    def test_close_is_noop(self, tmp_path):
        FileSystemRecorder(tmp_path).close()


# ===========================================================================
# LogRecorder
# ===========================================================================


class TestLogRecorder:
    def test_logs_exchange_via_callback(self):
        captured = []
        recorder = LogRecorder(log_callback=captured.append)
        recorder.record({"seq": 1, "response": {"status_code": 200}})
        assert len(captured) == 1
        assert "API exchange recorded" in captured[0]
        assert '"seq": 1' in captured[0]

    def test_logs_exchange_default_logger(self, caplog):
        recorder = LogRecorder()
        with caplog.at_level(logging.DEBUG):
            recorder.record({"seq": 1, "response": {"status_code": 200}})
        assert "API exchange recorded" in caplog.text

    def test_line_truncation(self):
        captured = []
        recorder = LogRecorder(log_callback=captured.append, max_line_chars=20)
        recorder.record({"seq": 1, "data": "x" * 100})
        assert captured[0].endswith("...[truncated]")

    def test_record_failure_is_swallowed(self):
        def boom(_message):
            raise RuntimeError("boom")

        recorder = LogRecorder(log_callback=boom)
        recorder.record({"seq": 1})  # must not raise

    def test_uses_default_logger(self):
        recorder = LogRecorder()
        assert recorder._log is not None

    def test_close_is_noop(self):
        LogRecorder().close()


# ===========================================================================
# OpenCTIFileRecorder
# ===========================================================================


class TestOpenCTIFileRecorder:
    def test_uploads_zip_on_close(self):
        uploaded = {}

        def upload(name, data):
            uploaded["name"] = name
            uploaded["data"] = data

        recorder = OpenCTIFileRecorder(upload, filename="debug.zip")
        recorder.record({"seq": 1, "request": {"method": "get"}, "response": {}})
        recorder.record({"seq": 2, "request": {"method": "post"}, "response": {}})
        recorder.close()

        assert uploaded["name"] == "debug.zip"
        with zipfile.ZipFile(io.BytesIO(uploaded["data"])) as archive:
            names = set(archive.namelist())
            assert "0001_GET.json" in names
            assert "0002_POST.json" in names
            assert "index.json" in names
            index = json.loads(archive.read("index.json"))
            assert index[0]["method"] == "GET"

    def test_default_filename(self):
        recorder = OpenCTIFileRecorder(lambda n, d: None)
        assert recorder._filename.startswith("debug_session_")
        assert recorder._filename.endswith(".zip")

    def test_close_without_exchanges_does_not_upload(self):
        called = []
        recorder = OpenCTIFileRecorder(lambda n, d: called.append(True))
        recorder.close()
        assert called == []

    def test_upload_failure_is_swallowed(self):
        def upload(name, data):
            raise RuntimeError("network down")

        recorder = OpenCTIFileRecorder(upload)
        recorder.record({"seq": 1, "request": {"method": "get"}, "response": {}})
        recorder.close()  # must not raise
        assert recorder._exchanges == []

    def test_index_entry_missing_method(self):
        uploaded = {}
        recorder = OpenCTIFileRecorder(
            lambda n, d: uploaded.update(data=d), filename="d.zip"
        )
        recorder.record({"seq": 5})
        recorder.close()
        with zipfile.ZipFile(io.BytesIO(uploaded["data"])) as archive:
            assert "0005_REQUEST.json" in archive.namelist()


# ===========================================================================
# MultiRecorder
# ===========================================================================


class TestMultiRecorder:
    def test_fans_out_record_and_close(self):
        events = []

        class Fake:
            def __init__(self, name):
                self.name = name

            def record(self, exchange):
                events.append(("record", self.name))

            def close(self):
                events.append(("close", self.name))

        multi = MultiRecorder([Fake("a"), Fake("b")])
        multi.record({"seq": 1})
        multi.close()
        assert ("record", "a") in events
        assert ("record", "b") in events
        assert ("close", "a") in events
        assert ("close", "b") in events

    def test_record_failure_isolated(self):
        recorded = []

        class Exploding:
            def record(self, exchange):
                raise RuntimeError("boom")

            def close(self):
                raise RuntimeError("boom")

        class Good:
            def record(self, exchange):
                recorded.append(True)

            def close(self):
                recorded.append("closed")

        multi = MultiRecorder([Exploding(), Good()])
        multi.record({"seq": 1})  # must not raise
        multi.close()  # must not raise
        assert True in recorded
        assert "closed" in recorded


def test_recorders_satisfy_protocol(tmp_path):
    assert isinstance(FileSystemRecorder(tmp_path), RequestRecorder)
    assert isinstance(LogRecorder(), RequestRecorder)
    assert isinstance(OpenCTIFileRecorder(lambda n, d: None), RequestRecorder)
    assert isinstance(MultiRecorder([]), RequestRecorder)


# ===========================================================================
# build_recorder factory
# ===========================================================================


class TestBuildRecorder:
    def test_disabled_returns_none(self):
        assert build_recorder(enabled=False) is None

    def test_log_mode_default(self):
        recorder = build_recorder(enabled=True)
        assert isinstance(recorder, LogRecorder)

    def test_log_mode_with_callback(self):
        captured = []
        recorder = build_recorder(
            enabled=True, mode="log", log_callback=captured.append
        )
        recorder.record({"seq": 1})
        assert captured

    def test_file_mode(self, tmp_path):
        recorder = build_recorder(enabled=True, mode="file", record_dir=tmp_path)
        assert isinstance(recorder, FileSystemRecorder)
        assert recorder.session_dir.parent == tmp_path

    def test_file_mode_default_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        recorder = build_recorder(enabled=True, mode="file")
        assert isinstance(recorder, FileSystemRecorder)
        assert recorder.session_dir.parent.name == "recordings"
