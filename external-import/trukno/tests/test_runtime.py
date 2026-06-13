import builtins
import json
from io import StringIO
from unittest.mock import MagicMock

import pytest
from trukno_connector import runtime
from trukno_connector.runtime import run_once
from trukno_connector.state import ConnectorState


class DummyHelper:
    def __init__(self):
        self.sent = []
        self.persisted = []

    def send_stix2_bundle(self, bundle, *args, **kwargs):
        self.sent.append(bundle)

    def set_state(self, state):
        self.persisted.append(state)


class DummyClient:
    def __init__(self, items):
        self.items = items

    def list_updated_breaches(self, updated_after):
        return self.items

    def get_breach_details(self, breach_id):
        return {
            "id": breach_id,
            "title": "Example",
            "publishedAt": "2026-04-20T12:00:00Z",
            "summary": "Summary",
            "relatedTTPs": [{"id": "ttp-1", "title": "Credential Access"}],
        }


def test_log_passes_context_as_logger_meta():
    helper = type("Helper", (), {"connector_logger": MagicMock()})()

    runtime._log(helper, "info", "Message", {"key": "value"})

    helper.connector_logger.info.assert_called_once_with(
        "Message", meta={"key": "value"}
    )


def test_run_once_fetches_transforms_and_sends_bundle():
    helper = DummyHelper()
    state = ConnectorState(last_seen_updated_at="2026-04-20T00:00:00Z")
    client = DummyClient(
        [type("Item", (), {"id": "b1", "updated_at": "2026-04-20T10:00:00Z"})()]
    )

    updated_state = run_once(helper=helper, client=client, state=state)

    assert len(helper.sent) == 1
    bundle = json.loads(helper.sent[0])
    report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    assert report["name"] == "Example"
    assert updated_state.last_seen_updated_at == "2026-04-20T10:00:00Z"


def test_run_once_skips_breach_without_linkable_entities_but_advances_checkpoint():
    helper = DummyHelper()
    state = ConnectorState(last_seen_updated_at="2026-04-20T00:00:00Z")

    class EmptyBreachClient(DummyClient):
        def get_breach_details(self, breach_id):
            return {
                "id": breach_id,
                "title": "Empty breach",
                "publishedAt": "2026-04-20T12:00:00Z",
                "summary": "No linkable entities",
            }

    client = EmptyBreachClient(
        [type("Item", (), {"id": "b1", "updated_at": "2026-04-20T10:00:00Z"})()]
    )

    updated_state = run_once(helper=helper, client=client, state=state)

    # No STIX-valid report can be built without object_refs, so nothing is sent,
    # but the checkpoint still advances so the breach is not refetched forever.
    assert helper.sent == []
    assert updated_state.last_seen_updated_at == "2026-04-20T10:00:00Z"
    assert helper.persisted == [{"last_seen_updated_at": "2026-04-20T10:00:00Z"}]


def test_prepare_helper_config_falls_back_to_defaults_for_blank_connector_fields():
    helper_config = runtime._prepare_helper_config(
        {"connector": {"name": "", "scope": "", "log_level": ""}}
    )

    connector = helper_config["connector"]
    assert connector["type"] == "EXTERNAL_IMPORT"
    assert connector["name"] == runtime.DEFAULT_CONNECTOR_NAME
    assert connector["scope"] == runtime.DEFAULT_CONNECTOR_SCOPE
    assert connector["log_level"] == "info"


def test_prepare_helper_config_preserves_explicit_connector_fields():
    helper_config = runtime._prepare_helper_config(
        {"connector": {"name": "Custom", "scope": "report", "log_level": "debug"}}
    )

    connector = helper_config["connector"]
    assert connector["name"] == "Custom"
    assert connector["scope"] == "report"
    assert connector["log_level"] == "debug"


def test_run_once_persists_checkpoint_after_each_successful_send_before_mid_batch_failure():
    helper = DummyHelper()
    state = ConnectorState(last_seen_updated_at="2026-04-20T00:00:00Z")

    class FailingClient(DummyClient):
        def get_breach_details(self, breach_id):
            if breach_id == "b2":
                raise RuntimeError("boom")
            return super().get_breach_details(breach_id)

    client = FailingClient(
        [
            type("Item", (), {"id": "b1", "updated_at": "2026-04-20T10:00:00Z"})(),
            type("Item", (), {"id": "b2", "updated_at": "2026-04-20T12:00:00Z"})(),
        ]
    )

    with pytest.raises(RuntimeError, match="boom"):
        run_once(helper=helper, client=client, state=state)

    assert helper.persisted == [{"last_seen_updated_at": "2026-04-20T10:00:00Z"}]
    assert state.last_seen_updated_at == "2026-04-20T10:00:00Z"


def test_run_once_marks_work_errored_on_mid_batch_failure():
    class HelperWithWork(DummyHelper):
        def __init__(self):
            super().__init__()
            self.connect_id = "connector-id"
            self.api = MagicMock()
            self.api.work.initiate_work.return_value = "work-1"

    helper = HelperWithWork()
    state = ConnectorState(last_seen_updated_at="2026-04-20T00:00:00Z")

    class FailingClient(DummyClient):
        def get_breach_details(self, breach_id):
            if breach_id == "b2":
                raise RuntimeError("boom")
            return super().get_breach_details(breach_id)

    client = FailingClient(
        [
            type("Item", (), {"id": "b1", "updated_at": "2026-04-20T10:00:00Z"})(),
            type("Item", (), {"id": "b2", "updated_at": "2026-04-20T12:00:00Z"})(),
        ]
    )

    with pytest.raises(RuntimeError, match="boom"):
        run_once(helper=helper, client=client, state=state)

    helper.api.work.to_processed.assert_called_once()
    _, kwargs = helper.api.work.to_processed.call_args
    assert kwargs.get("in_error") is True


def test_run_once_marks_work_processed_on_success():
    class HelperWithWork(DummyHelper):
        def __init__(self):
            super().__init__()
            self.connect_id = "connector-id"
            self.api = MagicMock()
            self.api.work.initiate_work.return_value = "work-1"

    helper = HelperWithWork()
    state = ConnectorState(last_seen_updated_at="2026-04-20T00:00:00Z")
    client = DummyClient(
        [type("Item", (), {"id": "b1", "updated_at": "2026-04-20T10:00:00Z"})()]
    )

    run_once(helper=helper, client=client, state=state)

    helper.api.work.to_processed.assert_called_once()
    _, kwargs = helper.api.work.to_processed.call_args
    assert kwargs.get("in_error") is False


def test_build_runtime_reads_env_when_config_file_is_absent(monkeypatch):
    helper_calls = []
    client_calls = []

    class DummyHelperWithState:
        def __init__(self, config):
            helper_calls.append(config)

        def get_state(self):
            return None

    class DummyClientForBuild:
        def __init__(self, base_url, api_key):
            client_calls.append((base_url, api_key))

    monkeypatch.setattr(runtime.os.path, "isfile", lambda path: False)
    monkeypatch.setattr(
        runtime.os,
        "environ",
        {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "CONNECTOR_ID": "connector-id",
            "CONNECTOR_NAME": "TruKno",
            "CONNECTOR_SCOPE": "report",
            "TRUKNO_API_BASE_URL": "https://api.trukno.test/v2",
            "TRUKNO_API_KEY": "secret",
            "TRUKNO_INTERVAL_MINUTES": "15",
            "TRUKNO_INITIAL_LOOKBACK_DAYS": "7",
        },
    )
    monkeypatch.setattr(runtime, "OpenCTIConnectorHelper", DummyHelperWithState)
    monkeypatch.setattr(runtime, "TruKnoClient", DummyClientForBuild)
    monkeypatch.setattr(runtime, "_utc_now_iso", lambda: "2026-05-01T09:30:00Z")
    monkeypatch.setattr(
        runtime.ConnectorState,
        "empty",
        classmethod(
            lambda cls, initial_lookback_days, now_iso: ConnectorState(
                last_seen_updated_at="2026-04-24T12:00:00Z"
            )
        ),
    )

    _, _, state, config = runtime.build_runtime()

    assert state.last_seen_updated_at == "2026-04-24T12:00:00Z"
    assert config.trukno_api_key == "secret"
    assert client_calls == [("https://api.trukno.test/v2", "secret")]
    assert helper_calls[0]["trukno"]["api_base_url"] == "https://api.trukno.test/v2"


def test_build_runtime_checks_explicit_config_path_first(monkeypatch):
    raw_config = {
        "opencti": {"url": "http://opencti:8080", "token": "token"},
        "connector": {
            "id": "connector-id",
            "name": "TruKno",
            "scope": "report",
        },
        "trukno": {
            "api_base_url": "https://api.trukno.test/v2",
            "api_key": "secret",
            "interval_minutes": 15,
            "initial_lookback_days": 7,
        },
    }
    opened_paths = []

    class DummyHelperWithState:
        def __init__(self, config):
            self.raw = config

        def get_state(self):
            return None

    monkeypatch.setattr(
        runtime.os,
        "environ",
        {"TRUKNO_CONNECTOR_CONFIG": "C:/runtime/trukno.yml"},
    )
    monkeypatch.setattr(runtime.os, "getcwd", lambda: "C:/workspace")
    monkeypatch.setattr(
        runtime.os.path,
        "isfile",
        lambda path: path == "C:/runtime/trukno.yml",
    )
    monkeypatch.setattr(
        builtins,
        "open",
        lambda path, *args, **kwargs: opened_paths.append(path) or StringIO("ignored"),
    )
    monkeypatch.setattr(runtime.yaml, "safe_load", lambda stream: raw_config)
    monkeypatch.setattr(runtime, "OpenCTIConnectorHelper", DummyHelperWithState)
    monkeypatch.setattr(runtime, "TruKnoClient", lambda *args: object())
    monkeypatch.setattr(runtime, "_utc_now_iso", lambda: "2026-05-01T09:30:00Z")
    monkeypatch.setattr(
        runtime.ConnectorState,
        "empty",
        classmethod(
            lambda cls, initial_lookback_days, now_iso: ConnectorState(
                last_seen_updated_at="2026-04-24T12:00:00Z"
            )
        ),
    )

    runtime.build_runtime()

    assert opened_paths == ["C:/runtime/trukno.yml"]
