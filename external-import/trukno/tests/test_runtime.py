from datetime import timedelta
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from trukno_connector import runtime
from trukno_connector.runtime import run_once
from trukno_connector.settings import ConnectorSettings
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


def test_build_runtime_uses_sdk_settings_and_unwraps_trukno_secret(monkeypatch):
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

    monkeypatch.setenv("OPENCTI_URL", "http://opencti:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "token")
    monkeypatch.setenv("CONNECTOR_ID", "connector-id")
    monkeypatch.setenv("CONNECTOR_NAME", "TruKno Runtime")
    monkeypatch.setenv("TRUKNO_API_BASE_URL", "https://api.trukno.test/v2")
    monkeypatch.setenv("TRUKNO_API_KEY", "secret")
    monkeypatch.setenv("TRUKNO_INITIAL_LOOKBACK_DAYS", "7")
    settings = ConnectorSettings()

    monkeypatch.setattr(runtime, "ConnectorSettings", lambda: settings, raising=False)
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
    assert config is settings
    assert helper_calls == [settings.to_helper_config()]
    assert client_calls == [
        (str(settings.trukno.api_base_url), settings.trukno.api_key.get_secret_value())
    ]


def test_main_schedules_process_using_configured_iso_duration(monkeypatch):
    helper = MagicMock()
    client = object()
    state = ConnectorState(last_seen_updated_at="2026-04-20T00:00:00Z")
    settings = SimpleNamespace(
        connector=SimpleNamespace(
            name="TruKno Runtime", duration_period=timedelta(seconds=90)
        )
    )
    run_once_mock = MagicMock(return_value=state)

    monkeypatch.setattr(
        runtime, "build_runtime", lambda: (helper, client, state, settings)
    )
    monkeypatch.setattr(runtime, "run_once", run_once_mock)
    monkeypatch.setattr(
        runtime,
        "time",
        SimpleNamespace(sleep=lambda seconds: pytest.fail("manual sleep polling")),
        raising=False,
    )

    runtime.main()

    helper.schedule_process.assert_called_once()
    _, kwargs = helper.schedule_process.call_args
    assert kwargs["duration_period"] == 90.0

    kwargs["message_callback"]()

    run_once_mock.assert_called_once_with(
        helper=helper,
        client=client,
        state=state,
        connector_name="TruKno Runtime",
    )
