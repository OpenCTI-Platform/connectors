from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from splunk_connector.connector import SplunkConnector
from splunk_connector.importers.base import BaseImporter


class FakeImporter(BaseImporter):
    state_key = "fake"
    name = "Fake"

    def __init__(self, should_run=True, collect_side_effect=None):
        self._should_run = should_run
        self.collect = MagicMock(
            side_effect=collect_side_effect,
            return_value=(["object-1"], {"records_count": 1}),
        )

    @property
    def interval(self):
        return timedelta(minutes=1)

    def should_run(self, state, now):
        return self._should_run


class FakeHelper:
    def __init__(self, state=None):
        self.connect_name = "Splunk Test"
        self.connect_id = "connector-id"
        self.connector_logger = SimpleNamespace(
            info=MagicMock(),
            warning=MagicMock(),
            error=MagicMock(),
        )
        self.api = SimpleNamespace(
            work=SimpleNamespace(
                initiate_work=MagicMock(return_value="work-id"),
                to_processed=MagicMock(),
            )
        )
        self._state = state
        self.get_state = MagicMock(return_value=state)
        self.set_state = MagicMock()
        self.stix2_create_bundle = MagicMock(side_effect=lambda objects: objects)
        self.send_stix2_bundle = MagicMock(return_value=["bundle-id"])
        self.schedule_process = MagicMock()


def _settings(**splunk_overrides):
    splunk = SimpleNamespace(
        token=SimpleNamespace(get_secret_value=lambda: "splunk-token"),
        base_url="https://splunk.example.com:8089",
        verify_ssl=True,
        timeout_seconds=60,
        owner="-",
        app="-",
        es_api_prefix="/servicesNS/nobody/missioncontrol/public/v2",
        tlp_level="amber",
        confidence=60,
        scopes=["indicator", "identity", "incident"],
        import_indicators=True,
        import_identities=True,
        import_incidents=True,
        batch_size=2,
    )
    for key, value in splunk_overrides.items():
        setattr(splunk, key, value)
    return SimpleNamespace(
        splunk=splunk,
        connector=SimpleNamespace(duration_period=timedelta(minutes=5)),
    )


def _connector(config=None, helper=None):
    return SplunkConnector(config or _settings(), helper or FakeHelper())


def test_build_importers_respects_enabled_scopes():
    connector = _connector()

    assert [importer.state_key for importer in connector.importers] == [
        "indicators",
        "identities",
        "incidents",
    ]


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"import_indicators": False}, ["identities", "incidents"]),
        ({"import_identities": False}, ["indicators", "incidents"]),
        ({"import_incidents": False}, ["indicators", "identities"]),
        ({"scopes": ["indicator"]}, ["indicators"]),
    ],
)
def test_build_importers_respects_disabled_flags_and_scopes(overrides, expected):
    connector = _connector(_settings(**overrides))

    assert [importer.state_key for importer in connector.importers] == expected


def test_process_message_no_importers_logs_warning():
    helper = FakeHelper()
    connector = _connector(helper=helper)
    connector.importers = []

    connector.process_message()

    helper.connector_logger.warning.assert_called_once_with("[SPLUNK] No enabled importers")
    helper.api.work.initiate_work.assert_not_called()


def test_process_message_skips_importer_when_interval_not_elapsed():
    helper = FakeHelper(state={"fake": {"last_success": datetime.now(UTC).isoformat()}})
    connector = _connector(helper=helper)
    importer = FakeImporter(should_run=False)
    connector.importers = [importer]

    connector.process_message()

    importer.collect.assert_not_called()
    helper.api.work.initiate_work.assert_not_called()
    helper.set_state.assert_called_once()


def test_process_message_success_updates_dataset_and_top_level_state():
    helper = FakeHelper(state={})
    connector = _connector(helper=helper)
    importer = FakeImporter()
    connector.importers = [importer]
    connector.converter.common_objects = MagicMock(return_value=["author", "tlp"])

    connector.process_message()

    helper.api.work.initiate_work.assert_called_once()
    helper.api.work.to_processed.assert_called_once()
    assert helper.set_state.call_count == 2
    dataset_state = helper.set_state.call_args_list[0].args[0]["fake"]
    final_state = helper.set_state.call_args_list[-1].args[0]
    assert dataset_state["objects_sent"] == 1
    assert "last_run" in final_state


def test_process_message_failure_does_not_mark_work_processed():
    helper = FakeHelper(state={})
    connector = _connector(helper=helper)
    importer = FakeImporter(collect_side_effect=RuntimeError("boom"))
    connector.importers = [importer]

    with pytest.raises(RuntimeError):
        connector.process_message()

    helper.api.work.initiate_work.assert_called_once()
    helper.api.work.to_processed.assert_not_called()
    final_state = helper.set_state.call_args.args[0]
    assert "last_run" in final_state


def test_process_message_continues_after_importer_failure():
    helper = FakeHelper(state={})
    connector = _connector(helper=helper)
    failing_importer = FakeImporter(collect_side_effect=RuntimeError("boom"))
    failing_importer.state_key = "failing"
    failing_importer.name = "Failing"
    successful_importer = FakeImporter()
    successful_importer.state_key = "successful"
    successful_importer.name = "Successful"
    connector.importers = [failing_importer, successful_importer]
    connector.converter.common_objects = MagicMock(return_value=["author", "tlp"])

    with pytest.raises(RuntimeError, match="failing"):
        connector.process_message()

    failing_importer.collect.assert_called_once()
    successful_importer.collect.assert_called_once()
    assert helper.api.work.initiate_work.call_count == 2
    helper.api.work.to_processed.assert_called_once()
    assert helper.set_state.call_args_list[0].args[0]["successful"]["objects_sent"] == 1


def test_send_objects_returns_zero_for_empty_list():
    helper = FakeHelper()
    connector = _connector(helper=helper)

    assert connector._send_objects("Dataset", "work-id", []) == 0
    helper.send_stix2_bundle.assert_not_called()


def test_send_objects_batches_and_includes_common_objects():
    helper = FakeHelper()
    connector = _connector(helper=helper)
    connector.converter.common_objects = MagicMock(return_value=["author", "tlp"])

    sent = connector._send_objects("Dataset", "work-id", ["one", "two", "three"])

    assert sent == 3
    assert helper.stix2_create_bundle.call_args_list[0].args[0] == [
        "one",
        "two",
        "author",
        "tlp",
    ]
    assert helper.stix2_create_bundle.call_args_list[1].args[0] == [
        "three",
        "author",
        "tlp",
    ]
    helper.send_stix2_bundle.assert_any_call(
        ["one", "two", "author", "tlp"],
        work_id="work-id",
        cleanup_inconsistent_bundle=True,
    )
    assert helper.send_stix2_bundle.call_count == 2


def test_load_state_returns_empty_dict_when_helper_state_missing():
    connector = _connector(helper=FakeHelper(state=None))

    assert connector._load_state() == {}


def test_run_schedules_process_with_duration_seconds():
    helper = FakeHelper()
    connector = _connector(helper=helper)

    connector.run()

    helper.schedule_process.assert_called_once_with(
        message_callback=connector.process_message,
        duration_period=300.0,
    )
