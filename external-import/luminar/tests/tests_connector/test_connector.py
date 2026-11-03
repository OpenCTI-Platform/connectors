import itertools
import json

import pytest
from conftest import TS, RecordingLogger, stix_id
from luminar_connector import connector as connector_module
from luminar_connector.connector import ConnectorLuminar, IngestionError
from luminar_connector.converter_to_stix import ConversionStats, ConverterToStix
from luminar_connector.luminar_manager import LuminarAPIError
from luminar_connector.relationship_schema import RelationshipSchema
from pycti import OpenCTIConnectorHelper

NO_SCHEMA = RelationshipSchema(None)


class FakeWork:
    def __init__(self):
        self.progress = []
        self.processed_calls = []

    def initiate_work(self, connector_id, name, is_multipart=False):
        assert is_multipart is True
        return "work-1"

    def get_work(self, work_id):
        if self.progress:
            item = self.progress.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return {"tracking": {"import_expected_number": 1, "import_processed_number": 1}}

    def to_processed(self, work_id, message, in_error=False):
        self.processed_calls.append((work_id, message, in_error))


class FakeApi:
    def __init__(self):
        self.work = FakeWork()

    def query(self, _query):
        return {
            "data": {
                "schemaRelationsTypesMapping": [
                    {"key": "Indicator_Malware", "values": ["indicates"]}
                ]
            }
        }


class FakeHelper:
    connect_name = "Luminar"
    connect_id = "connector-id"

    def __init__(self, state=None):
        self.state = state
        self.sent = []
        self.pings = 0
        self.ping_error = None
        self.send_error = None
        self.api = FakeApi()
        self.scheduled = None

    def get_state(self):
        return json.loads(json.dumps(self.state)) if self.state is not None else None

    def set_state(self, state):
        self.state = state

    def force_ping(self):
        if self.ping_error:
            raise self.ping_error
        self.pings += 1

    stix2_create_bundle = staticmethod(OpenCTIConnectorHelper.stix2_create_bundle)

    def send_stix2_bundle(self, bundle, **kwargs):
        if self.send_error:
            raise self.send_error
        objects = json.loads(bundle)["objects"]
        self.sent.append((objects, kwargs))
        return objects

    def schedule_iso(self, message_callback, duration_period):
        self.scheduled = (message_callback, duration_period)


class FakeClient:
    def __init__(self, results_by_feed=None, error=None):
        self.results_by_feed = results_by_feed or {}
        self.error = error
        self.calls = []
        self.taxi_collection = {
            "iocs": "1",
            "leakedrecords": "2",
            "cyberfeeds": "3",
            "vulnerabilities": "4",
        }

    def get_objects(self, alias, added_after=None):
        self.calls.append((alias, added_after))
        if self.error:
            raise self.error
        yield from self.results_by_feed.get(alias, [])


def result(data, last_success, error=None, hydration_complete=True):
    return {
        "results": {
            "data": data,
            "last_success": last_success,
            "hydration_complete": hydration_complete,
        },
        "error": error,
    }


def malware(number=1):
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": stix_id("malware", number),
        "created": TS,
        "modified": TS,
        "name": f"m{number}",
        "is_family": True,
    }


@pytest.fixture
def make_connector():
    def _make(state=None, client=None):
        connector = ConnectorLuminar.__new__(ConnectorLuminar)
        connector.helper = FakeHelper(state)
        connector.logger = RecordingLogger()
        connector.duration_period = "PT1H"
        connector.initial_fetch_date = "2026-01-01T00:00:00.000000Z"
        connector.converter = ConverterToStix(connector.logger, create_observable=True)
        connector.client = client or FakeClient()
        return connector

    return _make


# ----- configuration and checkpoints -------------------------------------- #


def test_timestamp_helpers():
    assert (
        ConnectorLuminar._initial_fetch_timestamp(" 2026-03-04 ")
        == "2026-03-04T00:00:00.000000Z"
    )
    with pytest.raises(ValueError):
        ConnectorLuminar._initial_fetch_timestamp(None)
    assert (
        ConnectorLuminar._normalize_checkpoint("2026-01-01T00:00:01Z")
        == "2026-01-01T00:00:01.000000Z"
    )
    assert ConnectorLuminar._normalize_checkpoint("bad") is None
    assert (
        ConnectorLuminar._resume_timestamp("2026-01-01T00:00:01.000000Z")
        == "2026-01-01T00:00:00.000000Z"
    )


def test_load_checkpoints_empty_state(make_connector):
    assert make_connector()._load_checkpoints() == {}


def test_load_checkpoints_migrates_legacy_state(make_connector):
    connector = make_connector(
        state={
            "last_run": "2026-05-05T00:00:00.000000Z",
            "feeds": {"iocs": "2026-06-06T00:00:00Z", "cyberfeeds": "garbage"},
        }
    )

    checkpoints = connector._load_checkpoints()

    assert checkpoints == {
        "iocs": "2026-06-06T00:00:00.000000Z",
        "leakedrecords": "2026-05-05T00:00:00.000000Z",
        "cyberfeeds": "2026-05-05T00:00:00.000000Z",
    }
    assert "last_run" not in connector.helper.state
    assert (
        connector.helper.state["feeds"]["leakedrecords"]
        == "2026-05-05T00:00:00.000000Z"
    )
    assert (
        "[CONNECTOR] Ignoring unparseable stored checkpoint"
        in connector.logger.messages("warning")
    )


def test_save_checkpoint_is_monotonic_and_persisted(make_connector):
    connector = make_connector(state={"feeds": {"iocs": "2026-01-01T00:00:05.000000Z"}})

    connector._save_checkpoint("iocs", "not-a-date")
    connector._save_checkpoint("iocs", "2026-01-01T00:00:04.000000Z")
    assert connector.helper.state["feeds"]["iocs"] == "2026-01-01T00:00:05.000000Z"
    assert connector.helper.pings == 0

    connector._save_checkpoint("iocs", "2026-01-01T00:00:06Z")
    assert connector.helper.state["feeds"]["iocs"] == "2026-01-01T00:00:06.000000Z"
    assert connector.helper.pings == 1

    connector.helper.ping_error = RuntimeError("platform down")
    connector._save_checkpoint("cyberfeeds", "2026-01-01T00:00:07Z")
    assert (
        connector.helper.state["feeds"]["cyberfeeds"] == "2026-01-01T00:00:07.000000Z"
    )
    assert any("persist checkpoint" in m for m in connector.logger.messages("warning"))


# ----- load: phases and ingestion wait ------------------------------------- #


def test_send_batch_sends_phases_in_order(make_connector):
    connector = make_connector()
    objects = [
        {"type": "identity", "id": stix_id("identity", 1)},
        {"type": "relationship", "id": stix_id("relationship", 1)},
        {"type": "report", "id": stix_id("report", 1)},
        {"type": "observed-data", "id": stix_id("observed-data", 1)},
        {"type": "sighting", "id": stix_id("sighting", 1)},
    ]
    connector.helper.api.work.progress = [
        {"tracking": {"import_expected_number": 2, "import_processed_number": 2}},
        {"tracking": {"import_expected_number": 4, "import_processed_number": 4}},
    ]

    sent = connector._send_batch(objects, "work-1")

    assert sent == 5
    phases = [
        (sorted(o["type"] for o in objs), kwargs["cleanup_inconsistent_bundle"])
        for objs, kwargs in connector.helper.sent
    ]
    assert phases == [
        (["identity", "observed-data"], True),
        (["relationship", "sighting"], False),
        (["report"], False),
    ]
    assert all(
        kwargs["work_id"] == "work-1" and kwargs["update"] is True
        for _, kwargs in connector.helper.sent
    )
    assert connector.helper.api.work.progress == []  # waited after phases 1 and 2


def test_send_bundle_failure_raises_ingestion_error(make_connector):
    connector = make_connector()
    connector.helper.send_error = ConnectionError("rabbitmq unreachable")
    with pytest.raises(IngestionError, match="rabbitmq unreachable"):
        connector._send_batch(
            [{"type": "identity", "id": stix_id("identity", 1)}], "work-1"
        )


def test_wait_for_ingestion_paths(make_connector, monkeypatch):
    connector = make_connector()
    work = connector.helper.api.work

    connector._wait_for_ingestion(None, "entities")  # no work: nothing to wait for

    work.progress = [
        RuntimeError("api down"),
        {"tracking": {"import_expected_number": 3, "import_processed_number": None}},
        {"tracking": {"import_expected_number": 3, "import_processed_number": 3}},
    ]
    connector._wait_for_ingestion("work-1", "entities")
    assert work.progress == []
    assert "[CONNECTOR] Could not read work progress" in connector.logger.messages(
        "warning"
    )

    work.progress = [{}]
    connector._wait_for_ingestion("work-1", "entities")
    assert (
        "[CONNECTOR] Work not found; not waiting for ingestion"
        in connector.logger.messages("warning")
    )


def test_wait_for_ingestion_gives_up_when_stalled(make_connector, monkeypatch):
    connector = make_connector()
    clock = itertools.count(start=0, step=400)
    monkeypatch.setattr(connector_module.time, "monotonic", lambda: next(clock))
    connector.helper.api.work.progress = [
        {"tracking": {"import_expected_number": 5, "import_processed_number": n}}
        for n in (1, 2, 2, 2, 2)
    ]

    connector._wait_for_ingestion("work-1", "entities")

    assert (
        "[CONNECTOR] Waiting for OpenCTI to ingest phase"
        in connector.logger.messages("info")
    )
    assert (
        "[CONNECTOR] Ingestion made no progress; sending next phase"
        in connector.logger.messages("warning")
    )


# ----- per-feed pipeline ---------------------------------------------------- #


def test_process_feed_success(make_connector):
    client = FakeClient(
        {
            "iocs": [
                result([malware(1)], "2026-01-01T00:00:01Z"),
                result([], "2026-01-01T00:00:02Z"),
            ]
        }
    )
    connector = make_connector(state={"feeds": {}}, client=client)
    stats = ConversionStats()

    error = connector._process_feed(
        "iocs", "2026-01-01T00:00:00.000000Z", NO_SCHEMA, "work-1", stats
    )

    assert error is None
    assert client.calls == [("iocs", "2025-12-31T23:59:59.000000Z")]
    assert stats.output == 1 and len(connector.helper.sent) == 1
    assert connector.helper.state["feeds"]["iocs"] == "2026-01-01T00:00:02.000000Z"
    assert "[CONNECTOR] Feed completed" in connector.logger.messages("info")


def test_process_feed_without_checkpoint_and_with_nothing_to_send(make_connector):
    broken = {"type": "malware", "id": "not-a-stix-id"}
    client = FakeClient({"iocs": [result([broken], None)]})
    connector = make_connector(client=client)

    assert (
        connector._process_feed("iocs", None, NO_SCHEMA, "work-1", ConversionStats())
        is None
    )
    assert client.calls == [("iocs", None)] and connector.helper.sent == []


def test_process_feed_keeps_checkpoint_when_hydration_failed(make_connector):
    client = FakeClient(
        {
            "iocs": [
                result([malware()], "2026-01-01T00:00:01Z", hydration_complete=False)
            ]
        }
    )
    connector = make_connector(state={"feeds": {}}, client=client)

    error = connector._process_feed(
        "iocs", None, NO_SCHEMA, "work-1", ConversionStats()
    )

    assert error == "referenced-object lookup (match[id]) failed"
    assert connector.helper.state == {"feeds": {}}
    assert len(connector.helper.sent) == 1  # what was converted is still ingested


def test_process_feed_stops_on_extraction_error(make_connector):
    client = FakeClient(
        {"iocs": [result([malware()], "2026-01-01T00:00:01Z", error="HTTP 503: down")]}
    )
    connector = make_connector(state={"feeds": {}}, client=client)

    assert (
        connector._process_feed("iocs", None, NO_SCHEMA, "work-1", ConversionStats())
        == "HTTP 503: down"
    )
    assert connector.helper.state["feeds"]["iocs"] == "2026-01-01T00:00:01.000000Z"

    failing = make_connector(
        client=FakeClient(error=LuminarAPIError("HTTP 401: denied"))
    )
    assert (
        failing._process_feed("iocs", None, NO_SCHEMA, "work-1", ConversionStats())
        == "HTTP 401: denied"
    )


def test_process_feed_stops_on_transformation_failure(make_connector, monkeypatch):
    client = FakeClient({"iocs": [result([malware()], "2026-01-01T00:00:01Z")]})
    connector = make_connector(state={"feeds": {}}, client=client)

    def boom(*_args, **_kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(connector.converter, "convert_batch", boom)

    assert (
        connector._process_feed("iocs", None, NO_SCHEMA, "work-1", ConversionStats())
        == "transformation failed: bug"
    )
    assert connector.helper.state == {"feeds": {}}


# ----- full run ------------------------------------------------------------- #


def test_process_message_success_with_feed_error(make_connector):
    client = FakeClient(
        {
            "iocs": [result([malware(1)], "2026-01-01T00:00:01Z")],
            "leakedrecords": [result([], None, error="HTTP 500: boom")],
        }
    )
    connector = make_connector(
        state={"feeds": {"cyberfeeds": "2026-01-01T00:00:00Z"}}, client=client
    )

    connector.process_message()

    assert [alias for alias, _ in client.calls] == [
        "iocs",
        "leakedrecords",
        "cyberfeeds",
    ]
    ((work_id, message, in_error),) = connector.helper.api.work.processed_calls
    assert work_id == "work-1" and in_error is True
    assert (
        "1 objects ingested" in message and "leakedrecords: HTTP 500: boom" in message
    )
    assert "last_run_end" in connector.helper.state
    assert (
        "[CONNECTOR] Luminar collections not processed by this connector"
        in connector.logger.messages("info")
    )


def test_process_message_marks_work_failed_when_ingestion_fails(make_connector):
    client = FakeClient({"iocs": [result([malware(1)], "2026-01-01T00:00:01Z")]})
    connector = make_connector(client=client)
    connector.helper.send_error = RuntimeError("queue down")

    connector.process_message()

    ((_, message, in_error),) = connector.helper.api.work.processed_calls
    assert in_error is True and message.startswith("Run failed")
    assert "[CONNECTOR] Run failed" in connector.logger.messages("error")


def test_process_message_stops_on_interrupt(make_connector, monkeypatch):
    connector = make_connector()

    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr(connector, "_load_checkpoints", interrupt)
    with pytest.raises(SystemExit):
        connector.process_message()


def test_run_schedules_process_message(make_connector):
    connector = make_connector()
    connector.run()
    callback, period = connector.helper.scheduled
    assert callback == connector.process_message and period == "PT1H"
