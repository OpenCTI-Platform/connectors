import copy
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import connector.connector as connector_module
import pytest
from conftest import make_sample_bundle, make_settings
from connector import PolySwarmFeedConnector
from connectors_sdk import ApiServerError
from polyswarm_client import TaxiiAuthenticationError, TaxiiPage
from pycti import OpenCTIConnectorHelper


class FakeTaxiiClient:
    """Scripted TAXII client: one queue of pages (or exceptions) per collection."""

    def __init__(self, pages: dict[str, list]) -> None:
        self.pages = pages
        self.calls: list[dict] = []

    def get_collection_id(self, collection: str) -> str:
        return f"{collection}-id"

    def get_objects(self, collection, collection_id, **kwargs):
        self.calls.append({"collection": collection, **kwargs})
        queue = self.pages.get(collection, [])
        result = queue.pop(0) if queue else TaxiiPage()
        if isinstance(result, Exception):
            raise result
        return result


def page(*samples, more=False, next_token=None, last=None) -> TaxiiPage:
    return TaxiiPage(
        objects=list(samples),
        more=more,
        next=next_token if more else None,
        date_added_last=last,
    )


class FakeHelper:
    """Minimal OpenCTIConnectorHelper stand-in with an in-memory state."""

    def __init__(self, logger, stored_state=None) -> None:
        self.connector_logger = logger
        self.connect_name = "PolySwarm Feed"
        self.connect_id = "connector-id"
        self.stored_state = stored_state
        self.bundles: list[dict] = []
        self.api = MagicMock()
        self._work_count = 0
        self.api.work.initiate_work.side_effect = self._initiate_work
        self.stix2_create_bundle = OpenCTIConnectorHelper.stix2_create_bundle

    def _initiate_work(self, connector_id, name):
        self._work_count += 1
        return f"work-{self._work_count}"

    def get_state(self):
        return copy.deepcopy(self.stored_state)

    def set_state(self, state):
        self.stored_state = copy.deepcopy(state)

    def force_ping(self):
        pass

    def send_stix2_bundle(self, bundle, **kwargs):
        self.bundles.append({"bundle": json.loads(bundle), **kwargs})
        return [bundle]

    def processed(self):
        return [
            call.args + (call.kwargs,) for call in self.api.work.to_processed.mock_calls
        ]


class RecordingHuntingSource:
    """Replaces HuntingSource; class attributes script its behaviour."""

    instances: list = []
    result = ([], {})
    error: Exception | None = None

    def __init__(self, config, author, tlp_marking, logger, client=None):
        self.config = config
        self.author = author
        self.tlp_marking = tlp_marking
        self.client = client
        self.received_state = None
        self.received_max_objects = None
        RecordingHuntingSource.instances.append(self)

    def collect_batches(self, state, max_objects=None):
        self.received_state = state
        self.received_max_objects = max_objects
        if RecordingHuntingSource.error:
            raise RecordingHuntingSource.error
        objects, new_state = RecordingHuntingSource.result
        if objects and not isinstance(objects[0], list):
            objects = [objects]
        return objects, new_state


@pytest.fixture(autouse=True)
def hunting_source(monkeypatch):
    RecordingHuntingSource.instances = []
    RecordingHuntingSource.result = ([], {})
    RecordingHuntingSource.error = None
    monkeypatch.setattr(connector_module, "HuntingSource", RecordingHuntingSource)
    return RecordingHuntingSource


def build(fake_logger, pages, stored_state=None, **overrides):
    settings = make_settings(**overrides)
    helper = FakeHelper(fake_logger, stored_state)
    client = FakeTaxiiClient(pages)
    return PolySwarmFeedConnector(settings, helper, taxii_client=client), helper, client


def test_first_run_backfills_and_sends_one_bundle_per_page(fake_logger):
    pages = {
        "trustgroup": [
            page(make_sample_bundle(1), more=True, next_token="n1", last="T1"),
            page(make_sample_bundle(2), last="T2"),
        ]
    }
    connector, helper, client = build(fake_logger, pages)
    before = datetime.now(tz=timezone.utc)

    connector.process_message()

    first_call = client.calls[0]
    added_after = datetime.fromisoformat(
        first_call["added_after"].replace("Z", "+00:00")
    )
    assert abs(added_after - (before - timedelta(days=14))) < timedelta(minutes=1)
    assert first_call.get("next_token") is None
    assert client.calls[1]["next_token"] == "n1"

    assert len(helper.bundles) == 2
    for sent in helper.bundles:
        assert sent["work_id"] == "work-1"
        objects = sent["bundle"]["objects"]
        assert objects[0]["id"] == connector.author["id"]
        assert objects[1]["id"] == connector.tlp_marking["id"]
    assert helper.api.work.initiate_work.call_count == 1
    assert helper.processed()[0][0] == "work-1"

    stored = helper.stored_state
    assert stored["collections"]["trustgroup"] == {
        "added_after": "T2",
        "next_token": None,
    }
    assert stored["last_run"] is not None


def test_next_run_resumes_from_stored_added_after(fake_logger):
    stored = {"collections": {"trustgroup": {"added_after": "T9", "next_token": None}}}
    connector, helper, client = build(fake_logger, {}, stored_state=stored)

    connector.process_message()

    assert client.calls == [
        {"collection": "trustgroup", "added_after": "T9", "limit": 100}
    ]
    assert helper.bundles == []
    assert helper.api.work.initiate_work.call_count == 0
    assert helper.stored_state["collections"]["trustgroup"]["added_after"] == "T9"


def test_page_without_date_added_header_keeps_cursor(fake_logger):
    stored = {"collections": {"trustgroup": {"added_after": "T9"}}}
    pages = {"trustgroup": [page(make_sample_bundle(1), last=None)]}
    connector, helper, _ = build(fake_logger, pages, stored_state=stored)

    connector.process_message()

    assert len(helper.bundles) == 1
    assert helper.stored_state["collections"]["trustgroup"]["added_after"] == "T9"


def test_max_objects_per_run_stops_paging_and_keeps_next_token(fake_logger):
    pages = {
        "trustgroup": [
            page(make_sample_bundle(1), more=True, next_token="n1", last="T1"),
            page(make_sample_bundle(2), last="T2"),
        ]
    }
    connector, helper, client = build(fake_logger, pages, max_objects_per_run=5)

    connector.process_message()

    assert len(client.calls) == 1
    assert len(helper.bundles) == 1
    assert helper.stored_state["collections"]["trustgroup"] == {
        "added_after": "T1",
        "next_token": "n1",
    }

    # The next run continues from the stored `next` token.
    connector.process_message()
    assert client.calls[1]["next_token"] == "n1"
    assert "added_after" not in client.calls[1]
    assert helper.stored_state["collections"]["trustgroup"] == {
        "added_after": "T2",
        "next_token": None,
    }


def test_max_objects_is_shared_across_collections(fake_logger):
    pages = {
        "trustgroup": [page(make_sample_bundle(1), last="T1")],
        "ransomware": [page(make_sample_bundle(2), last="R1")],
    }
    connector, helper, client = build(
        fake_logger,
        pages,
        feed_collections="trustgroup,ransomware",
        max_objects_per_run=5,
    )

    connector.process_message()

    assert [call["collection"] for call in client.calls] == ["trustgroup"]
    assert "ransomware" not in helper.stored_state["collections"]


def _objects_in_one_sample_page(fake_logger) -> int:
    pages = {"trustgroup": [page(make_sample_bundle(1), last="T1")]}
    connector, helper, _ = build(fake_logger, pages)
    connector.process_message()
    # Each bundle also carries the author and the TLP marking.
    return len(helper.bundles[0]["bundle"]["objects"]) - 2


def test_objects_sent_before_a_collection_fails_count_toward_the_cap(fake_logger):
    one_page = _objects_in_one_sample_page(type(fake_logger)())
    pages = {
        "trustgroup": [
            page(make_sample_bundle(1), more=True, next_token="n1", last="T1"),
            ApiServerError("boom", status_code=500),
            ApiServerError("boom again", status_code=500),
        ],
        "ransomware": [
            page(make_sample_bundle(2), more=True, next_token="r1", last="R1"),
            page(make_sample_bundle(3), last="R2"),
        ],
    }
    connector, helper, client = build(
        fake_logger,
        pages,
        feed_collections="trustgroup,ransomware",
        max_objects_per_run=one_page + 1,
    )

    connector.process_message()

    # The failed collection's sent page counts, so only one object of budget
    # is left: the next collection sends one page and stops.
    ransomware_calls = [c for c in client.calls if c["collection"] == "ransomware"]
    assert len(ransomware_calls) == 1
    assert helper.stored_state["collections"]["ransomware"]["next_token"] == "r1"
    (completed,) = [
        meta
        for _, message, meta in fake_logger.records
        if message == "Connector run completed"
    ]
    assert completed["objects_sent"] == 2 * one_page


def test_each_collection_has_its_own_work_and_cursor(fake_logger):
    pages = {
        "trustgroup": [page(make_sample_bundle(1), last="T1")],
        "freemium": [page(make_sample_bundle(2, with_attack_pattern=True), last="F1")],
    }
    connector, helper, _ = build(
        fake_logger, pages, feed_collections="trustgroup,freemium"
    )

    connector.process_message()

    assert [sent["work_id"] for sent in helper.bundles] == ["work-1", "work-2"]
    assert helper.stored_state["collections"]["trustgroup"]["added_after"] == "T1"
    assert helper.stored_state["collections"]["freemium"]["added_after"] == "F1"


def test_rejected_next_token_falls_back_to_added_after(fake_logger):
    stored = {"collections": {"trustgroup": {"added_after": "T1", "next_token": "old"}}}
    pages = {
        "trustgroup": [
            ApiServerError("Server error (500)", status_code=500),
            page(make_sample_bundle(1), last="T2"),
        ]
    }
    connector, helper, client = build(fake_logger, pages, stored_state=stored)

    connector.process_message()

    assert client.calls[0]["next_token"] == "old"
    assert client.calls[1]["added_after"] == "T1"
    assert len(helper.bundles) == 1
    assert helper.stored_state["collections"]["trustgroup"] == {
        "added_after": "T2",
        "next_token": None,
    }
    assert fake_logger.messages("warning")


def test_auth_error_on_next_token_is_not_swallowed(fake_logger):
    stored = {"collections": {"trustgroup": {"added_after": "T1", "next_token": "t"}}}
    pages = {"trustgroup": [TaxiiAuthenticationError("401")]}
    connector, helper, client = build(fake_logger, pages, stored_state=stored)

    connector.process_message()

    assert len(client.calls) == 1
    assert helper.stored_state["collections"]["trustgroup"]["next_token"] == "t"
    assert any("feed import failed" in m for m in fake_logger.messages("error"))


def test_failure_mid_collection_keeps_progress_and_other_collections_run(
    fake_logger,
):
    pages = {
        "trustgroup": [
            page(make_sample_bundle(1), more=True, next_token="n1", last="T1"),
            ApiServerError("boom", status_code=500),
            ApiServerError("boom again", status_code=500),
        ],
        "ransomware": [page(make_sample_bundle(2), last="R1")],
    }
    connector, helper, _ = build(
        fake_logger, pages, feed_collections="trustgroup,ransomware"
    )

    connector.process_message()

    collections = helper.stored_state["collections"]
    assert collections["trustgroup"] == {"added_after": "T1", "next_token": "n1"}
    assert collections["ransomware"]["added_after"] == "R1"
    failed = helper.processed()[0]
    assert failed[0] == "work-1" and failed[-1] == {"in_error": True}
    assert helper.processed()[1][0] == "work-2"


def test_hunting_not_called_when_disabled(fake_logger, hunting_source):
    connector, helper, _ = build(fake_logger, {})
    connector.process_message()
    assert hunting_source.instances == []
    assert helper.stored_state.get("hunting") is None


def test_hunting_called_when_enabled_with_its_sub_state(fake_logger, hunting_source):
    hunt_object = {
        "type": "indicator",
        "id": "indicator--11111111-1111-4111-8111-111111111111",
    }
    hunting_source.result = ([hunt_object], {"since": "S2", "seen": ["h1"]})
    stored = {"hunting": {"since": "S1"}}
    connector, helper, _ = build(
        fake_logger, {}, stored_state=stored, hunting_enabled=True
    )

    connector.process_message()

    (source,) = hunting_source.instances
    assert source.received_state == {"since": "S1"}
    assert source.author == connector.author
    assert source.tlp_marking == connector.tlp_marking
    assert source.config is connector.config.polyswarm
    assert helper.stored_state["hunting"] == {"since": "S2", "seen": ["h1"]}
    (sent,) = helper.bundles
    assert sent["bundle"]["objects"][-1] == hunt_object


def test_first_hunting_run_gets_empty_state(fake_logger, hunting_source):
    connector, _, _ = build(fake_logger, {}, hunting_enabled=True)
    connector.process_message()
    assert hunting_source.instances[0].received_state == {}


def test_hunting_failure_keeps_feed_progress_and_hunting_state(
    fake_logger, hunting_source
):
    hunting_source.error = RuntimeError("hunting down")
    stored = {"hunting": {"since": "S1"}}
    pages = {"trustgroup": [page(make_sample_bundle(1), last="T1")]}
    connector, helper, _ = build(
        fake_logger, pages, stored_state=stored, hunting_enabled=True
    )

    connector.process_message()

    assert helper.stored_state["collections"]["trustgroup"]["added_after"] == "T1"
    assert helper.stored_state["hunting"] == {"since": "S1"}
    assert any("hunting" in m for m in fake_logger.messages("error"))


def test_hunting_send_failure_keeps_hunting_state(fake_logger, hunting_source):
    hunting_source.result = (
        [{"type": "indicator", "id": "indicator--1"}],
        {"since": "S2"},
    )
    stored = {"hunting": {"since": "S1"}}
    connector, helper, _ = build(
        fake_logger, {}, stored_state=stored, hunting_enabled=True
    )
    helper.send_stix2_bundle = MagicMock(side_effect=RuntimeError("queue down"))

    connector.process_message()

    assert helper.stored_state["hunting"] == {"since": "S1"}
    assert helper.processed()[0][-1] == {"in_error": True}


def test_feed_failure_does_not_block_hunting(fake_logger, hunting_source):
    hunting_source.result = ([], {"since": "S2"})
    pages = {"trustgroup": [TaxiiAuthenticationError("401")]}
    connector, helper, _ = build(fake_logger, pages, hunting_enabled=True)

    connector.process_message()

    assert helper.stored_state["hunting"] == {"since": "S2"}


def test_hunting_gets_the_budget_left_after_the_feed(fake_logger, hunting_source):
    one_page = _objects_in_one_sample_page(type(fake_logger)())
    pages = {"trustgroup": [page(make_sample_bundle(1), last="T1")]}
    connector, _, _ = build(
        fake_logger, pages, hunting_enabled=True, max_objects_per_run=one_page + 50
    )

    connector.process_message()

    assert hunting_source.instances[0].received_max_objects == 50


def test_hunting_waits_when_the_feed_used_the_whole_budget(
    fake_logger, hunting_source
):
    hunting_source.result = (
        [{"type": "indicator", "id": "indicator--1"}],
        {"since": "S2"},
    )
    stored = {"hunting": {"since": "S1"}}
    pages = {"trustgroup": [page(make_sample_bundle(1), last="T1")]}
    connector, helper, _ = build(
        fake_logger,
        pages,
        stored_state=stored,
        hunting_enabled=True,
        max_objects_per_run=5,
    )

    connector.process_message()

    assert hunting_source.instances == []
    assert helper.stored_state["hunting"] == {"since": "S1"}
    assert any("live hunting" in m for m in fake_logger.messages("info"))


def test_hunting_batches_are_sent_as_separate_bundles_in_one_work(
    fake_logger, hunting_source
):
    first = [{"type": "indicator", "id": "indicator--1"}]
    second = [{"type": "indicator", "id": "indicator--2"}]
    hunting_source.result = ([first, second], {"since": "S2"})
    connector, helper, _ = build(fake_logger, {}, hunting_enabled=True)

    connector.process_message()

    assert [sent["bundle"]["objects"][-1]["id"] for sent in helper.bundles] == [
        "indicator--1",
        "indicator--2",
    ]
    assert {sent["work_id"] for sent in helper.bundles} == {"work-1"}
    assert helper.stored_state["hunting"] == {"since": "S2"}
    assert "2 objects" in helper.processed()[0][1]


def test_run_schedules_process_message(fake_logger):
    connector, helper, _ = build(fake_logger, {})
    helper.schedule_process = MagicMock()

    connector.run()

    helper.schedule_process.assert_called_once_with(
        message_callback=connector.process_message, duration_period=3600.0
    )
