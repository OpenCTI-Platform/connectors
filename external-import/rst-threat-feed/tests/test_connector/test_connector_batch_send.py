from unittest.mock import MagicMock

import pytest

from connector.connector import RSTThreatFeed
from connector.settings import ConnectorSettings


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler):
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RST Threat Feed",
                    "scope": "application/json",
                    "log_level": "error",
                    "duration_period": "PT24H",
                },
                "rst_threat_feed": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                    "opencti_batch_size": 5,
                    "domain": True,
                    "ip": False,
                    "url": False,
                    "hash": False,
                },
            }
        )


@pytest.fixture
def connector():
    settings = StubConnectorSettings()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connect_id = "connector-id"
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.return_value = '{"type":"bundle","objects":[]}'
    helper.send_stix2_bundle.return_value = ["bundle-sent"]
    return RSTThreatFeed(config=settings, helper=helper)


def test_batch_send_uses_helper_bundle_pattern(connector):
    stix_object = MagicMock()
    stix_object.type = "indicator"
    stix_object.id = "indicator--1"
    stix_object.serialize.return_value = '{"type":"indicator","id":"indicator--1"}'

    ok = connector._batch_send_one(
        [stix_object], timestamp=1_700_000_000, feed_type="domain"
    )

    assert ok is True
    connector.helper.stix2_create_bundle.assert_called_once()
    kwargs = connector.helper.send_stix2_bundle.call_args.kwargs
    assert kwargs["cleanup_inconsistent_bundle"] is True
    assert kwargs["work_id"] == "work-1"


def test_batch_send_marks_failed_work_on_retry(connector, monkeypatch):
    stix_object = MagicMock()
    stix_object.type = "indicator"
    stix_object.id = "indicator--1"
    connector._max_retries = 2
    connector.helper.send_stix2_bundle.side_effect = [
        ConnectionError("temporary"),
        ["bundle-sent"],
    ]
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    ok = connector._batch_send_one(
        [stix_object], timestamp=1_700_000_000, feed_type="domain"
    )

    assert ok is True
    assert connector.helper.send_stix2_bundle.call_count == 2
    first = connector.helper.api.work.to_processed.call_args_list[0]
    assert first.kwargs.get("in_error") is True


def test_order_stix_objects_author_marking_entities_relationships(connector):
    author = MagicMock(
        type="identity", id="identity--author", identity_class="organization"
    )
    sector = MagicMock(type="identity", id="identity--sector", identity_class="class")
    marking = MagicMock(type="marking-definition", id="marking--1")
    indicator = MagicMock(type="indicator", id="indicator--1")
    relationship = MagicMock(type="relationship", id="relationship--1")

    ordered = connector._order_stix_objects(
        [relationship, indicator, sector, marking, author]
    )
    assert [obj.id for obj in ordered] == [
        "identity--author",
        "marking--1",
        "identity--sector",
        "indicator--1",
        "relationship--1",
    ]


def test_batch_send_chunks_and_prefixes_foundation(connector):
    author = MagicMock(
        type="identity", id="identity--author", identity_class="organization"
    )
    marking = MagicMock(type="marking-definition", id="marking--1")
    objects = [author, marking] + [
        MagicMock(type="indicator", id=f"indicator--{i}") for i in range(8)
    ]

    sent_chunks = []

    def capture(chunk, timestamp, feed_type):
        sent_chunks.append(chunk)
        return True

    connector._batch_send_one = capture
    ok = connector._batch_send(objects, timestamp=1_700_000_000, feed_type="domain")

    assert ok is True
    assert len(sent_chunks) >= 2
    for chunk in sent_chunks:
        assert chunk[0].id == "identity--author"
        assert chunk[1].id == "marking--1"
        assert len(chunk) <= connector._opencti_batch_size
