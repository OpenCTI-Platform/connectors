from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connectors_sdk import SpamhausUnavailableError
from external_import_connector.connector import ConnectorState
from external_import_connector.converter_to_stix import ConverterToStix
from external_import_connector.spamhaus_urls import (
    URLS_PATH,
    SpamhausUrlsClient,
    item_to_row,
)

FIRST_SEEN = "2026-10-30T14:53:12Z"
FIRST_SEEN_TS = datetime(2026, 10, 30, 14, 53, 12, tzinfo=timezone.utc).timestamp()


def make_item(**overrides) -> dict:
    """Synthetic `Url` record, shaped after the Spamhaus abuse.ch API reference."""
    item = {
        "id": 4047624,
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/4047624/",
        "url": "http://42.234.72.133:38558/bin.sh",
        "url_status": "offline",
        "host": "42.234.72.133",
        "first_seen": FIRST_SEEN,
        "last_online": "2026-10-31T08:00:00Z",
        "threat": "malware_download",
        "blacklists": {"spamhaus_dbl": "not listed"},
        "reporter": "geenensp",
        "larted": True,
        "tags": ["elf", "Mozi"],
    }
    item.update(overrides)
    return item


def make_client(pages: list[list], import_offline: bool = True, checkpoint: float = 0):
    """Client over a fake SDK client whose `paginate` yields the given pages."""
    spamhaus = MagicMock()
    spamhaus.paginate.return_value = iter(pages)
    config = MagicMock()
    config.urlhaus.import_offline = import_offline
    config.urlhaus.spamhaus_import_from = datetime(2026, 10, 1, tzinfo=timezone.utc)
    state = ConnectorState()
    state.last_processed_entry_old = checkpoint
    state.last_processed_entry_new = checkpoint
    return SpamhausUrlsClient(spamhaus, MagicMock(), config, state), spamhaus, state


def collect(client: SpamhausUrlsClient) -> list[list]:
    return list(client.get_entities())


def test_should_map_item_to_csv_columns_when_item_is_complete():
    row = item_to_row(make_item())

    assert row == [
        "4047624",
        FIRST_SEEN,
        "http://42.234.72.133:38558/bin.sh",
        "offline",
        "2026-10-31T08:00:00Z",
        "malware_download",
        "elf,Mozi",
        "https://urlhaus.abuse.ch/url/4047624/",
        "geenensp",
    ]


def test_should_leave_last_online_empty_when_url_is_online():
    item = make_item(url_status="online")
    del item["last_online"]

    row = item_to_row(item)

    assert row[3] == "online"
    assert row[4] == ""


def test_should_leave_tags_empty_when_tags_are_missing():
    item = make_item()
    del item["tags"]

    assert item_to_row(item)[6] == ""


@pytest.mark.parametrize(
    "missing", ["id", "url", "url_status", "first_seen", "urlhaus_reference"]
)
def test_should_raise_value_error_when_required_field_is_missing(missing):
    item = make_item()
    del item[missing]

    with pytest.raises(ValueError, match=missing):
        item_to_row(item)


def test_should_build_converter_objects_when_row_comes_from_an_item():
    """The mapped row is consumed by the existing converter, unchanged."""
    converter = ConverterToStix(MagicMock(), MagicMock(), {})
    row = item_to_row(make_item())

    reference = converter.create_external_reference(row)
    indicator = converter.create_indicator(row, reference)
    observable = converter.create_obs_url(row, reference)

    assert indicator.pattern == "[url:value = 'http://42.234.72.133:38558/bin.sh']"
    assert indicator.valid_from == datetime(
        2026, 10, 30, 14, 53, 12, tzinfo=timezone.utc
    )
    assert indicator.labels == ["elf", "Mozi"]
    assert "Status: offline" in indicator.description
    assert observable.value == "http://42.234.72.133:38558/bin.sh"
    assert reference.url == "https://urlhaus.abuse.ch/url/4047624/"


def test_should_query_since_import_from_when_no_checkpoint_exists():
    client, spamhaus, _ = make_client([])

    collect(client)

    spamhaus.paginate.assert_called_once_with(
        URLS_PATH, params={"since": "2026-10-01T00:00:00Z"}, page_size=100
    )


def test_should_query_since_checkpoint_when_a_previous_run_stored_one():
    client, spamhaus, _ = make_client([], checkpoint=FIRST_SEEN_TS)

    collect(client)

    assert spamhaus.paginate.call_args.kwargs["params"] == {"since": FIRST_SEEN}


def test_should_yield_one_batch_per_page_when_several_pages_are_returned():
    client, _, _ = make_client(
        [[make_item(id=1)], [make_item(id=2)], [make_item(id=3)]]
    )

    batches = collect(client)

    assert [[row[0] for row in batch] for batch in batches] == [["1"], ["2"], ["3"]]


def test_should_yield_no_row_and_keep_checkpoint_when_no_item_is_returned():
    client, _, state = make_client([], checkpoint=FIRST_SEEN_TS)

    rows = [row for batch in collect(client) for row in batch]

    assert rows == []
    assert state.last_processed_entry_new == FIRST_SEEN_TS


def test_should_propagate_commercial_error_when_the_api_fails_mid_run():
    def pages():
        yield [make_item(id=1)]
        raise SpamhausUnavailableError("Spamhaus cannot answer (HTTP 503)")

    client, spamhaus, _ = make_client([])
    spamhaus.paginate.return_value = pages()

    with pytest.raises(SpamhausUnavailableError):
        collect(client)


def test_should_advance_checkpoint_to_newest_first_seen_when_items_are_read():
    items = [
        make_item(id=1, first_seen="2026-10-30T10:00:00Z"),
        make_item(id=2, first_seen="2026-10-31T10:00:00Z"),
        make_item(id=3, first_seen="2026-10-29T10:00:00Z"),
    ]
    client, _, state = make_client([items])

    collect(client)

    expected = datetime(2026, 10, 31, 10, tzinfo=timezone.utc).timestamp()
    assert state.last_processed_entry_new == expected
    assert state.last_processed_entry_old == 0


def test_should_skip_offline_urls_when_import_offline_is_disabled():
    items = [
        make_item(id=1, url_status="offline"),
        make_item(id=2, url_status="online"),
        make_item(id=3, url_status="unknown"),
    ]
    client, _, _ = make_client([items], import_offline=False)

    rows = [row for batch in collect(client) for row in batch]

    assert [row[0] for row in rows] == ["2", "3"]


def test_should_skip_item_and_warn_when_it_cannot_be_mapped():
    broken = make_item(id=9, first_seen="2026-12-31T10:00:00Z")
    del broken["url"]
    client, _, state = make_client([[make_item(id=1), broken]])

    rows = [row for batch in collect(client) for row in batch]

    assert [row[0] for row in rows] == ["1"]
    client.helper.connector_logger.warning.assert_called_once()
    # The checkpoint does not move past the item that failed to convert
    assert state.last_processed_entry_new == FIRST_SEEN_TS


def test_should_skip_item_when_first_seen_is_not_a_date():
    client, _, _ = make_client([[make_item(id=1, first_seen="not-a-date")]])

    assert [row for batch in collect(client) for row in batch] == []
    client.helper.connector_logger.warning.assert_called_once()
