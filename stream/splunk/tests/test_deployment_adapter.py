from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk import (
    HitCollection,
    IndicatorDeployment,
    VendorHit,
    VendorIndicator,
)
from splunk_deployment import (
    SplunkKVStoreDeploymentAdapter,
    describe_error,
    parse_splunk_time,
)
from splunk_test_support import INDICATOR_ID

SINCE = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
DEPLOYMENT = IndicatorDeployment(
    relationship_id="relationship-id",
    status="deployed",
    indicator_id=INDICATOR_ID,
    pattern="[ipv4-addr:value = '198.51.100.7']",
    pattern_type="stix",
)


@pytest.fixture
def kvstore():
    return MagicMock()


def make_adapter(kvstore, **kwargs):
    kwargs.setdefault("push_indicator", MagicMock(return_value=INDICATOR_ID))
    return SplunkKVStoreDeploymentAdapter(kvstore, **kwargs)


def test_list_vendor_indicators_maps_the_kv_store_items(kvstore):
    item = {
        "_key": INDICATOR_ID,
        "type": "indicator",
        "values": ["198.51.100.7", "evil.example"],
    }
    kvstore.list_indicators.return_value = iter(
        [item, {"_key": "other", "type": "indicator"}]
    )

    vendor_indicators = list(make_adapter(kvstore).list_vendor_indicators())

    assert vendor_indicators == [
        VendorIndicator(
            indicator_id=INDICATOR_ID, external_id=INDICATOR_ID, value="198.51.100.7"
        ),
        VendorIndicator(indicator_id="other", external_id="other", value=None),
    ]
    assert vendor_indicators[0].raw == item


@pytest.mark.parametrize("malformed", [{"type": "indicator"}, "x"])
def test_list_vendor_indicators_rejects_an_item_without_key(kvstore, malformed):
    kvstore.list_indicators.return_value = iter([malformed])

    with pytest.raises(ValueError, match="carries no _key"):
        list(make_adapter(kvstore).list_vendor_indicators())


def test_list_vendor_indicators_propagates_read_errors(kvstore):
    kvstore.list_indicators.side_effect = requests.HTTPError("503 Server Error")

    with pytest.raises(requests.HTTPError):
        list(make_adapter(kvstore).list_vendor_indicators())


def test_remove_vendor_indicator_deletes_the_item(kvstore):
    make_adapter(kvstore).remove_vendor_indicator(
        VendorIndicator(indicator_id=INDICATOR_ID, external_id=INDICATOR_ID),
        DEPLOYMENT,
    )

    kvstore.delete.assert_called_once_with(INDICATOR_ID)


def test_remove_vendor_indicator_raises_without_key(kvstore):
    with pytest.raises(ValueError):
        make_adapter(kvstore).remove_vendor_indicator(
            VendorIndicator(value="198.51.100.7"), DEPLOYMENT
        )
    kvstore.delete.assert_not_called()


def test_remove_vendor_indicator_propagates_errors(kvstore):
    kvstore.delete.side_effect = requests.HTTPError("500 Server Error")

    with pytest.raises(requests.HTTPError):
        make_adapter(kvstore).remove_vendor_indicator(
            VendorIndicator(indicator_id=INDICATOR_ID, external_id=INDICATOR_ID),
            DEPLOYMENT,
        )


def test_push_indicator_uses_the_stream_create_path(kvstore):
    push = MagicMock(return_value=INDICATOR_ID)
    indicator = {"type": "indicator", "id": "indicator--x"}

    assert make_adapter(kvstore, push_indicator=push).push_indicator(indicator) == (
        INDICATOR_ID
    )
    push.assert_called_once_with(indicator)


def test_collect_hits_is_disabled_without_saved_search(kvstore):
    adapter = make_adapter(kvstore, hits_saved_search="  ")

    assert adapter.hits_supported is False
    assert adapter.collect_hits([DEPLOYMENT], SINCE) == []
    kvstore.run_saved_search.assert_not_called()


def test_collect_hits_skips_the_search_without_deployments(kvstore):
    adapter = make_adapter(kvstore, hits_saved_search="OpenCTI matches")

    assert adapter.collect_hits([], SINCE) == []
    kvstore.run_saved_search.assert_not_called()


def test_collect_hits_maps_the_saved_search_results(kvstore):
    recent = SINCE + timedelta(minutes=5)
    kvstore.run_saved_search.return_value = [
        {"opencti_id": INDICATOR_ID, "_time": recent.isoformat(), "count": "3"},
        {"value": ["198.51.100.7", "x"], "_time": str(recent.timestamp())},
        {"opencti_id": "too-old", "_time": (SINCE - timedelta(seconds=1)).isoformat()},
        {"_time": recent.isoformat(), "count": 2},
        {"opencti_id": "bad-count", "_time": recent.isoformat(), "count": "n/a"},
    ]
    adapter = make_adapter(
        kvstore, hits_saved_search=" OpenCTI matches ", hits_max_results=500
    )

    hits = adapter.collect_hits([DEPLOYMENT], SINCE)

    kvstore.run_saved_search.assert_called_once_with("OpenCTI matches", SINCE, 500)
    assert hits == [
        VendorHit(
            timestamp=recent,
            indicator_id=INDICATOR_ID,
            external_id=INDICATOR_ID,
            count=3,
        ),
        VendorHit(timestamp=recent, value="198.51.100.7"),
        VendorHit(timestamp=recent, indicator_id="bad-count", external_id="bad-count"),
    ]


@pytest.mark.parametrize(
    "malformed", [{"opencti_id": "no-time"}, {"_time": "never"}, "not a row"]
)
def test_collect_hits_rejects_a_result_without_time(kvstore, malformed):
    """A skipped result would be lost: the hit window moves past it."""
    kvstore.run_saved_search.return_value = [
        {"opencti_id": INDICATOR_ID, "_time": SINCE.isoformat()},
        malformed,
    ]
    adapter = make_adapter(kvstore, hits_saved_search="matches")

    with pytest.raises(ValueError, match="carries no _time"):
        adapter.collect_hits([DEPLOYMENT], SINCE)


def test_collect_hits_is_complete_until_the_newest_result_when_capped(kvstore):
    """Results are sorted oldest first: when the limit is reached, the next run
    resumes at the newest result read instead of losing the results beyond it."""
    newest = SINCE + timedelta(minutes=5)
    kvstore.run_saved_search.return_value = [
        {"opencti_id": INDICATOR_ID, "_time": SINCE.isoformat()},
        {"opencti_id": INDICATOR_ID, "_time": newest.isoformat()},
    ]
    adapter = make_adapter(kvstore, hits_saved_search="matches", hits_max_results=2)

    collection = adapter.collect_hits([DEPLOYMENT], SINCE)

    assert isinstance(collection, HitCollection)
    assert collection.complete_until == newest
    assert len(collection.hits) == 2
    assert collection.resume is None


def test_collect_hits_capped_at_its_start_are_a_lower_bound(kvstore):
    """More results share the start time than the limit: a row count would move
    with late or deleted events, so the read is not continued within that instant
    (the reconciler starts the next read just after it)."""
    kvstore.run_saved_search.return_value = [
        {"opencti_id": INDICATOR_ID, "_time": SINCE.isoformat()},
        {"value": "198.51.100.7", "_time": SINCE.isoformat()},
    ]
    adapter = make_adapter(kvstore, hits_saved_search="matches", hits_max_results=2)

    collection = adapter.collect_hits([DEPLOYMENT], SINCE)

    kvstore.run_saved_search.assert_called_once_with("matches", SINCE, 2)
    assert collection == HitCollection(
        hits=collection.hits, complete_until=SINCE, resume=None
    )
    assert len(collection.hits) == 2


def test_collect_hits_propagates_search_errors(kvstore):
    kvstore.run_saved_search.side_effect = requests.HTTPError("400 Client Error")

    with pytest.raises(requests.HTTPError):
        make_adapter(kvstore, hits_saved_search="matches").collect_hits(
            [DEPLOYMENT], SINCE
        )


@pytest.mark.parametrize(
    "value, expected",
    [
        (1696320000, datetime(2023, 10, 3, 8, 0, tzinfo=UTC)),
        ("1696320000.000", datetime(2023, 10, 3, 8, 0, tzinfo=UTC)),
        ("2023-10-03T10:00:00.000+02:00", datetime(2023, 10, 3, 8, 0, tzinfo=UTC)),
        (["1696320000", "1696320001"], datetime(2023, 10, 3, 8, 0, tzinfo=UTC)),
        ("not a time", None),
        ("nan", None),
        (None, None),
        (True, None),
    ],
)
def test_parse_splunk_time(value, expected):
    assert parse_splunk_time(value) == expected


def test_describe_error_appends_the_splunk_response():
    response = requests.Response()
    response.status_code = 400
    response._content = b'{"messages":[{"type":"ERROR","text":"bad field"}]}'
    error = requests.HTTPError("400 Client Error: Bad Request", response=response)

    assert describe_error(error) == (
        '400 Client Error: Bad Request - {"messages":[{"type":"ERROR","text":"bad field"}]}'
    )
    assert describe_error(ValueError()) == "ValueError"
