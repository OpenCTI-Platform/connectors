from typing import Any
from unittest.mock import MagicMock

import pytest
from abuseipdb_taxii_client import TaxiiBadRequestError, TaxiiPage
from conftest import COLLECTION_ID, CONFIGURED_COLLECTION_ID, make_processor
from connector import ConnectorState
from connector.data_processors import TaxiiFeedProcessor
from connectors_sdk import ProviderApiServerError

IMPORT_SINCE = "2026-08-19T04:00:00Z"
MARK_1 = "2026-08-20T10:00:00.000000Z"
MARK_2 = "2026-08-21T15:00:00.123456Z"

IDENTITY = {
    "type": "identity",
    "id": "identity--5b2a6e3f-2d3c-4c4b-9a0e-1f7f5b6c8d9e",
    "name": "AbuseIPDB",
}
SIGHTING = {
    "type": "sighting",
    "id": "sighting--0d6b8e7c-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
}


def indicator(n: int) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--00000000-0000-4000-8000-{n:012d}",
        "pattern": f"[ipv4-addr:value = '192.0.2.{n}']",
        "pattern_type": "stix",
    }


def page(
    objects: list[dict[str, Any]],
    *,
    next_cursor: str | None = None,
    added_last: str | None = None,
) -> TaxiiPage:
    return TaxiiPage(
        objects=objects,
        more=next_cursor is not None,
        next_cursor=next_cursor,
        added_last=added_last,
    )


def run_pull(processor: TaxiiFeedProcessor) -> list[list[dict[str, Any]]]:
    return list(processor.transform(processor.collect()))


def final_meta(processor: TaxiiFeedProcessor) -> dict[str, Any]:
    return processor.logger.info.call_args_list[-1].kwargs["meta"]


def delivered_ids(bundles: list[list[dict[str, Any]]]) -> set[str]:
    return {obj["id"] for bundle in bundles for obj in bundle}


def test_drain_relays_every_page_unchanged_and_advances_the_mark():
    pages = [
        page([IDENTITY, indicator(1), SIGHTING], next_cursor="c1"),
        page([indicator(2)], next_cursor="c2"),
        page([indicator(3)], added_last=MARK_2),
    ]
    processor = make_processor(list(pages))

    bundles = run_pull(processor)

    assert len(bundles) == 3
    for bundle, served in zip(bundles, pages):
        assert bundle is served.objects
    assert processor.client.configured_id == CONFIGURED_COLLECTION_ID
    assert [r["next_cursor"] for r in processor.client.requests] == [None, "c1", "c2"]
    assert processor.client.requests[0]["added_after"] == IMPORT_SINCE
    assert processor.state.next_cursor is None
    assert processor.state.added_after == MARK_2
    assert final_meta(processor) == {
        "drained": True,
        "pages": 3,
        "objects_submitted": 5,
    }


def test_position_is_recorded_only_after_the_page_was_handed_over():
    processor = make_processor(
        [
            page([indicator(1)], next_cursor="c1"),
            page([indicator(2)], added_last=MARK_2),
        ]
    )
    bundles = processor.transform(processor.collect())

    next(bundles)
    assert processor.state.next_cursor is None
    assert processor.state.added_after == IMPORT_SINCE

    next(bundles)
    assert processor.state.next_cursor == "c1"
    assert processor.state.added_after == IMPORT_SINCE

    with pytest.raises(StopIteration):
        next(bundles)
    assert processor.state.next_cursor is None
    assert processor.state.added_after == MARK_2


@pytest.mark.parametrize("initial_mark", [None, MARK_1])
def test_missing_header_keeps_the_previous_mark(initial_mark: str | None):
    processor = make_processor(
        [page([indicator(1)], added_last=None)],
        state=ConnectorState(added_after=initial_mark),
    )

    run_pull(processor)

    assert processor.state.added_after == (initial_mark or IMPORT_SINCE)


def test_daily_cap_answer_ends_the_pull_cleanly():
    processor = make_processor(
        [
            page([indicator(1)], next_cursor="c1"),
            page([], added_last=MARK_2),
        ]
    )

    bundles = run_pull(processor)

    assert len(bundles) == 1
    assert len(processor.client.requests) == 2
    processor.logger.exception.assert_not_called()
    assert final_meta(processor)["drained"] is True


def test_next_utc_day_replay_is_relayed():
    served = [indicator(1), indicator(2)]
    first = make_processor([page(list(served), added_last=MARK_1)])
    run_pull(first)

    second = make_processor([page(list(served), added_last=MARK_2)], state=first.state)
    bundles = run_pull(second)

    assert bundles == [served]


def test_interrupted_first_pull_saves_its_start():
    processor = make_processor(
        [
            page([indicator(1)], next_cursor="c1"),
            ProviderApiServerError("server error"),
        ]
    )

    run_pull(processor)

    assert processor.state.added_after == IMPORT_SINCE
    assert processor.state.next_cursor == "c1"


def test_failure_mid_drain_saves_the_resume_cursor():
    state = ConnectorState(added_after=MARK_1)
    first = make_processor(
        [
            page([indicator(1)], next_cursor="c1"),
            ProviderApiServerError("server error"),
        ],
        state=state,
    )

    run_pull(first)

    first.logger.exception.assert_called_once()
    assert state.next_cursor == "c1"
    assert state.added_after == MARK_1

    second = make_processor([page([indicator(2)], added_last=MARK_2)], state=state)
    run_pull(second)

    assert second.client.requests[0]["next_cursor"] == "c1"
    assert state.next_cursor is None
    assert state.added_after == MARK_2


def test_restart_after_a_closed_pull_replays_from_the_saved_mark():
    completed = make_processor([page([indicator(0)], added_last=MARK_1)])
    run_pull(completed)
    saved = completed.state.to_json()
    served = [
        page([indicator(1)], next_cursor="c1"),
        page([indicator(2)], next_cursor="c2"),
        page([indicator(3)], added_last=MARK_2),
    ]
    killed = make_processor(list(served), state=ConnectorState(**saved))
    bundles = killed.transform(killed.collect())
    first_run = [next(bundles), next(bundles)]
    bundles.close()
    killed.logger.exception.assert_not_called()

    restarted = make_processor(list(served), state=ConnectorState(**saved))
    second_run = run_pull(restarted)

    assert restarted.client.requests[0] == {
        "added_after": MARK_1,
        "next_cursor": None,
        "limit": 100,
    }
    served_ids = {obj["id"] for p in served for obj in p.objects}
    assert delivered_ids(first_run) | delivered_ids(second_run) >= served_ids


def test_repeated_cursor_delivers_the_page_then_stops():
    state = ConnectorState(added_after=MARK_1)
    processor = make_processor(
        [
            page([indicator(1)], next_cursor="c1"),
            page([indicator(2)], next_cursor="c1"),
        ],
        state=state,
    )

    bundles = run_pull(processor)

    assert delivered_ids(bundles) == {indicator(1)["id"], indicator(2)["id"]}
    assert len(processor.client.requests) == 2
    processor.logger.exception.assert_called_once()
    assert final_meta(processor)["drained"] is False
    assert state.next_cursor is None

    following = make_processor([page([], added_last=MARK_2)], state=state)
    run_pull(following)

    assert following.client.requests[0] == {
        "added_after": MARK_1,
        "next_cursor": None,
        "limit": 100,
    }


def test_unexpected_error_escapes_the_pull():
    processor = make_processor(
        [page([indicator(1)], next_cursor="c1"), TypeError("unexpected")]
    )

    with pytest.raises(TypeError):
        run_pull(processor)

    processor.logger.exception.assert_not_called()


def test_rejected_saved_cursor_is_dropped():
    state = ConnectorState(added_after=MARK_1, next_cursor="stale")
    processor = make_processor(
        [TaxiiBadRequestError("rejected")],
        state=state,
    )

    run_pull(processor)

    assert state.next_cursor is None
    assert state.added_after == MARK_1


def test_process_sends_one_bundle_per_non_empty_page():
    helper = MagicMock()
    processor = make_processor(
        [
            page([IDENTITY, indicator(1)], next_cursor="c1"),
            page([], next_cursor="c2"),
            page([indicator(2)], added_last=MARK_2),
        ],
        helper=helper,
    )

    processor.process()

    helper.api.work.initiate_work.assert_called_once()
    assert helper.send_stix2_bundle.call_count == 2


def test_process_opens_no_work_for_an_exhausted_feed():
    helper = MagicMock()
    processor = make_processor([page([], added_last=MARK_2)], helper=helper)

    processor.process()

    helper.api.work.initiate_work.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_failed_send_escapes_process_without_advancing_the_cursor():
    helper = MagicMock()
    processor = make_processor(
        [
            page([indicator(1)], next_cursor="c1"),
            page([indicator(2)], next_cursor="c2"),
            page([indicator(3)], added_last=MARK_2),
        ],
        state=ConnectorState(added_after=MARK_1),
        helper=helper,
    )
    helper.send_stix2_bundle.side_effect = [[], RuntimeError("send failed")]

    with pytest.raises(RuntimeError):
        processor.process()

    processor.logger.exception.assert_not_called()
    assert processor.state.next_cursor == "c1"
    assert processor.state.added_after == MARK_1


def test_position_saved_for_another_feed_is_dropped():
    state = ConnectorState(
        collection_id="previous-feed-id", added_after=MARK_1, next_cursor="c1"
    )
    processor = make_processor([page([indicator(1)], added_last=MARK_2)], state=state)

    run_pull(processor)

    assert processor.client.requests[0] == {
        "added_after": IMPORT_SINCE,
        "next_cursor": None,
        "limit": 100,
    }
    assert state.collection_id == COLLECTION_ID


@pytest.mark.parametrize(
    "saved_collection_id",
    [pytest.param(COLLECTION_ID, id="same_feed"), pytest.param(None, id="unknown")],
)
def test_position_is_kept_unless_saved_for_another_feed(
    saved_collection_id: str | None,
):
    state = ConnectorState(
        collection_id=saved_collection_id, added_after=MARK_1, next_cursor="c1"
    )
    processor = make_processor([page([indicator(1)], added_last=MARK_2)], state=state)

    run_pull(processor)

    assert processor.client.requests[0] == {
        "added_after": MARK_1,
        "next_cursor": "c1",
        "limit": 100,
    }
    assert state.collection_id == COLLECTION_ID
