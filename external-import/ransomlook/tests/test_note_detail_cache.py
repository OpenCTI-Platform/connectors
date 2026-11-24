from unittest.mock import MagicMock

import connector.connector as coordinator
import pytest
from connector.api_client import RansomLookAPIError, RansomLookCapabilityUnavailable

from .test_connector import make_connector


def note_objects(objects):
    return [obj for obj in objects if obj.type == "note"]


def test_note_details_are_reused_across_groups_and_reset_each_run():
    connector = make_connector()
    connector.client.get_group_notes = MagicMock(
        side_effect=lambda group: [{"id": "shared", "name": group + " summary"}]
    )
    connector.client.get_note = MagicMock(
        return_value={"id": "shared", "content": "Example", "format": "txt"}
    )
    first_group = connector.converter.create_group("first", {})
    second_group = connector.converter.create_group("second", {})

    first, first_complete = connector._try_create_group_notes("first", first_group.id)
    second, second_complete = connector._try_create_group_notes(
        "second", second_group.id
    )

    connector.client.get_note.assert_called_once_with("shared")
    assert first_complete and second_complete
    first_note = note_objects(first)[0]
    second_note = note_objects(second)[0]
    assert first_note.object_refs == [first_group.id]
    assert second_note.object_refs == [second_group.id]
    assert first_note.abstract == "first summary"
    assert second_note.abstract == "second summary"
    assert first_note.id != second_note.id

    connector._reset_evidence_budget()
    connector._try_create_group_notes("first", first_group.id)
    assert connector.client.get_note.call_count == 2


def test_empty_note_detail_is_reused_without_losing_group_summaries():
    connector = make_connector()
    connector.client.get_group_notes = MagicMock(
        side_effect=lambda group: [{"id": "shared", "content": group}]
    )
    connector.client.get_note = MagicMock(return_value={})

    for group in ("first", "second"):
        group_id = connector.converter.create_group(group, {}).id
        objects, complete = connector._try_create_group_notes(group, group_id)
        assert complete
        assert note_objects(objects)[0].content == group

    connector.client.get_note.assert_called_once_with("shared")


@pytest.mark.parametrize(
    "failure",
    [RansomLookAPIError("unavailable"), RansomLookCapabilityUnavailable("notes", 404)],
)
def test_note_detail_failures_are_retried_for_another_group(failure):
    connector = make_connector()
    connector.client.get_group_notes = MagicMock(
        return_value=[{"id": "shared", "content": "summary"}]
    )
    connector.client.get_note = MagicMock(
        side_effect=[failure, {"id": "shared", "content": "full"}]
    )
    first_group = connector.converter.create_group("first", {})
    second_group = connector.converter.create_group("second", {})

    first, _ = connector._try_create_group_notes("first", first_group.id)
    second, complete = connector._try_create_group_notes("second", second_group.id)

    assert connector.client.get_note.call_count == 2
    assert note_objects(first)[0].content == "summary"
    assert note_objects(second)[0].content == "full"
    assert complete


@pytest.mark.parametrize("invalid_kind", ["object", "circular", "deep"])
def test_uncacheable_note_detail_is_still_imported(invalid_kind, monkeypatch):
    connector = make_connector()
    connector.client.get_group_notes = MagicMock(return_value=[{"id": "shared"}])
    invalid = object()
    if invalid_kind == "circular":
        invalid = []
        invalid.append(invalid)
    elif invalid_kind == "deep":
        invalid = None
    detail = {"id": "shared", "content": "Example", "unused": invalid}
    connector.client.get_note = MagicMock(return_value=detail)
    if invalid_kind == "deep":
        dumps = coordinator.json.dumps

        def fail_for_detail(value, *args, **kwargs):
            if value is detail:
                raise RecursionError("detail nesting limit")
            return dumps(value, *args, **kwargs)

        monkeypatch.setattr(coordinator.json, "dumps", fail_for_detail)

    for group in ("first", "second"):
        group_id = connector.converter.create_group(group, {}).id
        objects, complete = connector._try_create_group_notes(group, group_id)
        assert complete
        assert note_objects(objects)[0].content == "Example"

    assert connector.client.get_note.call_count == 2
    assert connector._note_details == {}
    assert connector._note_details_bytes == 0


def test_note_detail_cache_falls_back_to_fetch_when_size_limit_exceeded():
    connector = make_connector()
    connector.client.max_response_bytes = 10
    connector.client.get_group_notes = MagicMock(return_value=[{"id": "shared"}])
    connector.client.get_note = MagicMock(
        return_value={"id": "shared", "content": "Example"}
    )
    first_group = connector.converter.create_group("first", {})
    second_group = connector.converter.create_group("second", {})

    first, _ = connector._try_create_group_notes("first", first_group.id)
    second, _ = connector._try_create_group_notes("second", second_group.id)

    assert connector.client.get_note.call_count == 2
    assert (
        note_objects(first)[0].content == note_objects(second)[0].content == "Example"
    )


@pytest.mark.parametrize(
    ("response_limit", "cache_limit", "expected_calls"),
    [(1, 2, 2), (3, 1, 3)],
)
def test_note_cache_limit_is_independent_and_bounded(
    response_limit, cache_limit, expected_calls
):
    connector = make_connector(max_records_per_endpoint=response_limit)
    connector.NOTE_DETAIL_CACHE_MAX_ENTRIES = cache_limit
    connector.client.get_group_notes = MagicMock(
        side_effect=lambda group: [{"id": "first" if group in ("a", "d") else "second"}]
    )
    connector.client.get_note = MagicMock(
        side_effect=lambda key: {"id": key, "content": "Example"}
    )

    for group in "abcd":
        group_id = connector.converter.create_group(group, {}).id
        objects, complete = connector._try_create_group_notes(group, group_id)
        assert complete
        assert note_objects(objects)[0].content == "Example"

    assert connector.client.get_note.call_count == expected_calls
