from unittest.mock import MagicMock

import pytest
from connector.event_filter import EventFilter

EVENT = {
    "id": "42",
    "info": "OSINT - Emotet campaign",
    "Orgc": {"name": "CIRCL", "uuid": "55f6ea5e-2c60-40e5-964f-47a8950d210f"},
    "Org": {"name": "ORGNAME", "uuid": "5d5c8a2c-1c8c-4f9e-8f0b-0a0a0a0a0a0a"},
}


def _filter(**config) -> EventFilter:
    defaults = {
        "event_filter_creator_orgs": [],
        "event_filter_creator_orgs_not": [],
        "event_filter_owner_orgs": [],
        "event_filter_owner_orgs_not": [],
        "event_filter_name_regex": None,
    }
    return EventFilter(MagicMock(**{**defaults, **config}))


def test_no_filter_accepts_every_event():
    assert _filter().accepts(EVENT) is True


@pytest.mark.parametrize(
    "config, expected",
    [
        pytest.param(
            {"event_filter_creator_orgs": ["circl"]},
            True,
            id="creator_included_by_name",
        ),
        pytest.param(
            {"event_filter_creator_orgs": ["55F6EA5E-2C60-40E5-964F-47A8950D210F"]},
            True,
            id="creator_included_by_uuid",
        ),
        pytest.param(
            {"event_filter_creator_orgs": ["Other"]}, False, id="creator_not_included"
        ),
        pytest.param(
            {"event_filter_creator_orgs_not": ["CIRCL"]}, False, id="creator_excluded"
        ),
        pytest.param(
            {"event_filter_creator_orgs_not": ["Other"]},
            True,
            id="creator_not_excluded",
        ),
        pytest.param(
            {"event_filter_owner_orgs": ["ORGNAME"]}, True, id="owner_included"
        ),
        pytest.param(
            {"event_filter_owner_orgs": ["CIRCL"]}, False, id="owner_not_included"
        ),
        pytest.param(
            {"event_filter_owner_orgs_not": [" orgname "]}, False, id="owner_excluded"
        ),
        pytest.param(
            {"event_filter_name_regex": "emotet"},
            False,
            id="name_regex_is_case_sensitive",
        ),
        pytest.param(
            {"event_filter_name_regex": "(?i)emotet"}, True, id="name_regex_matches"
        ),
        pytest.param(
            {"event_filter_name_regex": "^OSINT"}, True, id="name_regex_anchored"
        ),
        pytest.param(
            {"event_filter_name_regex": "^Emotet"}, False, id="name_regex_no_match"
        ),
    ],
)
def test_single_filter(config, expected):
    assert _filter(**config).accepts(EVENT) is expected


def test_filters_are_combined_with_and():
    event_filter = _filter(
        event_filter_creator_orgs=["CIRCL"],
        event_filter_owner_orgs=["ORGNAME"],
        event_filter_name_regex="Ryuk",
    )

    assert event_filter.accepts(EVENT) is False


def test_include_list_rejects_event_without_organisation():
    event = {"id": "1", "info": "No org"}

    assert _filter(event_filter_creator_orgs=["CIRCL"]).accepts(event) is False
    assert _filter(event_filter_creator_orgs_not=["CIRCL"]).accepts(event) is True
