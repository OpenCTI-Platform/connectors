"""Unit tests for ``lib.filters``.

The ``build_neighbor_filter`` / ``build_query_filter`` combinators are the
single point where the request's ``access_filter`` is ANDed with the
positive filter — neighbour ids for ``full`` exports, the user-supplied
list filter for ``query`` exports. If either combinator silently drops the
``access_filter`` a marking-restricted neighbour or query result could leak
through the export. The cases below pin the contract.

``access_filter_has_content`` is the single source of truth for the
"usable access filter" check shared between the combinators above and the
connector worker's per-direction relationship-list call. ``TestAccessFilterHasContent``
locks the contract so the two stages cannot diverge silently.
"""

import pytest
from lib.filters import (
    access_filter_has_content,
    build_neighbor_filter,
    build_query_filter,
)

_USER_LIST_FILTER = {
    "mode": "and",
    "filterGroups": [],
    "filters": [
        {
            "key": "entity_type",
            "values": ["Indicator"],
            "operator": "eq",
            "mode": "or",
        }
    ],
}

_ACCESS_FILTER = {
    "mode": "and",
    "filterGroups": [],
    "filters": [
        {
            "key": "objectMarking",
            "values": ["marking-definition--tlp-amber"],
            "operator": "not_eq",
            "mode": "or",
        }
    ],
}

_ACCESS_FILTER_NESTED = {
    "mode": "and",
    "filterGroups": [_ACCESS_FILTER],
    "filters": [],
}

_EMPTY_FILTER = {"mode": "and", "filterGroups": [], "filters": []}


def _ids_group(neighbor_ids):
    return {
        "mode": "and",
        "filterGroups": [],
        "filters": [
            {
                "key": "ids",
                "values": neighbor_ids,
                "operator": "eq",
                "mode": "or",
            }
        ],
    }


class TestBuildNeighborFilter:
    """``build_neighbor_filter`` must always select the requested ids and
    apply ``access_filter`` whenever it carries content."""

    def test_none_access_filter_returns_only_the_ids_group(self):
        neighbor_ids = ["entity--1", "entity--2"]
        result = build_neighbor_filter(neighbor_ids, None)
        assert result == _ids_group(neighbor_ids)

    def test_empty_access_filter_returns_only_the_ids_group(self):
        result = build_neighbor_filter(["entity--1"], _EMPTY_FILTER)
        assert result == _ids_group(["entity--1"])

    def test_populated_access_filter_is_anded_with_the_ids_group(self):
        neighbor_ids = ["entity--1", "entity--2"]
        result = build_neighbor_filter(neighbor_ids, _ACCESS_FILTER)
        assert result == {
            "mode": "and",
            "filterGroups": [_ids_group(neighbor_ids), _ACCESS_FILTER],
            "filters": [],
        }

    def test_nested_filter_groups_are_treated_as_content(self):
        # An ``access_filter`` whose own ``filters`` list is empty but
        # whose ``filterGroups`` contains a nested clause must still be
        # ANDed in — dropping it here would let marking-restricted
        # neighbours through.
        result = build_neighbor_filter(["entity--1"], _ACCESS_FILTER_NESTED)
        assert result == {
            "mode": "and",
            "filterGroups": [_ids_group(["entity--1"]), _ACCESS_FILTER_NESTED],
            "filters": [],
        }

    def test_empty_neighbor_ids_still_produces_a_valid_filter(self):
        # ``build_neighbor_filter`` is a pure combinator — it does not
        # short-circuit on empty input. Callers are responsible for not
        # invoking the platform with an empty ``ids`` filter.
        result = build_neighbor_filter([], _ACCESS_FILTER)
        assert result["filterGroups"][0] == _ids_group([])
        assert result["filterGroups"][1] == _ACCESS_FILTER


class TestBuildQueryFilter:
    """``build_query_filter`` must AND the user filter with the access
    filter whenever both are populated, and never silently drop either."""

    def test_no_filters_returns_none(self):
        assert build_query_filter(None, None) is None

    def test_only_user_filter_is_returned_as_is(self):
        assert build_query_filter(_USER_LIST_FILTER, None) == _USER_LIST_FILTER

    def test_only_user_filter_with_empty_access_filter_is_returned_as_is(self):
        assert build_query_filter(_USER_LIST_FILTER, _EMPTY_FILTER) == _USER_LIST_FILTER

    def test_only_access_filter_is_returned_when_user_filter_is_none(self):
        assert build_query_filter(None, _ACCESS_FILTER) == _ACCESS_FILTER

    def test_both_populated_are_anded_in_a_new_filter_group(self):
        result = build_query_filter(_USER_LIST_FILTER, _ACCESS_FILTER)
        assert result == {
            "mode": "and",
            "filterGroups": [_USER_LIST_FILTER, _ACCESS_FILTER],
            "filters": [],
        }

    def test_nested_filter_groups_count_as_content(self):
        # The access filter has empty ``filters`` but populated
        # ``filterGroups`` — it must still be ANDed in.
        result = build_query_filter(_USER_LIST_FILTER, _ACCESS_FILTER_NESTED)
        assert result == {
            "mode": "and",
            "filterGroups": [_USER_LIST_FILTER, _ACCESS_FILTER_NESTED],
            "filters": [],
        }

    @pytest.mark.parametrize("empty_access", [None, _EMPTY_FILTER, {}])
    def test_empty_access_filter_keeps_the_user_filter(self, empty_access):
        assert build_query_filter(_USER_LIST_FILTER, empty_access) == _USER_LIST_FILTER


class TestAccessFilterHasContent:
    """``access_filter_has_content`` is the shared "usable access filter"
    predicate used by ``build_neighbor_filter``, ``build_query_filter``
    and the connector's per-direction relationship-list call. Any
    divergence between the three would let marking-restricted rows leak
    through the export, so the contract is pinned here explicitly."""

    @pytest.mark.parametrize("empty_access", [None, {}, _EMPTY_FILTER])
    def test_empty_or_missing_access_filter_is_treated_as_absent(self, empty_access):
        assert access_filter_has_content(empty_access) is False

    def test_filters_only_access_filter_is_treated_as_content(self):
        assert access_filter_has_content(_ACCESS_FILTER) is True

    def test_filter_groups_only_access_filter_is_treated_as_content(self):
        assert access_filter_has_content(_ACCESS_FILTER_NESTED) is True

    def test_both_filters_and_filter_groups_populated_is_treated_as_content(self):
        composite = {
            "mode": "and",
            "filters": _ACCESS_FILTER["filters"],
            "filterGroups": [_ACCESS_FILTER],
        }
        assert access_filter_has_content(composite) is True

    @pytest.mark.parametrize(
        "missing_keys_access",
        [
            {"mode": "and"},
            {"filters": None, "filterGroups": None},
            {"filters": [], "filterGroups": None},
            {"filters": None, "filterGroups": []},
        ],
    )
    def test_missing_or_none_filters_keys_are_treated_as_absent(
        self, missing_keys_access
    ):
        assert access_filter_has_content(missing_keys_access) is False
