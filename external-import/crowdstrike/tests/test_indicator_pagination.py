"""Tests for the CrowdStrike indicator paginated fetch logic.

These tests cover the marker-based deep-pagination contract between
:class:`crowdstrike_feeds_services.client.indicators.IndicatorsAPI` and
:class:`crowdstrike_feeds_connector.indicator.importer.IndicatorImporter`:

* The importer drives marker-based deep pagination using the ``_marker``
  field carried by each indicator (the FQL clause ``_marker:>='...'``),
  per CrowdStrike's documented ``QueryIntelIndicatorEntities`` contract.
* Pagination stops cleanly when the API returns an empty page (the
  authoritative end-of-iteration signal), when the last accepted
  indicator is missing its ``_marker`` field (defensive guard against
  malformed responses), when the marker fails to advance between two
  consecutive pages (defensive anti-spin guard), or when
  ``max_records_per_run`` is reached. The importer intentionally does
  NOT branch on ``meta.pagination.total`` - that field is the count of
  records matching the current request's FQL clause and is included
  in the log line as ``matching_filter_total`` for diagnostics only.
* Inclusive-boundary strips (cross-run + within-run): FQL
  ``_marker:>='<cursor>'`` is inclusive, so the cursor row is
  expected back on every iteration. The paginator strips the
  leading row in two complementary ways:
  - Cross-run (iteration one): when ``fetch_marker`` is set and
    the first page's first row's ``_marker`` equals
    ``fetch_marker``, drop it. Marker comparison is the only
    signal available on iteration one because we don't yet have
    a previous-iteration ``id``.
  - Within-run (iterations 2+): track the ``id`` of the last
    accepted row and drop the next page's first row when its
    ``id`` matches. Matching on ``id`` (not ``_marker``) is the
    only signal that distinguishes "same indicator returned
    again because of the inclusive ``>=`` clause" from "two
    different indicators that happen to share a marker" - the
    latter is a pathological case still caught by the
    marker-didn't-advance anti-spin guard.
  Stripping up-front keeps duplicates from being counted against
  ``max_records_per_run`` and avoids paying for one idempotent
  re-process of the boundary indicator per iteration / run.
* Pagination is robust to ``meta.pagination`` being missing or ``None``.
* ``exclude_types`` and the FQL marker clause are combined correctly.
* Cross-run resume: the last accepted indicator's ``_marker`` is
  persisted in importer state under ``latest_indicator_marker`` and
  used verbatim as the first-page cursor on the next run; if the key
  is absent (e.g. a deployment carrying only the legacy
  ``latest_indicator_timestamp``), the state timestamp is used as the
  initial cursor instead.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# CrowdStrike's pydantic settings are constructed when
# ``crowdstrike_feeds_*`` modules are imported, so the env vars MUST be
# in place before any of them is loaded. The previous module-level
# ``os.environ.setdefault`` was problematic for two reasons:
#
#   * ``setdefault`` does NOT override potentially-invalid values
#     inherited from the test runner environment;
#   * the changes were never reverted, so they leaked into the other
#     CrowdStrike test modules (most of which use ``mock_env_vars(...)``
#     from ``conftest.py`` to patch and restore env).
#
# We now drive the env through a function-scoped ``autouse`` fixture
# (``monkeypatch.setenv`` always overrides and pytest restores the
# original env at teardown), and the connector modules are imported
# lazily inside ``_build_importer`` so the env fixture has applied by
# the time pydantic-settings runs.
_REQUIRED_ENV: dict[str, str] = {
    "OPENCTI_URL": "http://localhost:8080",
    "OPENCTI_TOKEN": "token",
    "CONNECTOR_ID": "ChangeMe",
    "CONNECTOR_TYPE": "EXTERNAL_IMPORT",
    "CONNECTOR_NAME": "CrowdStrike",
    "CONNECTOR_SCOPE": "crowdstrike",
    "CONNECTOR_LOG_LEVEL": "info",
    "CONNECTOR_DURATION_PERIOD": "PT30M",
    "CROWDSTRIKE_CLIENT_ID": "ChangeMe",
    "CROWDSTRIKE_CLIENT_SECRET": "ChangeMe",
}


@pytest.fixture(autouse=True)
def _crowdstrike_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin (and restore) the env vars CrowdStrike's settings expect.

    ``monkeypatch.setenv`` overrides any existing runner-provided
    value (whereas ``os.environ.setdefault`` left potentially-invalid
    values in place) and pytest restores the original env when the
    fixture tears down so these settings cannot leak into the other
    CrowdStrike test modules.
    """
    for key, value in _REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)


def _build_importer(*, max_records_per_run=None, exclude_types=None):
    """Build an ``IndicatorImporter`` whose API client is a ``MagicMock``.

    The :class:`IndicatorsAPI` / :class:`RelatedActorImporter` /
    :class:`ReportFetcher` classes are patched out because their
    constructors instantiate the CrowdStrike settings / falconpy
    client / pycti API, which would require real credentials at
    construction time. The connector modules are imported lazily so
    the ``_crowdstrike_env`` autouse fixture has applied (and
    overrides any invalid runner-provided value) before the
    pydantic settings are constructed at module import time.
    """
    from crowdstrike_feeds_connector.indicator.importer import (
        IndicatorImporter,
        IndicatorImporterConfig,
    )
    from crowdstrike_feeds_services.client.indicators import IndicatorsAPI

    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connect_id = "connector-id"

    author = MagicMock()
    tlp_marking = MagicMock()
    settings = MagicMock()

    cfg = IndicatorImporterConfig(
        config=settings,
        helper=helper,
        author=author,
        default_latest_timestamp=0,
        tlp_marking=tlp_marking,
        create_observables=True,
        create_indicators=True,
        exclude_types=exclude_types or [],
        report_status=0,
        report_type="threat-report",
        default_x_opencti_score=50,
        indicator_low_score=40,
        indicator_low_score_labels=set(),
        indicator_medium_score=60,
        indicator_medium_score_labels=set(),
        indicator_high_score=80,
        indicator_high_score_labels=set(),
        indicator_unwanted_labels=set(),
        indicator_max_age_by_type={},
        no_file_trigger_import=True,
        scopes={"indicator"},
        attack_lookup=None,
        max_records_per_run=max_records_per_run,
    )

    with patch(
        "crowdstrike_feeds_connector.indicator.importer.IndicatorsAPI",
        autospec=True,
    ), patch(
        "crowdstrike_feeds_connector.indicator.importer.RelatedActorImporter",
        autospec=True,
    ), patch(
        "crowdstrike_feeds_connector.indicator.importer.ReportFetcher",
        autospec=True,
    ):
        importer = IndicatorImporter(cfg)

    importer.indicators_api_cs = MagicMock(spec=IndicatorsAPI)
    return importer


def _make_page(resources, *, total=None, with_pagination=True) -> dict[str, Any]:
    """Build a fake parsed response body."""
    page: dict[str, Any] = {"resources": resources}
    if with_pagination:
        page["meta"] = {"pagination": {"total": total if total is not None else 0}}
    else:
        # Cover the ``meta.pagination`` is ``None`` case.
        page["meta"] = {"pagination": None}
    return page


def _fake_indicator(idx: int, *, marker: str | None = None) -> dict[str, Any]:
    """Build a fake indicator. ``_marker`` defaults to a monotonic value."""
    return {
        "id": f"ioc-{idx}",
        "last_updated": 1_700_000_000 + idx,
        "type": "domain",
        # Mimic CrowdStrike's marker format: 10-char unix timestamp +
        # unique suffix.
        "_marker": (
            marker if marker is not None else f"{1_700_000_000 + idx}aaa{idx:04d}"
        ),
    }


def test_pagination_walks_every_page_until_empty_page():
    importer = _build_importer()
    indicators = [_fake_indicator(i) for i in range(5)]
    # Termination is driven by the empty-page check at the top of the
    # loop (the authoritative end-of-iteration signal per CrowdStrike's
    # contract). ``meta.pagination.total`` values shown here are
    # illustrative of the "decreasing as the marker advances" pattern
    # the API returns for marker-based queries (each page's total
    # reflects records matching the *current request*'s FQL filter,
    # which narrows as ``_marker`` advances), but the importer does
    # NOT branch on those values for termination.
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators[:2], total=5),
        _make_page(indicators[2:4], total=3),
        _make_page(indicators[4:], total=1),
        _make_page([], total=0),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == indicators
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 4
    call_args_list = (
        importer.indicators_api_cs.get_combined_indicator_entities.call_args_list
    )
    # First call uses the importer state timestamp as the marker.
    assert call_args_list[0].kwargs["fql_filter"] == "_marker:>='1700000000'"
    # Subsequent calls advance the marker using the last indicator's
    # ``_marker`` field.
    assert (
        call_args_list[1].kwargs["fql_filter"]
        == f"_marker:>='{indicators[1]['_marker']}'"
    )
    assert (
        call_args_list[2].kwargs["fql_filter"]
        == f"_marker:>='{indicators[3]['_marker']}'"
    )
    assert (
        call_args_list[3].kwargs["fql_filter"]
        == f"_marker:>='{indicators[4]['_marker']}'"
    )
    # Marker-based pagination requires sorting by ``_marker`` ascending.
    assert all(call.kwargs["sort"] == "_marker.asc" for call in call_args_list)


def test_pagination_stops_when_resources_are_empty():
    importer = _build_importer()
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([], total=0),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == []
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 1


def test_pagination_handles_missing_pagination_metadata():
    importer = _build_importer()
    indicators = [_fake_indicator(i) for i in range(2)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        # ``meta.pagination`` is ``None`` — the importer should still
        # walk the page and then break on the empty follow-up.
        _make_page(indicators, with_pagination=False),
        _make_page([], total=0),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == indicators


def test_pagination_stops_when_marker_does_not_advance():
    """If the API ever returns the same marker twice in a row we must
    stop instead of looping forever."""
    importer = _build_importer()
    stuck_marker = "1700000005xxxx0001"
    indicators = [
        _fake_indicator(0, marker=stuck_marker),
        _fake_indicator(1, marker=stuck_marker),
    ]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([indicators[0]], total=10),
        _make_page([indicators[1]], total=10),
        # Should never be called — the loop must have broken out.
        _make_page([_fake_indicator(2)], total=10),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == indicators
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 2


def test_pagination_stops_when_marker_field_is_missing():
    importer = _build_importer()
    bad_indicator = {"id": "ioc-x", "last_updated": 1_700_000_000, "type": "domain"}
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([bad_indicator], total=10),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == [bad_indicator]
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 1


def test_pagination_caps_total_records_per_run_within_first_page():
    importer = _build_importer(max_records_per_run=3)
    indicators = [_fake_indicator(i) for i in range(10)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators, total=10),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    # Only 3 indicators fetched, and no follow-up page was requested.
    assert fetched == indicators[:3]
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 1


def test_pagination_caps_total_records_per_run_across_pages():
    importer = _build_importer(max_records_per_run=3)
    indicators = [_fake_indicator(i) for i in range(6)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators[:2], total=4),
        _make_page(indicators[2:4], total=2),
        _make_page(indicators[4:], total=0),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == indicators[:3]
    # Should have stopped after the 2nd page (2 from page 1, 1 from page 2).
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 2


@pytest.mark.parametrize("disabled_value", [None, 0, -1])
def test_pagination_cap_can_be_disabled(disabled_value):
    importer = _build_importer(max_records_per_run=disabled_value)
    indicators = [_fake_indicator(i) for i in range(5)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators[:2], total=5),
        _make_page(indicators[2:], total=3),
        _make_page([], total=0),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == indicators


def test_fql_filter_includes_exclude_types_clause():
    """``exclude_types`` must be appended to the marker FQL clause via ``+``."""
    importer = _build_importer(exclude_types=["hash_md5", "hash_sha1"])
    indicators = [_fake_indicator(0)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators, total=1),
        _make_page([], total=0),
    ]

    importer._paginated_query_indicators(limit=1000, fetch_timestamp=1_700_000_000)

    # Assert on the FIRST call (the timestamp-based resume). The
    # second call's filter uses the advanced ``_marker`` cursor from
    # the first page and the test for that advance lives in
    # ``test_pagination_walks_every_page_until_empty_page``.
    first_call_kwargs = (
        importer.indicators_api_cs.get_combined_indicator_entities.call_args_list[
            0
        ].kwargs
    )
    assert (
        first_call_kwargs["fql_filter"]
        == "_marker:>='1700000000'+type:!['hash_md5', 'hash_sha1']"
    )


def test_pagination_prefers_fetch_marker_over_timestamp_when_provided():
    """A persisted ``_marker`` (with its unique suffix) MUST drive the
    initial resume cursor instead of the bare ``last_updated`` timestamp.

    This pins the cross-run resume contract: without the persisted
    marker, the FQL ``_marker:>='1700000005'`` matches every indicator
    whose timestamp prefix is ``1700000005`` — including the ones we
    already processed in the previous run. The unique-suffixed marker
    pins resume to the exact boundary indicator.
    """
    importer = _build_importer()
    persisted_marker = "1700000005aaa0042"
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([], total=0),
    ]

    importer._paginated_query_indicators(
        limit=1000,
        fetch_timestamp=1_700_000_000,
        fetch_marker=persisted_marker,
    )

    call_kwargs = (
        importer.indicators_api_cs.get_combined_indicator_entities.call_args.kwargs
    )
    assert call_kwargs["fql_filter"] == f"_marker:>='{persisted_marker}'"


def test_pagination_falls_back_to_timestamp_when_fetch_marker_is_none():
    """No persisted marker (pre-upgrade state) MUST fall back to the
    timestamp-based resume so a deployment carrying only the legacy
    ``latest_indicator_timestamp`` key keeps working without manual
    state migration.
    """
    importer = _build_importer()
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([], total=0),
    ]

    importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000, fetch_marker=None
    )

    call_kwargs = (
        importer.indicators_api_cs.get_combined_indicator_entities.call_args.kwargs
    )
    assert call_kwargs["fql_filter"] == "_marker:>='1700000000'"


def test_run_persists_last_observed_marker_in_state():
    """``run()`` MUST persist the last observed ``_marker`` under
    ``latest_indicator_marker`` so the next run resumes exactly from
    the boundary indicator (and not from the seconds-granularity
    timestamp that would re-fetch every indicator sharing that second).
    """
    importer = _build_importer()
    # ``_process_indicators`` walks each indicator and runs the full
    # bundle pipeline. Short-circuit it for this state-shape test.
    importer._process_indicators = MagicMock(return_value=None)
    indicators = [_fake_indicator(i) for i in range(3)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators, total=3),
        _make_page([], total=0),
    ]

    new_state = importer.run({"latest_indicator_timestamp": 1_700_000_000})

    assert new_state["latest_indicator_marker"] == indicators[-1]["_marker"]
    assert "latest_indicator_timestamp" in new_state


def test_run_reads_persisted_marker_from_state_and_passes_to_fetch():
    """``run()`` MUST pull ``latest_indicator_marker`` from incoming
    state and use it (verbatim, suffix included) as the initial FQL
    marker so the cross-run boundary is exact.
    """
    importer = _build_importer()
    importer._process_indicators = MagicMock(return_value=None)
    persisted_marker = "1700000005aaa0042"
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([], total=0),
    ]

    importer.run(
        {
            "latest_indicator_timestamp": 1_700_000_000,
            "latest_indicator_marker": persisted_marker,
        }
    )

    call_kwargs = (
        importer.indicators_api_cs.get_combined_indicator_entities.call_args.kwargs
    )
    assert call_kwargs["fql_filter"] == f"_marker:>='{persisted_marker}'"


def test_pagination_strips_inclusive_boundary_when_only_boundary_returned():
    """Resume + no new indicators must NOT re-process the boundary row.

    The FQL clause ``_marker:>='<cursor>'`` is *inclusive*, so resuming
    with the persisted ``_marker`` and no newer indicators since
    returns the boundary indicator itself on the first call (page
    contains the indicator whose marker we persisted last time). The
    paginator strips the duplicate boundary row up-front, so the
    aggregated batch is empty, exactly one API call is issued, and
    we avoid paying for one idempotent re-process of the
    already-seen indicator on every "no new data" resume.
    """
    importer = _build_importer()
    persisted_marker = "1700000005aaa0042"
    boundary_indicator = _fake_indicator(0, marker=persisted_marker)
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([boundary_indicator], total=1),
        _make_page([_fake_indicator(1)], total=1),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000,
        fetch_timestamp=1_700_000_000,
        fetch_marker=persisted_marker,
    )

    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 1
    assert fetched == []


def test_pagination_strips_inclusive_boundary_under_tight_cap():
    """Tight ``max_records_per_run`` + persisted boundary must still
    advance.

    Regression for the case where a small per-run cap (e.g. ``1``)
    combined with the FQL ``_marker:>='<cursor>'`` inclusive boundary
    used to let the boundary row consume the entire quota: the page
    was sliced down to ``[boundary]``, the cap break fired, and
    ``next_marker`` resolved back to the persisted cursor - so the
    importer state never advanced and subsequent runs repeated the
    same row forever, never reaching the newer indicators. With the
    inclusive-boundary strip the boundary row is dropped BEFORE the
    cap slice, the quota is spent on the first newer indicator
    instead, and the persisted marker advances out of the boundary.
    """
    importer = _build_importer(max_records_per_run=1)
    persisted_marker = "1700000005aaa0042"
    boundary_indicator = _fake_indicator(0, marker=persisted_marker)
    newer_one = _fake_indicator(1, marker="1700000006aaa0001")
    newer_two = _fake_indicator(2, marker="1700000007aaa0002")
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([boundary_indicator, newer_one, newer_two], total=3),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000,
        fetch_timestamp=1_700_000_000,
        fetch_marker=persisted_marker,
    )

    assert fetched == [newer_one]
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 1
    assert fetched[-1]["_marker"] != persisted_marker


def test_pagination_strips_inclusive_boundary_within_run():
    """Continuation pages must NOT re-process the previous page's last row.

    FQL ``_marker:>='<cursor>'`` is inclusive within a single run too:
    after page one returns ``[ind_a, ind_b]``, ``current_marker`` is set
    to ``ind_b._marker`` and page two's query is
    ``_marker:>='ind_b._marker'``, which returns ``ind_b`` again as the
    first row. The paginator strips that duplicate (matching by ``id``,
    not by ``_marker``, so a coincidental marker collision between two
    *different* indicators is not eaten - that case lives in
    ``test_pagination_stops_when_marker_does_not_advance``).

    Without the strip the duplicate row would be appended a second time
    *and* counted against ``max_records_per_run``, which both inflates
    the apparent fetch volume and erodes the genuine forward progress
    at the tail of a tight cap.
    """
    importer = _build_importer()
    ind_a = _fake_indicator(0, marker="1700000001aaa0000")
    ind_b = _fake_indicator(1, marker="1700000002aaa0001")
    ind_c = _fake_indicator(2, marker="1700000003aaa0002")
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([ind_a, ind_b], total=3),
        _make_page([ind_b, ind_c], total=1),
        _make_page([], total=0),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == [ind_a, ind_b, ind_c]
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 3


def test_pagination_within_run_strip_does_not_consume_cap():
    """The within-run strip must not let the duplicate boundary row
    consume ``max_records_per_run`` quota.

    Regression: with ``max_records_per_run=3`` and the inclusive-boundary
    duplicate on every continuation page, page one returns two indicators
    (cap left = 1), page two returns ``[duplicate, ind_c]``. Without the
    strip the cap-slice would keep ``[duplicate]``, the cap break would
    fire and the importer state would advance to the duplicate's marker -
    in effect, the connector would never reach ``ind_c`` despite having a
    quota slot left for it. With the strip, the duplicate is dropped
    first, the cap-slice keeps ``[ind_c]`` and the run ends with the
    expected three unique indicators.
    """
    importer = _build_importer(max_records_per_run=3)
    ind_a = _fake_indicator(0, marker="1700000001aaa0000")
    ind_b = _fake_indicator(1, marker="1700000002aaa0001")
    ind_c = _fake_indicator(2, marker="1700000003aaa0002")
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([ind_a, ind_b], total=3),
        _make_page([ind_b, ind_c], total=1),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == [ind_a, ind_b, ind_c]
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 2


def test_run_keeps_previous_marker_when_last_indicator_lacks_marker():
    """When the last accepted indicator is missing its ``_marker``
    field, the run MUST keep the previously-persisted marker rather
    than drop the state key. Dropping it would silently re-trigger the
    seconds-granularity overlap on the next run.
    """
    importer = _build_importer()
    importer._process_indicators = MagicMock(return_value=None)
    persisted_marker = "1700000005aaa0042"
    bad_indicator = {"id": "ioc-x", "last_updated": 1_700_000_000, "type": "domain"}
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([bad_indicator], total=10),
    ]

    new_state = importer.run(
        {
            "latest_indicator_timestamp": 1_700_000_000,
            "latest_indicator_marker": persisted_marker,
        }
    )

    assert new_state["latest_indicator_marker"] == persisted_marker
