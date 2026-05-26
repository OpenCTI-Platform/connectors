"""Tests for the CrowdStrike indicator paginated fetch logic.

These tests cover the pagination contract between
:class:`crowdstrike_feeds_services.client.indicators.IndicatorsAPI` and
:class:`crowdstrike_feeds_connector.indicator.importer.IndicatorImporter`:

* The importer drives marker-based deep pagination using the ``_marker``
  field carried by each indicator (the FQL clause ``_marker:>='...'``),
  per CrowdStrike's documented ``QueryIntelIndicatorEntities`` contract.
* Pagination stops cleanly when the API returns an empty page, when
  ``meta.pagination.total`` reaches ``0``, when the marker fails to
  advance, or when ``max_records_per_run`` is reached.
* Pagination is robust to ``meta.pagination`` being missing or ``None``.
* ``exclude_types`` and the FQL marker clause are combined correctly.
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


def test_pagination_walks_every_page_until_total_is_zero():
    importer = _build_importer()
    indicators = [_fake_indicator(i) for i in range(5)]
    # ``total`` is the *remaining* past the current marker. The last
    # page reports 0 so the loop stops cleanly.
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators[:2], total=3),
        _make_page(indicators[2:4], total=1),
        _make_page(indicators[4:], total=0),
    ]

    fetched = importer._paginated_query_indicators(
        limit=1000, fetch_timestamp=1_700_000_000
    )

    assert fetched == indicators
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 3
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
        _make_page(indicators[:2], total=3),
        _make_page(indicators[2:], total=0),
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
        _make_page(indicators, total=0),
    ]

    importer._paginated_query_indicators(limit=1000, fetch_timestamp=1_700_000_000)

    call_kwargs = (
        importer.indicators_api_cs.get_combined_indicator_entities.call_args.kwargs
    )
    assert (
        call_kwargs["fql_filter"]
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
        _make_page(indicators, total=0),
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
