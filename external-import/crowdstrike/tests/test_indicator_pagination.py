"""Tests for the CrowdStrike indicator paginated fetch logic.

These tests cover the pagination contract between
:class:`crowdstrike_feeds_services.client.indicators.IndicatorsAPI` and
:class:`crowdstrike_feeds_connector.indicator.importer.IndicatorImporter`:

* The client returns ``next_page`` as a single string token (or ``None``).
* The importer walks every page until either the upstream API runs out of
  pages or the configured ``max_records_per_run`` cap is reached.
* Pagination is robust to ``meta.pagination`` being missing or ``None``.
"""

import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# The crowdstrike connector loads its env-based configuration at import time
# (``BaseCrowdstrikeClient.__init__`` builds the pydantic-settings config),
# so provide stub environment variables before the test imports below.
os.environ.setdefault("OPENCTI_URL", "http://localhost:8080")
os.environ.setdefault("OPENCTI_TOKEN", "token")
os.environ.setdefault("CONNECTOR_ID", "ChangeMe")
os.environ.setdefault("CONNECTOR_TYPE", "EXTERNAL_IMPORT")
os.environ.setdefault("CONNECTOR_NAME", "CrowdStrike")
os.environ.setdefault("CONNECTOR_SCOPE", "crowdstrike")
os.environ.setdefault("CONNECTOR_LOG_LEVEL", "info")
os.environ.setdefault("CONNECTOR_DURATION_PERIOD", "PT30M")
os.environ.setdefault("CROWDSTRIKE_CLIENT_ID", "ChangeMe")
os.environ.setdefault("CROWDSTRIKE_CLIENT_SECRET", "ChangeMe")

from crowdstrike_feeds_connector.indicator.importer import (  # noqa: E402
    IndicatorImporter,
    IndicatorImporterConfig,
)
from crowdstrike_feeds_services.client.indicators import IndicatorsAPI  # noqa: E402


def _build_importer(*, max_records_per_run=None):
    """Build an ``IndicatorImporter`` whose API client is a ``MagicMock``.

    The :class:`IndicatorsAPI` / :class:`RelatedActorImporter` / :class:`ReportFetcher`
    classes are patched out because their constructors instantiate the
    CrowdStrike settings / falconpy client / pycti API, which would require
    real credentials at construction time.
    """
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
        exclude_types=[],
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


def _make_page(
    resources, *, next_page=None, total=None, with_pagination=True
) -> dict[str, Any]:
    page: dict[str, Any] = {"resources": resources, "next_page": next_page}
    if with_pagination:
        page["meta"] = {"pagination": {"total": total if total is not None else 0}}
    else:
        # Cover the ``meta.pagination`` is ``None`` case.
        page["meta"] = {"pagination": None}
    return page


def _fake_indicator(idx: int) -> dict[str, Any]:
    return {"id": f"ioc-{idx}", "last_updated": 1_700_000_000 + idx, "type": "domain"}


def test_pagination_walks_every_page_until_next_page_is_none():
    importer = _build_importer()
    indicators = [_fake_indicator(i) for i in range(5)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators[:2], next_page="token-1", total=5),
        _make_page(indicators[2:4], next_page="token-2", total=5),
        _make_page(indicators[4:], next_page=None, total=5),
    ]

    fetched = importer._paginated_query_indicators(limit=1000, sort="x", fql_filter="y")

    assert fetched == indicators
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 3
    call_args_list = (
        importer.indicators_api_cs.get_combined_indicator_entities.call_args_list
    )
    assert call_args_list[0].kwargs["next_page"] is None
    assert call_args_list[1].kwargs["next_page"] == "token-1"
    assert call_args_list[2].kwargs["next_page"] == "token-2"


def test_pagination_stops_when_resources_are_empty():
    importer = _build_importer()
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page([], next_page="token-1"),
    ]

    fetched = importer._paginated_query_indicators(limit=1000, sort="x", fql_filter="y")

    assert fetched == []
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 1


def test_pagination_handles_missing_pagination_metadata():
    importer = _build_importer()
    indicators = [_fake_indicator(i) for i in range(2)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators, next_page=None, with_pagination=False),
    ]

    fetched = importer._paginated_query_indicators(limit=1000, sort="x", fql_filter="y")

    assert fetched == indicators


def test_pagination_caps_total_records_per_run_within_first_page():
    importer = _build_importer(max_records_per_run=3)
    indicators = [_fake_indicator(i) for i in range(10)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators, next_page="token-1", total=10),
    ]

    fetched = importer._paginated_query_indicators(limit=1000, sort="x", fql_filter="y")

    # Only 3 indicators fetched, and no follow-up page was requested.
    assert fetched == indicators[:3]
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 1


def test_pagination_caps_total_records_per_run_across_pages():
    importer = _build_importer(max_records_per_run=3)
    indicators = [_fake_indicator(i) for i in range(6)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators[:2], next_page="token-1", total=6),
        _make_page(indicators[2:4], next_page="token-2", total=6),
        _make_page(indicators[4:], next_page=None, total=6),
    ]

    fetched = importer._paginated_query_indicators(limit=1000, sort="x", fql_filter="y")

    assert fetched == indicators[:3]
    # Should have stopped after the 2nd page (2 from page 1, 1 from page 2).
    assert importer.indicators_api_cs.get_combined_indicator_entities.call_count == 2


@pytest.mark.parametrize("disabled_value", [None, 0, -1])
def test_pagination_cap_can_be_disabled(disabled_value):
    importer = _build_importer(max_records_per_run=disabled_value)
    indicators = [_fake_indicator(i) for i in range(5)]
    importer.indicators_api_cs.get_combined_indicator_entities.side_effect = [
        _make_page(indicators[:2], next_page="token-1", total=5),
        _make_page(indicators[2:], next_page=None, total=5),
    ]

    fetched = importer._paginated_query_indicators(limit=1000, sort="x", fql_filter="y")

    assert fetched == indicators


def test_get_next_page_extracts_token_from_url():
    response = {
        "headers": {
            "Next-Page": "/intel/combined/indicators/v1?limit=1000&next_page=abc123"
        }
    }
    assert IndicatorsAPI.get_next_page(response) == "abc123"


def test_get_next_page_returns_none_when_header_missing():
    assert IndicatorsAPI.get_next_page({"headers": {}}) is None


def test_get_next_page_returns_none_when_token_missing():
    response = {"headers": {"Next-Page": "/intel/combined/indicators/v1?limit=1000"}}
    assert IndicatorsAPI.get_next_page(response) is None
