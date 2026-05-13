"""Tests for report importer created_date FQL filter."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from crowdstrike_feeds_connector.report.importer import ReportImporter


@pytest.fixture
def report_importer():
    """Create a ReportImporter with mocked dependencies."""
    mock_config = MagicMock()
    mock_helper = MagicMock()
    mock_author = MagicMock()
    mock_tlp = MagicMock()

    # Set a known default_latest_timestamp (e.g., 2025-01-01 00:00:00 UTC)
    default_ts = int(datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp())

    with patch("crowdstrike_feeds_connector.report.importer.ReportsAPI"), patch(
        "crowdstrike_feeds_connector.report.importer.IndicatorsAPI"
    ):
        importer = ReportImporter(
            config=mock_config,
            helper=mock_helper,
            author=mock_author,
            default_latest_timestamp=default_ts,
            tlp_marking=mock_tlp,
            include_types=[],
            target_industries=[],
            report_status=0,
            report_type="threat-report",
            guess_malware=False,
            report_guess_relations=False,
            indicator_config={},
            no_file_trigger_import=True,
            scopes=set(),
        )
    return importer


def test_fetch_reports_includes_created_date_filter(report_importer):
    """The FQL filter must include created_date to exclude old reports."""
    start_timestamp = int(datetime(2025, 4, 1, tzinfo=timezone.utc).timestamp())

    with patch("crowdstrike_feeds_connector.report.importer.paginate") as mock_paginate:
        mock_paginated_fn = MagicMock(return_value=iter([]))
        mock_paginate.return_value = mock_paginated_fn

        # Exhaust the generator
        list(report_importer._fetch_reports(start_timestamp))

        mock_paginated_fn.assert_called_once()
        call_kwargs = mock_paginated_fn.call_args[1]
        fql_filter = call_kwargs["fql_filter"]

        # Must filter by last_modified_date (pagination cursor)
        assert f"last_modified_date:>{start_timestamp}" in fql_filter
        # Must also filter by created_date using the configured start timestamp
        assert f"created_date:>{report_importer.default_latest_timestamp}" in fql_filter


def test_fetch_reports_created_date_filter_uses_configured_timestamp(report_importer):
    """created_date filter should use default_latest_timestamp, not the advancing cursor."""
    # Simulate the cursor having advanced well past the configured timestamp
    advancing_cursor = int(datetime(2025, 5, 1, tzinfo=timezone.utc).timestamp())

    with patch("crowdstrike_feeds_connector.report.importer.paginate") as mock_paginate:
        mock_paginated_fn = MagicMock(return_value=iter([]))
        mock_paginate.return_value = mock_paginated_fn

        list(report_importer._fetch_reports(advancing_cursor))

        call_kwargs = mock_paginated_fn.call_args[1]
        fql_filter = call_kwargs["fql_filter"]

        # The created_date filter must use the original configured timestamp,
        # not the advancing pagination cursor.
        assert f"created_date:>{report_importer.default_latest_timestamp}" in fql_filter
        # The last_modified_date filter uses the advancing cursor
        assert f"last_modified_date:>{advancing_cursor}" in fql_filter


def test_fetch_reports_includes_type_and_industry_filters():
    """FQL filter should combine created_date with type and target_industries."""
    mock_config = MagicMock()
    mock_helper = MagicMock()

    default_ts = int(datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp())

    with patch("crowdstrike_feeds_connector.report.importer.ReportsAPI"), patch(
        "crowdstrike_feeds_connector.report.importer.IndicatorsAPI"
    ):
        importer = ReportImporter(
            config=mock_config,
            helper=mock_helper,
            author=MagicMock(),
            default_latest_timestamp=default_ts,
            tlp_marking=MagicMock(),
            include_types=["notice", "tipper"],
            target_industries=["technology"],
            report_status=0,
            report_type="threat-report",
            guess_malware=False,
            report_guess_relations=False,
            indicator_config={},
            no_file_trigger_import=True,
            scopes=set(),
        )

    start_ts = int(datetime(2025, 3, 1, tzinfo=timezone.utc).timestamp())

    with patch("crowdstrike_feeds_connector.report.importer.paginate") as mock_paginate:
        mock_paginated_fn = MagicMock(return_value=iter([]))
        mock_paginate.return_value = mock_paginated_fn

        list(importer._fetch_reports(start_ts))

        call_kwargs = mock_paginated_fn.call_args[1]
        fql_filter = call_kwargs["fql_filter"]

        assert f"last_modified_date:>{start_ts}" in fql_filter
        assert f"created_date:>{default_ts}" in fql_filter
        assert "type:['notice', 'tipper']" in fql_filter
        assert "target_industries:['technology']" in fql_filter
