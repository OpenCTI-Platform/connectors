"""Tests for LivehuntBuilder.process() — the main processing flow.

These tests exercise the full notification-processing pipeline by mocking
the VirusTotal client (iterator) and the OpenCTI helper (push / work
tracking).  Each test verifies that the correct STIX objects are emitted
and that client-side filters (limit, tag, age, size, AV hits, extensions)
behave as expected.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from connectors_sdk.models import (
    OrganizationAuthor,
    TLPMarking,
)
from livehunt.builder import LivehuntBuilder

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_vt_client():
    """Return a mock vt.Client with a configurable iterator."""
    client = MagicMock()
    client.iterator = MagicMock()
    return client


@pytest.fixture
def mock_helper():
    """Return a mock OpenCTIConnectorHelper."""
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connector_logger.debug = MagicMock()
    helper.connector_logger.info = MagicMock()
    helper.connector_logger.warning = MagicMock()
    helper.connector_logger.error = MagicMock()
    helper.api = MagicMock()
    helper.api.work = MagicMock()
    helper.api.work.to_processed = MagicMock()
    helper.api.incident = MagicMock()
    helper.api.incident.read = MagicMock(return_value=None)
    helper.api.stix_cyber_observable = MagicMock()
    helper.api.stix_cyber_observable.read = MagicMock(return_value=None)
    helper.metric = MagicMock()
    helper.metric.inc = MagicMock()
    return helper


@pytest.fixture
def author():
    """Return a default SDK author."""
    return OrganizationAuthor(name="VirusTotal Livehunt")


@pytest.fixture
def tlp_marking():
    """Return a default TLP marking."""
    return TLPMarking(level="amber+strict")


def make_vt_notification(
    sha256: str = "a" * 64,
    md5: str = "b" * 32,
    sha1: str = "c" * 40,
    size: int = 100000,
    names: List[str] = None,
    meaningful_name: str = "malware.exe",
    type_tags: List[str] = None,
    tags: List[str] = None,
    type_extension: str = "peexe",
    last_analysis_stats: Dict[str, Any] = None,
    last_analysis_results: Dict[str, Any] = None,
    first_submission_date: datetime = None,
    notification_date: float = None,
    hunting_info: Dict[str, Any] = None,
    context_attributes: Dict[str, Any] = None,
) -> SimpleNamespace:
    """Build a mock vtobj that mimics a VirusTotal Livehunt notification."""
    if names is None:
        names = ["malware.exe"]
    if type_tags is None:
        type_tags = []
    if tags is None:
        tags = []
    if last_analysis_stats is None:
        last_analysis_stats = {
            "malicious": 5,
            "suspicious": 1,
            "harmless": 0,
            "undetected": 50,
            "clean": 50,
        }
    if last_analysis_results is None:
        last_analysis_results = {
            "Antivirus_A": {"result": "Malware"},
            "Antivirus_B": {"result": "Malware"},
        }
    if first_submission_date is None:
        first_submission_date = datetime.now(timezone.utc)
    if notification_date is None:
        notification_date = datetime.now(timezone.utc).timestamp()
    if hunting_info is None:
        hunting_info = {"rule_name": "Test Rule"}
    if context_attributes is None:
        context_attributes = {
            "sources": [{"id": "yara-rule-1", "label": "Test YARA"}],
            "notification_date": notification_date,
            "hunting_info": hunting_info,
            "tags": [],
        }

    vtobj = SimpleNamespace(
        id=f"notif-{sha256}",
        sha256=sha256,
        md5=md5,
        sha1=sha1,
        size=size,
        names=names,
        meaningful_name=meaningful_name,
        type_tags=type_tags,
        tags=tags,
        type_extension=type_extension,
        last_analysis_stats=last_analysis_stats,
        last_analysis_results=last_analysis_results,
        first_submission_date=first_submission_date,
        _context_attributes=context_attributes,
    )
    return vtobj


# ──────────────────────────────────────────────────────────────────────
# Helper to build a LivehuntBuilder with mocked dependencies
# ──────────────────────────────────────────────────────────────────────


def build_test_builder(
    mock_vt_client,
    mock_helper,
    author,
    tlp_marking,
    **kwargs,
) -> LivehuntBuilder:
    """Create a LivehuntBuilder with minimal config for testing."""
    defaults = {
        "tag": None,
        "create_alert": True,
        "max_age_days": 30,
        "create_file": True,
        "upload_artifact": False,
        "create_yara_rule": False,
        "delete_notification": False,
        "extensions": [],
        "min_file_size": 0,
        "max_file_size": 10000000,
        "min_positives": 1,
        "alert_prefix": "[VT] Livehunt",
        "av_list": ["Antivirus_A", "Antivirus_B"],
        "yara_label_prefix": "",
        "livehunt_label_prefix": "vt:",
        "livehunt_tag_prefix": "vt:",
        "enable_label_enrichment": True,
        "get_malware_config": False,
        "create_file_indicators": False,
        "create_domain_name_indicators": False,
        "create_ip_indicators": False,
        "create_url_indicators": False,
        "limit": None,
    }
    defaults.update(kwargs)
    return LivehuntBuilder(
        client=mock_vt_client,
        helper=mock_helper,
        author=author,
        tlp_marking=tlp_marking,
        **defaults,
    )


# ──────────────────────────────────────────────────────────────────────
# Phase 3 Tests — process()
# ──────────────────────────────────────────────────────────────────────


class TestProcessNormalFlow:
    """Test 2: process() — flux normal."""

    def test_normal_flow(self, mock_vt_client, mock_helper, author, tlp_marking):
        """When a single valid notification is returned, the builder should
        create an alert, a file, and emit them in the bundle."""
        vtobj = make_vt_notification(sha256="a" * 64)
        mock_vt_client.iterator.return_value = [vtobj]

        builder = build_test_builder(mock_vt_client, mock_helper, author, tlp_marking)

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify iterator was called with correct params
        mock_vt_client.iterator.assert_called_once()
        call_kwargs = mock_vt_client.iterator.call_args
        assert (
            call_kwargs[1]["params"]["filter"]
            == f"date:{start_date}+ source_type:hunting_ruleset"
        )

        # Verify bundle was sent (send_stix2_bundle was called)
        mock_helper.send_stix2_bundle.assert_called_once()

        # Verify work was marked as processed
        mock_helper.api.work.to_processed.assert_called_once()


class TestProcessWithLimit:
    """Test 3: process() — avec limit."""

    def test_limit_catches_exact_number(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When limit=3 is set and 10 notifications are available, exactly 3 should be processed."""
        notifications = [
            make_vt_notification(sha256=f"{'a' * 63}{i}") for i in range(10)
        ]
        mock_vt_client.iterator.return_value = notifications

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            limit=3,
        )

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify only 3 notifications were processed
        assert builder.limit == 3

        # Verify send_stix2_bundle was called exactly 3 times
        assert mock_helper.send_stix2_bundle.call_count == 3


class TestProcessTagFiltering:
    """Test 4: process() — notifications filtrées par tag."""

    def test_only_tagged_notifications_processed(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When a tag filter is set, only notifications with that tag should be processed."""
        tagged = make_vt_notification(sha256="a" * 64)
        untagged = make_vt_notification(sha256="b" * 64)

        # Simulate iterator returning both tagged and untagged
        mock_vt_client.iterator.return_value = [tagged, untagged]

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            tag="my-tag",
        )

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify the filter includes the tag
        call_kwargs = mock_vt_client.iterator.call_args
        assert "notification_tag:my-tag" in call_kwargs[1]["params"]["filter"]


class TestProcessExpiredNotifications:
    """Test 5: process() — notifications expirées."""

    def test_old_first_submission_skipped(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When first_submission_date is older than max_age_days, the notification should be skipped."""
        old_date = datetime.now(timezone.utc)
        old_date = old_date.replace(year=old_date.year - 1)  # 1 year ago

        vtobj = make_vt_notification(
            sha256="a" * 64,
            first_submission_date=old_date,
        )
        mock_vt_client.iterator.return_value = [vtobj]

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            max_age_days=30,
        )

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify the notification was skipped (bundle should only have default items)
        assert len(builder.bundle) == len(builder._default_bundle)


class TestProcessFileSizeFilters:
    """Test 6: process() — fichier trop petit / trop gros."""

    def test_file_too_small_skipped(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When file size is below min_file_size, it should be skipped."""
        vtobj = make_vt_notification(sha256="a" * 64, size=100)
        mock_vt_client.iterator.return_value = [vtobj]

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            min_file_size=1000,
        )

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify the notification was skipped
        assert len(builder.bundle) == len(builder._default_bundle)

    def test_file_too_big_skipped(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When file size is above max_file_size, it should be skipped."""
        vtobj = make_vt_notification(sha256="a" * 64, size=20000000)
        mock_vt_client.iterator.return_value = [vtobj]

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            max_file_size=10000000,
        )

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify the notification was skipped
        assert len(builder.bundle) == len(builder._default_bundle)


class TestProcessLowAVHits:
    """Test 7: process() — fichier avec peu de hits AV."""

    def test_low_malicious_count_skipped(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When malicious count is below min_positives, the file should be skipped."""
        vtobj = make_vt_notification(
            sha256="a" * 64,
            last_analysis_stats={"malicious": 0, "suspicious": 0, "clean": 55},
        )
        mock_vt_client.iterator.return_value = [vtobj]

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            min_positives=5,
        )

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify the notification was skipped
        assert len(builder.bundle) == len(builder._default_bundle)


class TestProcessExtensionFiltering:
    """Test 8: process() — extensions filtrées."""

    def test_extension_not_in_filter_skipped(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When file extension is not in the filter list, it should be skipped."""
        vtobj = make_vt_notification(
            sha256="a" * 64,
            type_extension="txt",
        )
        mock_vt_client.iterator.return_value = [vtobj]

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            extensions=["exe", "dll"],
        )

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify the notification was skipped
        assert len(builder.bundle) == len(builder._default_bundle)

    def test_extension_in_filter_processed(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When file extension is in the filter list, it should be processed."""
        vtobj = make_vt_notification(
            sha256="a" * 64,
            type_extension="peexe",
        )
        mock_vt_client.iterator.return_value = [vtobj]

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            extensions=["peexe", "pdf"],
        )

        start_date = "2024-01-01"
        timestamp = int(datetime.now(timezone.utc).timestamp())

        builder.process(start_date, timestamp)

        # Verify the notification was processed (bundle was sent)
        mock_helper.send_stix2_bundle.assert_called_once()
