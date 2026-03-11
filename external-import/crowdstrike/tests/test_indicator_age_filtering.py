from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from crowdstrike_feeds_connector.indicator.importer import (
    IndicatorImporter,
    IndicatorImporterConfig,
)


def test_is_indicator_too_old():
    mock_config = MagicMock()
    mock_helper = MagicMock()

    age_config = {
        "ip": timedelta(days=90),
        "domain": timedelta(days=365),
        "url": timedelta(days=60),
        "hash": timedelta(days=730),
        "default": timedelta(days=30),
    }

    config = IndicatorImporterConfig(
        config=mock_config,
        helper=mock_helper,
        author=MagicMock(),
        default_latest_timestamp=0,
        tlp_marking=MagicMock(),
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
        indicator_max_age_by_type=age_config,
        no_file_trigger_import=True,
        scopes=set(["indicator"]),
        attack_lookup=None,
    )

    importer = IndicatorImporter(config)

    now_ts = int(datetime.now(timezone.utc).timestamp())

    test_cases = [
        ("ip_address", 10, False),
        ("ip_address", 100, True),
        ("ip_address_block", 89, False),
        ("ip_address_block", 91, True),
        ("domain", 100, False),
        ("domain", 400, True),
        ("url", 10, False),
        ("url", 70, True),
        ("hash_md5", 100, False),
        ("hash_md5", 800, True),
        ("hash_sha1", 100, False),
        ("hash_sha1", 800, True),
        ("hash_sha256", 100, False),
        ("hash_sha256", 800, True),
        ("registry", 10, False),
        ("registry", 40, True),
        ("mutex_name", 10, False),
        ("mutex_name", 40, True),
    ]

    for status_type, days_ago, expected in test_cases:
        published_date = now_ts - (days_ago * 24 * 60 * 60)
        indicator = {
            "id": f"indicator-{status_type}-{days_ago}",
            "type": status_type,
            "published_date": published_date,
        }
        assert (
            importer._is_indicator_too_old(indicator) == expected
        ), f"Failed for {status_type} published {days_ago} days ago"


def test_is_indicator_too_old_missing_published_date():
    age_config = {
        "ip": timedelta(days=90),
        "default": timedelta(days=30),
    }

    config = IndicatorImporterConfig(
        config=MagicMock(),
        helper=MagicMock(),
        author=MagicMock(),
        default_latest_timestamp=0,
        tlp_marking=MagicMock(),
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
        indicator_max_age_by_type=age_config,
        no_file_trigger_import=True,
        scopes=set(["indicator"]),
        attack_lookup=None,
    )

    importer = IndicatorImporter(config)

    indicator = {
        "id": "no-date-indicator",
        "type": "ip_address",
    }
    assert not importer._is_indicator_too_old(indicator)


def test_is_indicator_too_old_no_config():
    config = IndicatorImporterConfig(
        config=MagicMock(),
        helper=MagicMock(),
        author=MagicMock(),
        default_latest_timestamp=0,
        tlp_marking=MagicMock(),
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
        indicator_max_age_by_type={
            "ip": None,
            "domain": None,
            "url": None,
            "hash": None,
            "default": None,
        },
        no_file_trigger_import=True,
        scopes=set(["indicator"]),
        attack_lookup=None,
    )

    importer = IndicatorImporter(config)
    now_ts = int(datetime.now(timezone.utc).timestamp())

    indicator = {
        "id": "old-ip",
        "type": "ip_address",
        "published_date": now_ts - (1000 * 24 * 60 * 60),
    }
    assert not importer._is_indicator_too_old(indicator)


def test_is_indicator_too_old_fallback_to_default():
    age_config = {"default": timedelta(days=30)}

    config = IndicatorImporterConfig(
        config=MagicMock(),
        helper=MagicMock(),
        author=MagicMock(),
        default_latest_timestamp=0,
        tlp_marking=MagicMock(),
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
        indicator_max_age_by_type=age_config,
        no_file_trigger_import=True,
        scopes=set(["indicator"]),
        attack_lookup=None,
    )

    importer = IndicatorImporter(config)
    now_ts = int(datetime.now(timezone.utc).timestamp())

    indicator_recent = {
        "id": "recent-ip",
        "type": "ip_address",
        "published_date": now_ts - (10 * 24 * 60 * 60),
    }
    indicator_old = {
        "id": "old-ip",
        "type": "ip_address",
        "published_date": now_ts - (40 * 24 * 60 * 60),
    }

    assert not importer._is_indicator_too_old(indicator_recent)
    assert importer._is_indicator_too_old(indicator_old)


def test_is_indicator_too_old_exact_boundary():
    """Test that an indicator published exactly at the threshold is NOT filtered.

    The comparison uses strict '<', so published_date == (now - threshold) is not too old.
    Uses mocked time to avoid flakiness from clock drift between test and method.
    """
    fixed_now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    age_config = {
        "ip": timedelta(days=90),
        "default": timedelta(days=30),
    }

    config = IndicatorImporterConfig(
        config=MagicMock(),
        helper=MagicMock(),
        author=MagicMock(),
        default_latest_timestamp=0,
        tlp_marking=MagicMock(),
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
        indicator_max_age_by_type=age_config,
        no_file_trigger_import=True,
        scopes=set(["indicator"]),
        attack_lookup=None,
    )

    importer = IndicatorImporter(config)

    exactly_at_threshold = fixed_now - timedelta(days=90)
    exactly_at_threshold_ts = int(exactly_at_threshold.timestamp())

    one_second_past = fixed_now - timedelta(days=90, seconds=1)
    one_second_past_ts = int(one_second_past.timestamp())

    with patch(
        "crowdstrike_feeds_connector.indicator.importer.datetime"
    ) as mock_datetime:
        mock_datetime.now.return_value = fixed_now
        mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

        indicator_at_boundary = {
            "id": "boundary-ip",
            "type": "ip_address",
            "published_date": exactly_at_threshold_ts,
        }
        assert not importer._is_indicator_too_old(indicator_at_boundary)

        indicator_past_boundary = {
            "id": "past-boundary-ip",
            "type": "ip_address",
            "published_date": one_second_past_ts,
        }
        assert importer._is_indicator_too_old(indicator_past_boundary)