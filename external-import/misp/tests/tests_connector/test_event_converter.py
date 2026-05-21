from datetime import datetime, timezone
from unittest.mock import MagicMock

import pycti
import pytest
import stix2
from api_client.models import EventRestSearchListItem
from connector.use_cases.convert_event import (
    DEFAULT_THREAT_LEVEL_SCORE_MAPPING,
    EventConverter,
    event_threat_level_to_opencti_score,
)


@pytest.mark.parametrize(
    "threat_level, expected",
    [
        ("1", 90),
        ("2", 60),
        ("3", 30),
        ("4", 50),
    ],
)
def test_event_threat_level_to_opencti_score_default_mapping(threat_level, expected):
    """When called without an explicit mapping, the function reproduces the
    legacy hard-coded behavior (1=90, 2=60, 3=30, 4=50) so upgrading users
    who do not configure ``MISP_THREAT_LEVEL_SCORE_MAPPING`` keep getting
    identical scores.
    """
    assert event_threat_level_to_opencti_score(threat_level) == expected


def test_event_threat_level_to_opencti_score_unknown_value_falls_back_to_level_4():
    """MISP can return a ``threat_level_id`` outside ``[1, 4]`` (older
    instances, custom forks). Such values must resolve to the score
    associated with level ``"4"`` (Undefined) rather than raising.
    """
    assert event_threat_level_to_opencti_score("5") == 50
    assert event_threat_level_to_opencti_score("99") == 50


def test_event_threat_level_to_opencti_score_uses_custom_mapping():
    """The function honors the mapping provided by the caller, both for
    known levels and for the fallback (level ``"4"``).
    """
    mapping = {"1": 100, "2": 70, "3": 40, "4": 10}
    assert event_threat_level_to_opencti_score("1", mapping) == 100
    assert event_threat_level_to_opencti_score("2", mapping) == 70
    assert event_threat_level_to_opencti_score("3", mapping) == 40
    assert event_threat_level_to_opencti_score("4", mapping) == 10
    # Unknown threat-level resolves to the "Undefined" score.
    assert event_threat_level_to_opencti_score("foo", mapping) == 10


def test_default_threat_level_score_mapping_matches_legacy_behavior():
    """The module-level default mapping must mirror the historic
    hard-coded values so the behavior is preserved when no override
    is supplied at runtime.
    """
    assert DEFAULT_THREAT_LEVEL_SCORE_MAPPING == {
        "1": 90,
        "2": 60,
        "3": 30,
        "4": 50,
    }


def _make_author() -> stix2.Identity:
    return stix2.Identity(
        id=pycti.Identity.generate_id(
            name="Test Author", identity_class="organization"
        ),
        name="Test Author",
        identity_class="organization",
    )


def test_create_report_uses_publish_timestamp_for_created_and_published():
    converter = EventConverter(
        logger=MagicMock(),
        external_reference_base_url="https://misp.test",
    )
    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "info": "Test Event",
                "date": "2024-11-27",
                "timestamp": str(
                    int(
                        datetime(
                            2024, 12, 5, 6, 31, 34, tzinfo=timezone.utc
                        ).timestamp()
                    )
                ),
                "publish_timestamp": str(
                    int(
                        datetime(2024, 12, 5, 6, 30, 0, tzinfo=timezone.utc).timestamp()
                    )
                ),
            }
        }
    )

    author = _make_author()
    report = converter.create_report(
        event=event,
        labels=[],
        object_refs=[author.id],
        author=author,
        markings=[],
        external_references=[],
        associated_files=[],
    )

    assert report.created == datetime(2024, 12, 5, 6, 30, 0, tzinfo=timezone.utc)
    assert report.published == datetime(2024, 12, 5, 6, 30, 0, tzinfo=timezone.utc)
    assert report.modified == datetime(2024, 12, 5, 6, 31, 34, tzinfo=timezone.utc)


def test_create_report_falls_back_to_event_date_when_publish_timestamp_missing():
    converter = EventConverter(
        logger=MagicMock(),
        external_reference_base_url="https://misp.test",
    )
    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "info": "Test Event",
                "date": "2024-11-27",
                "timestamp": str(
                    int(
                        datetime(
                            2024, 12, 5, 6, 31, 34, tzinfo=timezone.utc
                        ).timestamp()
                    )
                ),
                "publish_timestamp": "0",
            }
        }
    )

    author = _make_author()
    report = converter.create_report(
        event=event,
        labels=[],
        object_refs=[author.id],
        author=author,
        markings=[],
        external_references=[],
        associated_files=[],
    )

    assert report.created == datetime(2024, 11, 27, 0, 0, 0, tzinfo=timezone.utc)
    assert report.published == datetime(2024, 11, 27, 0, 0, 0, tzinfo=timezone.utc)
