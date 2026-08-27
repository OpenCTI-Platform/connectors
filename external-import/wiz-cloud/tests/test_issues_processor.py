"""Converter tests against shapes taken from the captured tenant payload.

Covers the edge cases the sample proved real:
- empty description
- duplicated entitySnapshot across issues (System emitted once, targeted twice)
- actors: null inside threatDetectionDetails
- tags with slashes in keys

Payloads and the processor come from conftest.py fixtures; only _convert and
the models are exercised here, no I/O.
"""

from datetime import datetime, timedelta, timezone

from wiz_cloud.processors.issues_processor import _utc


class TestCursorFormatting:
    def test_keeps_microseconds(self):
        # Wiz createdAt carries microseconds and the filter is exclusive, so
        # truncating to the second re-selects the issue the cursor points at.
        dt = datetime(2025, 2, 20, 13, 27, 49, 464786, tzinfo=timezone.utc)
        assert _utc(dt) == "2025-02-20T13:27:49.464786Z"

    def test_converts_to_utc(self):
        dt = datetime(2025, 2, 20, 15, 27, 49, 1, tzinfo=timezone(timedelta(hours=2)))
        assert _utc(dt) == "2025-02-20T13:27:49.000001Z"

    def test_whole_second_has_no_fraction(self):
        dt = datetime(2025, 2, 20, 13, 27, 49, tzinfo=timezone.utc)
        assert _utc(dt) == "2025-02-20T13:27:49Z"


class TestWizIssueModel:
    def test_parses_full_issue(self, signin_issue):
        assert signin_issue.rule_name == "Wiz Sign-in from Unusual Country"
        assert signin_issue.entity_snapshot.external_id == "mlipebtwsndhxdmnzdwrxzmio"
        assert signin_issue.threat_detection_details.actors[0].type == "SERVICE_ACCOUNT"

    def test_empty_description_and_null_actors(self, empty_description_issue):
        assert empty_description_issue.description == ""
        assert empty_description_issue.threat_detection_details.actors is None
        assert empty_description_issue.entity_snapshot.tags["Wiz/wz"] == "666"


class TestConversion:
    def test_incident_name_is_rule_plus_issue_id(self, processor, signin_issue):
        objects = processor._convert(signin_issue, systems_cache={})
        incident = objects[0]
        assert incident.name == (
            "Wiz Sign-in from Unusual Country"
            " - Wiz issue 22b081f9-42d1-5b53-a504-1ddfbf28d53e"
        )

    def test_empty_description_falls_back_to_none(
        self, processor, empty_description_issue
    ):
        incident = processor._convert(empty_description_issue, systems_cache={})[0]
        assert incident.description is None
        assert incident.name == (
            "Service account token was accessed"
            " - Wiz issue 15811dfb-9cdf-539a-951f-d7961526d74d"
        )

    def test_duplicate_snapshot_yields_one_system_two_relationships(
        self, processor, empty_description_issue, duplicate_snapshot_issue
    ):
        cache = {}
        first = processor._convert(empty_description_issue, cache)
        second = processor._convert(duplicate_snapshot_issue, cache)
        # System appears in the first conversion only; both carry a relationship.
        assert len(first) == 3  # incident, system, relationship
        assert len(second) == 2  # incident, relationship
        assert len(cache) == 1
