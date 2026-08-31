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
from unittest.mock import MagicMock

from connectors_sdk.models import OrganizationAuthor, TLPMarking, Vulnerability
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


class TestTransformLogging:
    def _messages(self, processor):
        return [call.args[0] for call in processor.logger.info.call_args_list]

    def test_logs_nothing_to_ingest_on_empty_collection(self, processor):
        bundles = list(processor.transform(iter([])))

        assert bundles == []
        assert any(
            "Nothing to ingest" in message for message in self._messages(processor)
        )

    def test_logs_nothing_to_ingest_when_every_issue_is_unparseable(self, processor):
        bundles = list(processor.transform(iter([[{"id": "broken"}]])))

        assert bundles == []
        assert any(
            "Nothing to ingest" in message for message in self._messages(processor)
        )

    def test_stays_quiet_when_issues_are_ingested(
        self, processor, empty_description_issue_data
    ):
        bundles = list(processor.transform(iter([[empty_description_issue_data]])))

        assert len(bundles) == 1
        assert not any(
            "Nothing to ingest" in message for message in self._messages(processor)
        )

    def test_author_and_marking_ride_with_the_first_real_bundle(
        self, processor, empty_description_issue_data
    ):
        bundles = list(
            processor.transform(
                iter([[{"id": "broken"}], [empty_description_issue_data]])
            )
        )

        assert len(bundles) == 1
        assert [type(obj).__name__ for obj in bundles[0][:2]] == [
            "OrganizationAuthor",
            "TLPMarking",
        ]


class TestInterleavedVulnerabilities:
    """Issues and the vulnerabilities of their resource travel together."""

    @staticmethod
    def _enable(processor, objects_by_asset: dict[str, list]) -> MagicMock:
        """Attach a vulnerabilities processor stub returning canned objects per asset.

        Args:
            processor: The issues processor under test.
            objects_by_asset: Objects to return for each asset id.

        Returns:
            The stub, so calls can be asserted.
        """
        vulnerabilities = MagicMock()
        vulnerabilities.failures = 0
        vulnerabilities.objects_for_asset.side_effect = (
            lambda asset_id, system: objects_by_asset.get(asset_id, [])
        )
        processor._vulnerabilities = vulnerabilities
        return vulnerabilities

    def test_each_issue_becomes_its_own_bundle(
        self, processor, signin_issue_data, empty_description_issue_data
    ):
        self._enable(processor, {})

        bundles = list(
            processor.transform(
                iter([[signin_issue_data, empty_description_issue_data]])
            )
        )

        # One page, two issues, two bundles: a page-sized bundle would carry
        # every finding of every asset at once.
        assert len(bundles) == 2

    def test_vulnerabilities_ride_in_the_bundle_of_their_issue(
        self, processor, signin_issue_data, empty_description_issue_data
    ):
        marker = Vulnerability(name="CVE-2026-46333")
        self._enable(processor, {"8728411e-1a43-55a2-801e-44ffcb5a3dfa": [marker]})

        bundles = list(
            processor.transform(
                iter([[signin_issue_data, empty_description_issue_data]])
            )
        )

        assert not any(obj is marker for obj in bundles[0])
        assert any(obj is marker for obj in bundles[1])

    def test_the_vulnerabilities_processor_receives_the_system_of_the_issue(
        self, processor, empty_description_issue_data
    ):
        vulnerabilities = self._enable(processor, {})

        list(processor.transform(iter([[empty_description_issue_data]])))

        asset_id, system = vulnerabilities.objects_for_asset.call_args[0]
        assert asset_id == "8728411e-1a43-55a2-801e-44ffcb5a3dfa"
        # The relationship must point at the object already in the bundle.
        assert system.name == "tivan-eleonore-vm"

    def test_author_and_marking_ride_with_the_first_issue_bundle(
        self, processor, signin_issue_data, empty_description_issue_data
    ):
        self._enable(processor, {})

        bundles = list(
            processor.transform(
                iter([[signin_issue_data, empty_description_issue_data]])
            )
        )

        assert [type(obj).__name__ for obj in bundles[0][:2]] == [
            "OrganizationAuthor",
            "TLPMarking",
        ]
        assert not any(
            isinstance(obj, (OrganizationAuthor, TLPMarking)) for obj in bundles[1]
        )

    def test_each_bundle_is_logged_with_its_vulnerability_count(
        self, processor, signin_issue_data, empty_description_issue_data
    ):
        self._enable(
            processor,
            {
                "8728411e-1a43-55a2-801e-44ffcb5a3dfa": [
                    Vulnerability(name="CVE-2026-46333"),
                    Vulnerability(name="CVE-2026-3039"),
                ]
            },
        )

        list(
            processor.transform(
                iter([[signin_issue_data, empty_description_issue_data]])
            )
        )

        counts = {
            call.args[1]["asset"]: call.args[1]["vulnerabilities"]
            for call in processor.logger.info.call_args_list
            if "Sending an incident" in call.args[0]
        }
        assert counts == {"TA-733-INTEG-ING": 0, "tivan-eleonore-vm": 2}

    def test_the_run_totals_are_logged(
        self, processor, signin_issue_data, empty_description_issue_data
    ):
        self._enable(
            processor,
            {"8728411e-1a43-55a2-801e-44ffcb5a3dfa": [Vulnerability(name="CVE-1")]},
        )

        list(
            processor.transform(
                iter([[signin_issue_data, empty_description_issue_data]])
            )
        )

        summary = next(
            call.args[1]
            for call in processor.logger.info.call_args_list
            if "Import finished" in call.args[0]
        )
        assert summary == {"incidents": 2, "vulnerabilities": 1, "bundles": 2}

    def test_the_cursor_advances_when_every_fetch_succeeded(
        self, processor, empty_description_issue_data
    ):
        self._enable(processor, {})

        list(processor.transform(iter([[empty_description_issue_data]])))

        assert processor.state.issues_last_created_at is not None

    def test_the_cursor_is_held_back_when_a_fetch_failed(
        self, processor, empty_description_issue_data
    ):
        vulnerabilities = self._enable(processor, {})
        vulnerabilities.failures = 1

        list(processor.transform(iter([[empty_description_issue_data]])))

        # Advancing would mark those vulnerabilities as imported for good;
        # replaying is harmless because every id is deterministic.
        assert processor.state.issues_last_created_at is None
        assert processor.logger.warning.called
