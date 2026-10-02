"""Issue processor tests against shapes taken from the captured tenant payload.

Covers the edge cases the sample proved real:
- empty description
- duplicated entitySnapshot across issues (System emitted once, targeted twice)
- actors: null inside threatDetectionDetails
- tags with slashes in keys

The payloads and the processor come from the conftest.py fixtures. The Wiz
client is a MagicMock, so the tests make no network calls.
"""

from datetime import datetime, timedelta, timezone

import pytest
from connectors_sdk.models import (
    Incident,
    OrganizationAuthor,
    Relationship,
    System,
    TLPMarking,
    Vulnerability,
)
from pydantic import ValidationError
from wiz_client.models import WizIssue, WizVulnerabilityFinding

TIVAN_VM = "8728411e-1a43-55a2-801e-44ffcb5a3dfa"
SERVICE_ACCOUNT = "b9e464fc-4b1a-5745-8d30-366690b946b8"


def _of_type(objects: list, kind: type) -> list:
    return [item for item in objects if isinstance(item, kind)]


def _result(issue: WizIssue, vulnerabilities: list | None = None) -> dict:
    """Build one item of a collect() page, in the format transform() expects."""
    return {"issue": issue, "vulnerabilities": vulnerabilities or []}


def _enable_vulnerabilities(processor, make_config, **overrides) -> None:
    processor._config = make_config(import_vulnerabilities=True, **overrides)


class TestWizIssueModel:
    def test_parses_full_issue(self, signin_issue):
        assert signin_issue.rule_name == "Wiz Sign-in from Unusual Country"
        assert signin_issue.entity_snapshot.external_id == "mlipebtwsndhxdmnzdwrxzmio"
        assert signin_issue.threat_detection_details.actors[0].type == "SERVICE_ACCOUNT"

    def test_empty_description_and_null_actors(self, empty_description_issue):
        assert empty_description_issue.description == ""
        assert empty_description_issue.threat_detection_details.actors is None
        assert empty_description_issue.entity_snapshot.tags["Wiz/wz"] == "666"


class TestIssueConversion:
    def test_incident_name_is_rule_plus_issue_id(self, issue_converter, signin_issue):
        incident = issue_converter.convert_issue(signin_issue, systems_cache={})[0]
        assert incident.name == (
            "Wiz Sign-in from Unusual Country"
            " - Wiz issue 22b081f9-42d1-5b53-a504-1ddfbf28d53e"
        )

    def test_empty_description_falls_back_to_none(
        self, issue_converter, empty_description_issue
    ):
        incident = issue_converter.convert_issue(
            empty_description_issue, systems_cache={}
        )[0]
        assert incident.description is None
        assert incident.name == (
            "Service account token was accessed"
            " - Wiz issue 15811dfb-9cdf-539a-951f-d7961526d74d"
        )

    def test_labels_describe_the_issue_without_naming_the_source(
        self, issue_converter, signin_issue
    ):
        """The Wiz author and external reference already name the source."""
        incident = issue_converter.convert_issue(signin_issue, systems_cache={})[0]

        assert "wiz" not in incident.labels
        assert "threat-detection" in incident.labels

    def test_system_carries_the_resource_tags_as_labels(
        self, issue_converter, empty_description_issue
    ):
        system = _of_type(
            issue_converter.convert_issue(empty_description_issue, systems_cache={}),
            System,
        )[0]

        assert "Wiz/wz=666" in system.labels

    def test_duplicate_snapshot_yields_one_system_two_relationships(
        self, issue_converter, empty_description_issue, duplicate_snapshot_issue
    ):
        cache = {}
        first = issue_converter.convert_issue(empty_description_issue, cache)
        second = issue_converter.convert_issue(duplicate_snapshot_issue, cache)
        # System appears in the first conversion only; both carry a relationship.
        assert len(first) == 3  # incident, system, relationship
        assert len(second) == 2  # incident, relationship
        assert len(cache) == 1


class TestCollect:
    def test_uses_the_since_window_on_a_first_run(self, processor):
        processor._client.paginate_issues.return_value = iter([])
        before = datetime.now(tz=timezone.utc)

        list(processor.collect())

        kwargs = processor._client.paginate_issues.call_args.kwargs
        assert kwargs["severity"] == ["CRITICAL", "HIGH"]
        assert kwargs["status"] == ["OPEN", "IN_PROGRESS"]
        assert kwargs["first"] == 50
        expected = before - timedelta(days=30)
        assert abs(kwargs["created_after"] - expected) < timedelta(minutes=1)

    def test_resumes_from_the_stored_cursor(self, processor):
        cursor = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)
        processor.state.issues_last_created_at = cursor
        processor._client.paginate_issues.return_value = iter([])

        list(processor.collect())

        kwargs = processor._client.paginate_issues.call_args.kwargs
        assert kwargs["created_after"] == cursor
        assert processor.work_name == "Wiz Cloud issues import since 2026-08-01 12:00"

    def test_yields_one_result_per_issue_and_one_list_per_page(
        self, processor, signin_issue, empty_description_issue
    ):
        processor._client.paginate_issues.return_value = iter(
            [[signin_issue, empty_description_issue], [signin_issue]]
        )

        pages = list(processor.collect())

        assert [len(page) for page in pages] == [2, 1]
        assert pages[0][0]["issue"] is signin_issue
        assert pages[0][1]["issue"] is empty_description_issue

    def test_does_not_query_vulnerabilities_when_disabled(
        self, processor, empty_description_issue
    ):
        processor._client.paginate_issues.return_value = iter(
            [[empty_description_issue]]
        )

        pages = list(processor.collect())

        assert pages[0][0]["vulnerabilities"] == []
        processor._client.paginate_vulnerabilities_findings.assert_not_called()

    def test_attaches_to_each_issue_only_the_findings_of_its_own_asset(
        self,
        processor,
        make_config,
        signin_issue,
        empty_description_issue,
        vulnerability_finding,
    ):
        _enable_vulnerabilities(processor, make_config)
        processor._client.paginate_issues.return_value = iter(
            [[signin_issue, empty_description_issue]]
        )
        findings_by_asset = {TIVAN_VM: [[vulnerability_finding]]}
        processor._client.paginate_vulnerabilities_findings.side_effect = (
            lambda **kwargs: iter(findings_by_asset.get(kwargs["asset_id"], []))
        )

        results = list(processor.collect())[0]

        assert results[0]["vulnerabilities"] == []
        assert results[1]["vulnerabilities"] == [vulnerability_finding]
        # One query per issue, not one query per issue for each issue of the page.
        assert processor._client.paginate_vulnerabilities_findings.call_count == 2

    @pytest.mark.parametrize(
        ("configured", "sent"),
        [
            (True, True),
            # `hasExploit: false` returns only findings WITHOUT a known exploit.
            (False, None),
        ],
    )
    def test_passes_the_vulnerability_filters_to_the_client(
        self, processor, make_config, empty_description_issue, configured, sent
    ):
        _enable_vulnerabilities(
            processor, make_config, vulnerability_has_exploit=configured
        )
        processor._client.paginate_issues.return_value = iter(
            [[empty_description_issue]]
        )
        processor._client.paginate_vulnerabilities_findings.return_value = iter([])

        list(processor.collect())

        kwargs = processor._client.paginate_vulnerabilities_findings.call_args.kwargs
        assert kwargs["asset_id"] == TIVAN_VM
        assert kwargs["severity"] == ["CRITICAL", "HIGH"]
        assert kwargs["status"] == ["OPEN", "IN_PROGRESS"]
        assert kwargs["has_exploit"] is sent

    def test_queries_only_threat_detections(self, processor):
        processor._client.paginate_issues.return_value = iter([])

        list(processor.collect())

        kwargs = processor._client.paginate_issues.call_args.kwargs
        assert kwargs["type"] == ["THREAT_DETECTION"]

    def test_skips_the_vulnerability_query_for_an_issue_without_asset(
        self, processor, make_config, signin_issue_data
    ):
        _enable_vulnerabilities(processor, make_config)
        issue = WizIssue.model_validate({**signin_issue_data, "entitySnapshot": None})
        processor._client.paginate_issues.return_value = iter([[issue]])

        results = list(processor.collect())[0]

        assert results[0]["vulnerabilities"] == []
        processor._client.paginate_vulnerabilities_findings.assert_not_called()

    def test_queries_an_asset_once_per_page(
        self,
        processor,
        make_config,
        empty_description_issue,
        duplicate_snapshot_issue,
        vulnerability_finding,
    ):
        _enable_vulnerabilities(processor, make_config)
        processor._client.paginate_issues.return_value = iter(
            [[empty_description_issue, duplicate_snapshot_issue]]
        )
        processor._client.paginate_vulnerabilities_findings.side_effect = (
            lambda **kwargs: iter([[vulnerability_finding]])
        )

        results = list(processor.collect())[0]

        # The findings are sent with the first issue and have deterministic
        # ids. The second issue has the same asset, so it gets no findings.
        assert results[0]["vulnerabilities"] == [vulnerability_finding]
        assert results[1]["vulnerabilities"] == []
        assert processor._client.paginate_vulnerabilities_findings.call_count == 1
        assert processor.logger.debug.called

    def test_queries_an_asset_once_per_run_across_pages(
        self,
        processor,
        make_config,
        empty_description_issue,
        duplicate_snapshot_issue,
    ):
        _enable_vulnerabilities(processor, make_config)
        processor._client.paginate_issues.return_value = iter(
            [[empty_description_issue], [duplicate_snapshot_issue]]
        )
        processor._client.paginate_vulnerabilities_findings.side_effect = (
            lambda **kwargs: iter([])
        )

        list(processor.collect())

        assert processor._client.paginate_vulnerabilities_findings.call_count == 1

    def test_queries_the_asset_again_on_the_next_run(
        self, processor, make_config, empty_description_issue
    ):
        _enable_vulnerabilities(processor, make_config)
        processor._client.paginate_vulnerabilities_findings.side_effect = (
            lambda **kwargs: iter([])
        )

        for _ in range(2):
            processor._client.paginate_issues.return_value = iter(
                [[empty_description_issue]]
            )
            list(processor.collect())

        assert processor._client.paginate_vulnerabilities_findings.call_count == 2

    def test_a_client_validation_error_stops_the_run(
        self, processor, make_config, empty_description_issue
    ):
        """On purpose: the cursor is not updated, so the next run tries again."""
        _enable_vulnerabilities(processor, make_config)
        processor._client.paginate_issues.return_value = iter(
            [[empty_description_issue]]
        )

        def broken(**kwargs):
            WizVulnerabilityFinding.model_validate({"id": "broken"})
            yield []  # pragma: no cover

        processor._client.paginate_vulnerabilities_findings.side_effect = broken

        with pytest.raises(ValidationError):
            list(processor.transform(processor.collect()))
        assert processor.state.issues_last_created_at is None


class TestTransform:
    def _messages(self, processor):
        return [call.args[0] for call in processor.logger.info.call_args_list]

    def test_logs_nothing_to_ingest_on_empty_collection(self, processor):
        bundles = list(processor.transform(iter([])))

        assert bundles == []
        assert any(
            "Nothing to ingest" in message for message in self._messages(processor)
        )

    def test_stays_quiet_when_issues_are_ingested(
        self, processor, empty_description_issue
    ):
        bundles = list(processor.transform(iter([[_result(empty_description_issue)]])))

        assert len(bundles) == 1
        assert not any(
            "Nothing to ingest" in message for message in self._messages(processor)
        )

    def test_emits_one_bundle_per_page(
        self, processor, signin_issue, empty_description_issue
    ):
        bundles = list(
            processor.transform(
                iter([[_result(signin_issue), _result(empty_description_issue)]])
            )
        )

        assert len(bundles) == 1
        assert len(_of_type(bundles[0], Incident)) == 2

    def test_author_and_marking_ride_with_the_first_bundle_only(
        self, processor, signin_issue, empty_description_issue
    ):
        bundles = list(
            processor.transform(
                iter([[_result(signin_issue)], [_result(empty_description_issue)]])
            )
        )

        assert len(bundles) == 2
        assert [type(obj).__name__ for obj in bundles[0][:2]] == [
            "OrganizationAuthor",
            "TLPMarking",
        ]
        assert not any(
            isinstance(obj, (OrganizationAuthor, TLPMarking)) for obj in bundles[1]
        )

    def test_a_system_shared_by_two_pages_is_sent_once(
        self, processor, empty_description_issue, duplicate_snapshot_issue
    ):
        bundles = list(
            processor.transform(
                iter(
                    [
                        [_result(empty_description_issue)],
                        [_result(duplicate_snapshot_issue)],
                    ]
                )
            )
        )

        assert len(_of_type(bundles[0], System)) == 1
        assert _of_type(bundles[1], System) == []

    def test_the_cursor_advances_to_the_newest_issue(
        self, processor, empty_description_issue, duplicate_snapshot_issue
    ):
        list(
            processor.transform(
                iter(
                    [
                        [
                            _result(empty_description_issue),
                            _result(duplicate_snapshot_issue),
                        ]
                    ]
                )
            )
        )

        assert (
            processor.state.issues_last_created_at == empty_description_issue.created_at
        )

    def test_the_cursor_stays_put_when_nothing_was_collected(self, processor):
        list(processor.transform(iter([])))

        assert processor.state.issues_last_created_at is None


class TestTransformWithVulnerabilities:
    """An issue and the vulnerabilities of its asset are sent in the same bundle."""

    def test_vulnerabilities_ride_in_the_bundle_of_their_issue(
        self, processor, make_config, empty_description_issue, vulnerability_finding
    ):
        _enable_vulnerabilities(processor, make_config)

        bundles = list(
            processor.transform(
                iter([[_result(empty_description_issue, [vulnerability_finding])]])
            )
        )

        assert len(bundles) == 1
        vulnerabilities = _of_type(bundles[0], Vulnerability)
        assert [v.name for v in vulnerabilities] == ["CVE-2026-46333"]

    def test_the_has_relationship_points_at_the_system_of_the_issue(
        self, processor, make_config, empty_description_issue, vulnerability_finding
    ):
        _enable_vulnerabilities(processor, make_config)

        bundle = list(
            processor.transform(
                iter([[_result(empty_description_issue, [vulnerability_finding])]])
            )
        )[0]

        system = _of_type(bundle, System)[0]
        has = [r for r in _of_type(bundle, Relationship) if r.type == "has"]
        assert len(has) == 1
        # The same System object as in the bundle, not a copy.
        assert has[0].source is system
        assert has[0].target.name == "CVE-2026-46333"

    def test_skips_a_finding_without_a_cve_id(
        self,
        processor,
        make_config,
        empty_description_issue,
        vulnerability_finding_data,
    ):
        _enable_vulnerabilities(processor, make_config)
        nameless = WizVulnerabilityFinding.model_validate(
            {**vulnerability_finding_data, "name": ""}
        )

        bundle = list(
            processor.transform(iter([[_result(empty_description_issue, [nameless])]]))
        )[0]

        assert _of_type(bundle, Vulnerability) == []
        assert processor.logger.warning.called

    def test_skips_a_finding_rejected_by_the_model(
        self,
        processor,
        make_config,
        empty_description_issue,
        vulnerability_finding,
        second_asset_finding_data,
    ):
        """A rejected finding is skipped. The incident and the other findings are kept."""
        _enable_vulnerabilities(processor, make_config)
        rejected = WizVulnerabilityFinding.model_validate(
            {**second_asset_finding_data, "id": "rejected"}
        )
        convert = processor._vulnerability_converter.convert_vulnerability

        def fail_on_the_rejected(finding, system):
            if finding.id == "rejected":
                raise ValidationError.from_exception_data("Vulnerability", [])
            return convert(finding, system)

        processor._vulnerability_converter.convert_vulnerability = fail_on_the_rejected

        bundles = list(
            processor.transform(
                iter(
                    [
                        [
                            _result(
                                empty_description_issue,
                                [rejected, vulnerability_finding],
                            )
                        ]
                    ]
                )
            )
        )

        assert len(bundles) == 1
        assert len(_of_type(bundles[0], Incident)) == 1
        assert [v.name for v in _of_type(bundles[0], Vulnerability)] == [
            "CVE-2026-46333"
        ]
        assert processor.logger.warning.called
        summary = next(
            call.args[1]
            for call in processor.logger.info.call_args_list
            if "Import finished" in call.args[0]
        )
        assert summary["vulnerabilities"] == 1
        assert processor.state.issues_last_created_at is not None

    def test_ignores_findings_when_the_import_is_disabled(
        self, processor, empty_description_issue, vulnerability_finding
    ):
        bundle = list(
            processor.transform(
                iter([[_result(empty_description_issue, [vulnerability_finding])]])
            )
        )[0]

        assert _of_type(bundle, Vulnerability) == []

    def test_each_incident_is_logged_with_its_vulnerability_count(
        self,
        processor,
        make_config,
        signin_issue,
        empty_description_issue,
        vulnerability_finding,
        second_asset_finding_data,
    ):
        _enable_vulnerabilities(processor, make_config)
        second = WizVulnerabilityFinding.model_validate(second_asset_finding_data)

        list(
            processor.transform(
                iter(
                    [
                        [
                            _result(signin_issue),
                            _result(
                                empty_description_issue,
                                [vulnerability_finding, second],
                            ),
                        ]
                    ]
                )
            )
        )

        counts = {
            call.args[1]["asset"]: call.args[1]["vulnerabilities"]
            for call in processor.logger.info.call_args_list
            if "Sending an incident" in call.args[0]
        }
        assert counts == {"TA-733-INTEG-ING": 0, "tivan-eleonore-vm": 2}

    def test_the_run_totals_are_logged(
        self,
        processor,
        make_config,
        signin_issue,
        empty_description_issue,
        vulnerability_finding,
    ):
        _enable_vulnerabilities(processor, make_config)

        list(
            processor.transform(
                iter(
                    [
                        [_result(signin_issue)],
                        [_result(empty_description_issue, [vulnerability_finding])],
                    ]
                )
            )
        )

        summary = next(
            call.args[1]
            for call in processor.logger.info.call_args_list
            if "Import finished" in call.args[0]
        )
        assert summary == {"incidents": 2, "vulnerabilities": 1, "bundles": 2}

    def test_collect_output_feeds_transform(
        self, processor, make_config, empty_description_issue, vulnerability_finding
    ):
        """collect() then transform(), with only the Wiz client faked."""
        _enable_vulnerabilities(processor, make_config)
        processor._client.paginate_issues.return_value = iter(
            [[empty_description_issue]]
        )
        processor._client.paginate_vulnerabilities_findings.return_value = iter(
            [[vulnerability_finding]]
        )

        bundles = list(processor.transform(processor.collect()))

        assert len(bundles) == 1
        assert len(_of_type(bundles[0], Incident)) == 1
        assert len(_of_type(bundles[0], Vulnerability)) == 1
        assert processor.state.issues_last_created_at is not None
