"""Converter tests against shapes taken from the captured tenant payload.

Covers the edge cases the sample proved real:
- empty description
- duplicated entitySnapshot across issues (entity reused, emitted in both bundles)
- actors: null inside threatDetectionDetails
- tags with slashes in keys

Payloads and the processor come from conftest.py fixtures; only _convert and
the models are exercised here, no I/O.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from connectors_sdk.models import (
    AttackPattern,
    Incident,
    OrganizationAuthor,
    Relationship,
    Software,
    System,
    TLPMarking,
    UserAccount,
    Vulnerability,
)
from connectors_sdk.models.enums import RelationshipType
from wiz_cloud.models import WizIssue
from wiz_cloud.observables import Credential
from wiz_cloud.processors import WizIssuesProcessor
from wiz_cloud.processors.issues_processor import _utc
from wiz_cloud.settings import WizCloudConfig


def _of_type(objects: list, kind: type) -> list:
    return [item for item in objects if isinstance(item, kind)]


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

    def test_rule_name_is_none_without_a_named_rule(self, signin_issue_data):
        signin_issue_data["sourceRules"] = [{"name": None}, {}]
        issue = WizIssue.model_validate(signin_issue_data)

        assert issue.rule_name is None

    def test_empty_description_and_null_actors(self, empty_description_issue):
        assert empty_description_issue.description == ""
        assert empty_description_issue.threat_detection_details.actors is None
        assert empty_description_issue.entity_snapshot.tags["Wiz/wz"] == "666"


class TestConversion:
    def test_incident_name_is_rule_plus_issue_id(self, processor, signin_issue):
        objects = processor._convert(signin_issue, entities_cache={})
        incident = objects[0]
        assert incident.name == (
            "Wiz Sign-in from Unusual Country"
            " - Wiz issue 22b081f9-42d1-5b53-a504-1ddfbf28d53e"
        )

    def test_empty_description_keeps_only_the_resource_summary(
        self, processor, empty_description_issue
    ):
        incident = processor._convert(empty_description_issue, entities_cache={})[0]
        assert incident.description == (
            "**Affected resource**\n"
            "\n"
            "- Name: tivan-eleonore-vm\n"
            "- Type: VIRTUAL_MACHINE\n"
            "- Cloud platform: AWS\n"
            "- Region: us-east-2\n"
            "- Provider ID: arn:aws:ec2:us-east-2:998231069301:instance/i-038b4a2cfb0c1f036\n"
            "- External ID: i-038b4a2cfb0c1f036"
        )
        assert incident.name == (
            "Service account token was accessed"
            " - Wiz issue 15811dfb-9cdf-539a-951f-d7961526d74d"
        )

    def test_description_appends_the_resource_after_the_issue_text(
        self, processor, signin_issue
    ):
        incident = processor._convert(signin_issue, entities_cache={})[0]
        assert incident.description.startswith(
            "Detects Wiz login from an unusual country.\n\n**Affected resource**\n"
        )
        # Empty strings from the payload are not written out.
        assert "Region" not in incident.description

    def test_no_snapshot_and_empty_description_falls_back_to_none(
        self, processor, empty_description_issue_data
    ):
        empty_description_issue_data["entitySnapshot"] = None
        issue = WizIssue.model_validate(empty_description_issue_data)

        objects = processor._convert(issue, entities_cache={})

        assert len(objects) == 1
        assert objects[0].description is None

    def test_labels_describe_the_issue_without_naming_the_source(
        self, processor, signin_issue
    ):
        """The Wiz author and external reference already name the source."""
        incident = processor._convert(signin_issue, entities_cache={})[0]

        assert "wiz" not in incident.labels
        assert "threat-detection" in incident.labels

    def test_duplicate_snapshot_reuses_one_system_object(
        self, processor, empty_description_issue, duplicate_snapshot_issue
    ):
        cache = {}
        first = processor._convert(empty_description_issue, cache)
        second = processor._convert(duplicate_snapshot_issue, cache)
        # Both conversions carry a System, but the cache reuses one object.
        assert len(first) == 3  # incident, system, relationship
        assert len(second) == 3  # incident, system, relationship
        assert len(cache) == 1
        first_system = _of_type(first, System)[0]
        second_system = _of_type(second, System)[0]
        assert first_system is second_system


class TestEntityMapping:
    @staticmethod
    def _convert(processor, issue_data, **snapshot):
        issue_data["entitySnapshot"].update(snapshot)
        issue = WizIssue.model_validate(issue_data)
        return processor._convert(issue, entities_cache={})

    def test_virtual_machine_is_a_targeted_system(
        self, processor, empty_description_issue_data
    ):
        incident, system, relationship = self._convert(
            processor, empty_description_issue_data
        )

        assert isinstance(system, System)
        assert system.name == "tivan-eleonore-vm"
        assert system.external_references[0].external_id == "i-038b4a2cfb0c1f036"
        assert relationship.type == RelationshipType.TARGETS
        assert relationship.source is incident
        assert relationship.target is system

    def test_service_account_is_a_related_user_account(
        self, processor, signin_issue_data
    ):
        _, account, relationship = self._convert(processor, signin_issue_data)

        assert isinstance(account, UserAccount)
        assert account.account_login == "TA-733-INTEG-ING"
        assert account.user_id == "mlipebtwsndhxdmnzdwrxzmio"
        assert account.is_service_account is True
        assert relationship.type == RelationshipType.RELATED_TO
        assert relationship.target is account

    def test_container_image_is_a_related_software(
        self, processor, empty_description_issue_data
    ):
        _, software, relationship = self._convert(
            processor,
            empty_description_issue_data,
            type="CONTAINER_IMAGE",
            name="nginx:1.27",
        )

        assert isinstance(software, Software)
        assert software.name == "nginx:1.27"
        assert relationship.type == RelationshipType.RELATED_TO

    def test_access_key_is_a_related_credential(
        self, processor, empty_description_issue_data
    ):
        _, credential, relationship = self._convert(
            processor,
            empty_description_issue_data,
            type="ACCESS_KEY",
            name="AKIAIOSFODNN7EXAMPLE",
        )

        assert isinstance(credential, Credential)
        assert credential.value == "AKIAIOSFODNN7EXAMPLE"
        assert credential.to_stix2_object()["type"] == "credential"
        assert relationship.type == RelationshipType.RELATED_TO

    def test_subscription_is_only_described(
        self, processor, empty_description_issue_data
    ):
        objects = self._convert(
            processor,
            empty_description_issue_data,
            type="SUBSCRIPTION",
            name="prod-account",
        )

        assert len(objects) == 1
        assert "- Name: prod-account" in objects[0].description
        assert "- Type: SUBSCRIPTION" in objects[0].description

    def test_unmapped_type_is_only_described(
        self, processor, empty_description_issue_data
    ):
        objects = self._convert(processor, empty_description_issue_data, type="BUCKET")

        assert len(objects) == 1
        assert "- Type: BUCKET" in objects[0].description

    def test_nameless_snapshot_is_skipped_instead_of_failing(
        self, processor, empty_description_issue_data
    ):
        objects = self._convert(processor, empty_description_issue_data, name="")

        assert len(objects) == 1
        assert "**Affected resource**" in objects[0].description


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


class TestPostInit:
    def test_builds_client_author_and_marking_from_settings(self):
        processor = WizIssuesProcessor()
        processor.settings = MagicMock(
            wiz_cloud=WizCloudConfig(
                api_url="https://api.example.com/graphql",
                client_id="id",
                client_secret="secret",
            )
        )
        # Injected by the SDK before post_init() in a real run.
        processor.logger = MagicMock()

        with patch("wiz_cloud.processors.issues_processor.WizApiClient") as client:
            processor.post_init()

        kwargs = client.call_args.kwargs
        assert kwargs["base_url"] == "https://api.example.com/graphql"
        assert kwargs["auth_url"] == "https://auth.app.wiz.io/oauth/token"
        assert kwargs["client_id"] == "id"
        assert kwargs["client_secret"] == "secret"
        assert kwargs["logger"] is processor.logger
        assert processor._author.name == "Wiz"
        assert processor._marking is not None


class TestCollect:
    @staticmethod
    def _prepare(processor, **config):
        processor._config = WizCloudConfig(
            api_url="https://api.example.com/graphql",
            client_id="id",
            client_secret="secret",
            **config,
        )
        processor._client = MagicMock()
        processor._client.paginate.return_value = iter([[{"id": "a"}]])
        return processor

    def test_uses_the_since_window_on_first_run(self, processor):
        self._prepare(processor, since="P1D")
        before = datetime.now(tz=timezone.utc) - timedelta(days=1)

        pages = list(processor.collect())

        after_filter = processor._client.paginate.call_args.args[1]["filterBy"][
            "createdAt"
        ]["after"]
        assert pages == [[{"id": "a"}]]
        assert datetime.fromisoformat(after_filter) >= before.replace(microsecond=0)
        assert processor.work_name.startswith("Wiz Cloud issues import since ")

    def test_uses_the_stored_cursor_when_present(self, processor):
        self._prepare(processor)
        processor.state.issues_last_created_at = datetime(
            2026, 8, 24, 15, 7, 37, 534962, tzinfo=timezone.utc
        )

        list(processor.collect())

        _, variables = processor._client.paginate.call_args.args[:2]
        assert variables["filterBy"]["createdAt"] == {
            "after": "2026-08-24T15:07:37.534962Z"
        }

    def test_filters_and_orders_oldest_first(self, processor):
        self._prepare(
            processor, page_size=10, issue_severity="LOW", issue_status="OPEN"
        )

        list(processor.collect())

        call = processor._client.paginate.call_args
        variables = call.args[1]
        assert call.kwargs["connection_key"] == "issues"
        assert variables["first"] == 10
        assert variables["after"] is None
        assert variables["orderBy"] == {"field": "CREATED_AT", "direction": "ASC"}
        assert variables["filterBy"]["type"] == ["THREAT_DETECTION"]
        assert variables["filterBy"]["severity"] == ["LOW"]
        assert variables["filterBy"]["status"] == ["OPEN"]


class TestTransformCursor:
    def test_advances_cursor_to_the_newest_converted_issue(
        self, processor, signin_issue, empty_description_issue_data, signin_issue_data
    ):
        list(
            processor.transform(
                iter([[empty_description_issue_data, signin_issue_data]])
            )
        )

        assert processor.state.issues_last_created_at == signin_issue.created_at

    def test_keeps_cursor_when_nothing_converts(self, processor):
        list(processor.transform(iter([[{"id": "broken"}]])))

        assert processor.state.issues_last_created_at is None


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

    def test_a_container_image_gets_its_vulnerabilities_on_its_software(
        self, processor, empty_description_issue_data
    ):
        vulnerabilities = self._enable(processor, {})
        empty_description_issue_data["entitySnapshot"].update(
            type="CONTAINER_IMAGE", name="nginx:1.27"
        )

        list(processor.transform(iter([[empty_description_issue_data]])))

        _, asset = vulnerabilities.objects_for_asset.call_args[0]
        assert isinstance(asset, Software)
        assert asset.name == "nginx:1.27"

    def test_an_asset_that_cannot_have_a_vulnerability_is_not_scanned(
        self, processor, signin_issue_data
    ):
        """OpenCTI only lets a System or a Software have a vulnerability."""
        vulnerabilities = self._enable(processor, {})

        bundles = list(processor.transform(iter([[signin_issue_data]])))

        vulnerabilities.objects_for_asset.assert_not_called()
        assert len(bundles) == 1

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
            call.kwargs["meta"]["asset"]: call.kwargs["meta"]["vulnerabilities"]
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
            call.kwargs["meta"]
            for call in processor.logger.info.call_args_list
            if "Import finished" in call.args[0]
        )
        assert summary == {
            "incidents": 2,
            "vulnerabilities": 1,
            "ttps": 0,
            "bundles": 2,
        }

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

    def test_every_bundle_carries_the_system_it_references(
        self, processor, empty_description_issue_data, duplicate_snapshot_issue_data
    ):
        """Bundles are ingested in any order, so refs must resolve locally."""
        self._enable(processor, {})

        bundles = list(
            processor.transform(
                iter([[empty_description_issue_data, duplicate_snapshot_issue_data]])
            )
        )

        assert len(bundles) == 2
        for bundle in bundles:
            systems = _of_type(bundle, System)
            targets = [
                obj
                for obj in bundle
                if isinstance(obj, Relationship) and obj.type == "targets"
            ]
            assert len(systems) == 1
            assert targets[0].target is systems[0]


class TestTtps:
    """MITRE techniques travel in the bundle of the issue that maps to them."""

    @staticmethod
    def _enable(processor, objects_by_issue: dict[str, list]) -> MagicMock:
        """Attach a TTPs processor stub returning canned objects per issue.

        Args:
            processor: The issues processor under test.
            objects_by_issue: Objects to return for each issue id.

        Returns:
            The stub, so calls can be asserted.
        """
        ttps = MagicMock()
        ttps.objects_for_issue.side_effect = (
            lambda issue, incident: objects_by_issue.get(issue.id, [])
        )
        processor._ttps = ttps
        return ttps

    def test_attack_patterns_are_added_to_the_issue_objects(
        self, processor, signin_issue_data
    ):
        pattern = AttackPattern(
            name="Develop Capabilities: Malware", mitre_id="T1587.001"
        )
        self._enable(processor, {signin_issue_data["id"]: [pattern]})

        bundles = list(processor.transform(iter([[signin_issue_data]])))

        assert any(obj is pattern for obj in bundles[0])

    def test_nothing_is_added_when_ttps_are_disabled(
        self, processor, signin_issue_data
    ):
        processor._ttps = None

        bundles = list(processor.transform(iter([[signin_issue_data]])))

        assert not _of_type(bundles[0], AttackPattern)

    def test_the_incident_is_passed_to_the_ttps_processor(
        self, processor, signin_issue_data
    ):
        ttps = self._enable(processor, {})

        bundles = list(processor.transform(iter([[signin_issue_data]])))

        incident = _of_type(bundles[0], Incident)[0]
        assert ttps.objects_for_issue.call_args[0][1] is incident

    def test_the_run_total_counts_the_attack_patterns(
        self, processor, signin_issue_data
    ):
        pattern = AttackPattern(
            name="Develop Capabilities: Malware", mitre_id="T1587.001"
        )
        self._enable(processor, {signin_issue_data["id"]: [pattern]})

        list(processor.transform(iter([[signin_issue_data]])))

        finished = [
            call
            for call in processor.logger.info.call_args_list
            if "Import finished" in call[0][0]
        ]
        assert finished[0].kwargs["meta"]["ttps"] == 1


class TestBundleDeduplication:
    """A bundle never carries the same object twice."""

    def test_a_page_bundle_carries_a_shared_system_once(
        self, processor, empty_description_issue_data, duplicate_snapshot_issue_data
    ):
        bundles = list(
            processor.transform(
                iter([[empty_description_issue_data, duplicate_snapshot_issue_data]])
            )
        )

        assert len(bundles) == 1
        assert len(_of_type(bundles[0], System)) == 1

    def test_a_page_bundle_carries_a_shared_technique_once(
        self, processor, empty_description_issue_data, duplicate_snapshot_issue_data
    ):
        # A distinct instance per issue, as the TTPs processor really builds
        # them: only the deterministic id makes them the same object.
        ttps = MagicMock()
        ttps.objects_for_issue.side_effect = lambda issue, incident: [
            AttackPattern(name="Develop Capabilities: Malware", mitre_id="T1587.001")
        ]
        processor._ttps = ttps

        bundles = list(
            processor.transform(
                iter([[empty_description_issue_data, duplicate_snapshot_issue_data]])
            )
        )

        assert len(_of_type(bundles[0], AttackPattern)) == 1
