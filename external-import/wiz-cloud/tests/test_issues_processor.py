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
from unittest.mock import MagicMock, patch

from wiz_cloud.models import WizIssue
from wiz_cloud.processors import WizIssuesProcessor
from wiz_cloud.processors.issues_processor import _utc
from wiz_cloud.settings import WizCloudConfig


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

    def test_labels_describe_the_issue_without_naming_the_source(
        self, processor, signin_issue
    ):
        """The Wiz author and external reference already name the source."""
        incident = processor._convert(signin_issue, systems_cache={})[0]

        assert "wiz" not in incident.labels
        assert "threat-detection" in incident.labels

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

        with patch("wiz_cloud.processors.issues_processor.WizApiClient") as client:
            processor.post_init()

        kwargs = client.call_args.kwargs
        assert kwargs["base_url"] == "https://api.example.com/graphql"
        assert kwargs["auth_url"] == "https://auth.app.wiz.io/oauth/token"
        assert kwargs["client_id"] == "id"
        assert kwargs["client_secret"] == "secret"
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
        self._prepare(processor, since=timedelta(days=1))
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
