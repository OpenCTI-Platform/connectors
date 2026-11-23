"""Spamhaus commercial mode: JWT API import, fallback and secret hygiene."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from connectors_sdk.shared.spamhaus import (
    SpamhausAuthenticationError,
    SpamhausUnavailableError,
)
from src.__main__ import FeedRow, ThreatFox

NOW = datetime(2027, 1, 15, 8, 0, 0, tzinfo=UTC)
PASSWORD = "p4ssw0rd-do-not-leak"
TOKEN = "jwt-token-do-not-leak"


def api_ioc(**overrides):
    """A synthetic item of GET /threatfox/v1/iocs (see abusech-docs.spamhaus.com)."""
    item = {
        "id": 41,
        "ioc": "gaga.com",
        "ioc_type": "domain",
        "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
        "threat_type": "botnet_cc",
        "threat_type_desc": "Indicator that identifies a botnet command&control server",
        "malware": "win.ave_maria",
        "malware_printable": "Ave Maria",
        "malware_alias": "AVE_MARIA,AveMariaRAT,Warzone RAT,avemaria",
        "malware_malpedia": "https://malpedia.example.org/details/win.ave_maria",
        "confidence_level": 75,
        "first_seen": "2027-01-14T10:00:00Z",
        "last_seen": "2027-01-15T09:00:00Z",
        "is_compromised": False,
        "reference": "https://example.org/report",
        "reporter": "abuse_ch",
        "sightings": 3,
        "tags": ["exe", "test"],
        "comment": "These domains are too bad!",
        "credits": [{"credits_from": "ThreatFox", "credits_amount": 100}],
        "malware_samples": [],
    }
    item.update(overrides)
    return item


class TestFeedRowFromApi:
    def test_maps_every_field_used_by_the_connector(self):
        row = FeedRow.from_api(api_ioc())

        assert row.id == "41"
        assert row.value == "gaga.com"
        assert row.type == "domain"
        assert row.threat_type == "botnet_cc"
        assert row.fk_malware == "win.ave_maria"
        assert row.malware_printable == "Ave Maria"
        assert row.malware_aliases == [
            "Ave Maria",
            "AVE_MARIA",
            "AveMariaRAT",
            "Warzone RAT",
            "avemaria",
        ]
        assert row.first_seen == datetime(2027, 1, 14, 10, 0, tzinfo=UTC)
        assert row.last_seen == datetime(2027, 1, 15, 9, 0, tzinfo=UTC)
        assert row.confidence_level == 75
        assert row.is_compromised is False
        assert row.reference == "https://example.org/report"
        assert row.tags == ["botnet_cc", "exe", "test"]
        assert row.reporter == "abuse_ch"
        assert row.anonymous is False

    def test_same_row_as_the_csv_for_the_same_ioc(self):
        csv_row = FeedRow(
            (
                "2027-01-14 10:00:00",
                "41",
                "gaga.com",
                "domain",
                "botnet_cc",
                "win.ave_maria",
                "AVE_MARIA,AveMariaRAT,Warzone RAT,avemaria",
                "Ave Maria",
                "2027-01-15 09:00:00",
                "75",
                "False",
                "https://example.org/report",
                "exe,test",
                "0",
                "abuse_ch",
            )
        )

        assert FeedRow.from_api(api_ioc()) == csv_row

    def test_offsets_are_converted_to_utc(self):
        row = FeedRow.from_api(api_ioc(first_seen="2027-01-14T11:00:00+01:00"))

        assert row.first_seen == datetime(2027, 1, 14, 10, 0, tzinfo=UTC)

    def test_fractional_seconds_are_accepted(self):
        row = FeedRow.from_api(api_ioc(first_seen="2027-01-14T10:00:00.123456Z"))

        assert row.first_seen.year == 2027

    def test_optional_fields_may_be_missing(self):
        item = api_ioc()
        for key in (
            "last_seen",
            "malware_alias",
            "reference",
            "is_compromised",
            "tags",
            "comment",
        ):
            del item[key]

        row = FeedRow.from_api(item)

        assert row.last_seen is None
        assert row.malware_aliases == ["Ave Maria"]
        assert row.reference == ""
        assert row.is_compromised is False
        assert row.tags == ["botnet_cc"]

    def test_unknown_malware_is_dropped_like_in_the_csv(self):
        row = FeedRow.from_api(
            api_ioc(malware="unknown", malware_printable="Unknown malware")
        )

        assert row.fk_malware == ""
        assert row.malware_printable == ""

    def test_anonymous_reporter(self):
        assert FeedRow.from_api(api_ioc(reporter="anonymous")).anonymous is True

    @pytest.mark.parametrize("missing", ["id", "ioc", "ioc_type", "first_seen"])
    def test_a_required_field_missing_is_a_key_error(self, missing):
        item = api_ioc()
        del item[missing]

        with pytest.raises(KeyError):
            FeedRow.from_api(item)

    def test_a_bad_date_is_a_value_error(self):
        with pytest.raises(ValueError):
            FeedRow.from_api(api_ioc(first_seen="yesterday"))


class FakeSpamhausClient:
    """Stands in for SpamhausClient: serves canned pages or raises."""

    def __init__(self, pages=None, error=None):
        self.pages = pages or []
        self.error = error
        self.calls = []

    def paginate(self, path, *, params=None, page_size=100):
        self.calls.append({"path": path, "params": params, "page_size": page_size})
        if self.error is not None:
            raise self.error
        yield from self.pages


@pytest.fixture
def connector():
    connector = ThreatFox.__new__(ThreatFox)
    connector.helper = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-id"
    connector.identity = {
        "standard_id": "identity--1d4d8a1e-5b0a-5a39-9a62-5d1e0b6c0a11"
    }
    connector.threatfox_csv_url = (
        "https://threatfox-api.abuse.ch/v2/files/exports/community-key/recent.csv"
    )
    connector.ioc_to_import = ["all_types"]
    connector.threatfox_import_offline = True
    connector.create_indicators = True
    connector.default_x_opencti_score = 50
    connector.x_opencti_score_ip = None
    connector.x_opencti_score_domain = None
    connector.x_opencti_score_url = None
    connector.x_opencti_score_hash = None
    connector.spamhaus_client = FakeSpamhausClient()
    connector.community_fallback = True
    connector.download_csv = MagicMock(return_value=iter([]))
    return connector


def sent_bundle_objects(connector):
    bundle = connector.helper.send_stix2_bundle.call_args.args[0]
    return json.loads(bundle)["objects"]


def run(connector, state=None):
    return connector.import_data(state or {}, NOW, NOW.timestamp())


def logged(connector):
    return str(connector.helper.mock_calls)


class TestCommercialImport:
    def test_requests_the_iocs_endpoint_with_since_from_the_checkpoint(self, connector):
        checkpoint = datetime(2027, 1, 14, 9, 30, 15, tzinfo=UTC).timestamp()

        run(connector, {"last_processed_entry": checkpoint})

        (call,) = connector.spamhaus_client.calls
        assert call["path"] == "/threatfox/v1/iocs"
        assert call["params"] == {"since": "2027-01-14T09:30:15Z"}

    def test_first_run_is_bounded_to_the_recent_window(self, connector):
        run(connector, {})

        (call,) = connector.spamhaus_client.calls
        expected = (NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert call["params"] == {"since": expected}

    def test_every_page_is_imported(self, connector):
        connector.spamhaus_client = FakeSpamhausClient(
            pages=[
                [api_ioc(id=1, ioc="one.example.com")],
                [api_ioc(id=2, ioc="two.example.com")],
            ]
        )

        assert run(connector) is True

        values = {
            o["value"]
            for o in sent_bundle_objects(connector)
            if o["type"] == "domain-name"
        }
        assert values == {"one.example.com", "two.example.com"}
        connector.download_csv.assert_not_called()

    def test_objects_are_the_same_as_for_the_csv(self, connector):
        connector.spamhaus_client = FakeSpamhausClient(pages=[[api_ioc()]])

        run(connector)

        types = sorted(o["type"] for o in sent_bundle_objects(connector))
        assert types == [
            "domain-name",
            "indicator",
            "malware",
            "relationship",
            "relationship",
        ]

    def test_checkpoint_advances_to_the_newest_first_seen(self, connector):
        connector.spamhaus_client = FakeSpamhausClient(
            pages=[
                [
                    api_ioc(id=1, first_seen="2027-01-14T10:00:00Z"),
                    api_ioc(id=2, first_seen="2027-01-14T12:00:00Z"),
                ]
            ]
        )

        assert run(connector) is True

        stored = connector.helper.set_state.call_args.args[0]
        assert (
            stored["last_processed_entry"]
            == datetime(2027, 1, 14, 12, 0, tzinfo=UTC).timestamp()
        )
        assert stored["last_run"] == NOW.timestamp()

    def test_a_bad_item_is_skipped_and_the_run_succeeds(self, connector):
        connector.spamhaus_client = FakeSpamhausClient(
            pages=[
                [
                    api_ioc(id=1, first_seen="not a date"),
                    {"id": 2},
                    api_ioc(id=3, ioc="good.example.com"),
                ]
            ]
        )

        assert run(connector) is True

        values = [
            o["value"]
            for o in sent_bundle_objects(connector)
            if o["type"] == "domain-name"
        ]
        assert values == ["good.example.com"]
        warnings = connector.helper.connector_logger.warning.call_args_list
        assert len(warnings) == 2

    def test_items_that_are_not_valid_objects_are_skipped_without_failing_the_run(
        self, connector
    ):
        connector.spamhaus_client = FakeSpamhausClient(
            pages=[
                [
                    None,
                    "not an object",
                    api_ioc(id=2, malware_alias=["not", "a", "string"]),
                    api_ioc(id=3, ioc="good.example.com"),
                ]
            ]
        )

        assert run(connector) is True

        values = [
            o["value"]
            for o in sent_bundle_objects(connector)
            if o["type"] == "domain-name"
        ]
        assert values == ["good.example.com"]
        warnings = connector.helper.connector_logger.warning.call_args_list
        assert len(warnings) == 3

    def test_ioc_type_filter_applies(self, connector):
        connector.ioc_to_import = ["url"]
        connector.spamhaus_client = FakeSpamhausClient(
            pages=[[api_ioc(), api_ioc(id=2, ioc="http://x.example/a", ioc_type="url")]]
        )

        run(connector)

        types = {o["type"] for o in sent_bundle_objects(connector)}
        assert "url" in types
        assert "domain-name" not in types

    def test_empty_result_still_stores_the_run(self, connector):
        assert run(connector) is True

        # Nothing to send, as in community mode, but the run is stored
        connector.helper.send_stix2_bundle.assert_not_called()
        connector.helper.set_state.assert_called_once()


class TestFallbackToTheCommunityKey:
    @pytest.mark.parametrize(
        "error",
        [
            SpamhausUnavailableError("Spamhaus cannot answer (HTTP 503)"),
            SpamhausAuthenticationError("check the Spamhaus credentials"),
        ],
        ids=["unavailable", "rejected"],
    )
    def test_commercial_failure_falls_back_to_the_csv_with_a_warning(
        self, connector, error
    ):
        connector.spamhaus_client = FakeSpamhausClient(error=error)
        connector.download_csv = MagicMock(
            return_value=iter(
                [
                    '2027-01-14 10:00:00, "9", "csv.example.com", "domain", "botnet_cc", '
                    '"win.ave_maria", "", "Ave Maria", "", "75", "False", "None", "exe", "0", "abuse_ch"'
                ]
            )
        )

        assert run(connector) is True

        connector.download_csv.assert_called_once()
        values = [
            o["value"]
            for o in sent_bundle_objects(connector)
            if o["type"] == "domain-name"
        ]
        assert values == ["csv.example.com"]
        warning = connector.helper.connector_logger.warning.call_args.args[0]
        assert "falling back" in warning.lower()
        assert "community" in warning.lower()

    def test_the_commercial_checkpoint_is_kept_after_a_csv_fallback(self, connector):
        checkpoint = datetime(2027, 1, 5, 0, 0, tzinfo=UTC).timestamp()
        connector.spamhaus_client = FakeSpamhausClient(
            error=SpamhausUnavailableError("Spamhaus cannot answer (HTTP 503)")
        )
        connector.download_csv = MagicMock(
            return_value=iter(
                [
                    '2027-01-14 10:00:00, "9", "csv.example.com", "domain", "botnet_cc", '
                    '"win.ave_maria", "", "Ave Maria", "", "75", "False", "None", "exe", "0", "abuse_ch"'
                ]
            )
        )

        assert run(connector, {"last_processed_entry": checkpoint}) is True

        # The CSV row is imported, but the checkpoint stays where the commercial
        # API left it, so the next healthy run catches up from there.
        assert sent_bundle_objects(connector)
        stored = connector.helper.set_state.call_args.args[0]
        assert stored["last_processed_entry"] == checkpoint
        assert stored["last_run"] == NOW.timestamp()

    def test_the_checkpoint_advances_again_once_the_commercial_api_recovers(
        self, connector
    ):
        connector.csv_fallback_used = True  # left over from a previous run
        connector.spamhaus_client = FakeSpamhausClient(
            pages=[[api_ioc(id=1, first_seen="2027-01-14T12:00:00Z")]]
        )

        assert run(connector) is True

        stored = connector.helper.set_state.call_args.args[0]
        assert (
            stored["last_processed_entry"]
            == datetime(2027, 1, 14, 12, 0, tzinfo=UTC).timestamp()
        )

    def test_only_commercial_credentials_fail_the_run(self, connector):
        connector.community_fallback = False
        connector.spamhaus_client = FakeSpamhausClient(
            error=SpamhausAuthenticationError(
                "Spamhaus rejected the login (HTTP 401): check the Spamhaus credentials"
            )
        )

        assert run(connector, {"last_run": 1}) is False

        connector.download_csv.assert_not_called()
        connector.helper.set_state.assert_not_called()
        args = connector.helper.api.work.to_processed.call_args
        assert args.kwargs == {"in_error": True}
        assert "Spamhaus credentials" in args.args[1]

    def test_only_commercial_and_unavailable_fails_the_run(self, connector):
        connector.community_fallback = False
        connector.spamhaus_client = FakeSpamhausClient(
            error=SpamhausUnavailableError("Spamhaus cannot answer (HTTP 503)")
        )

        assert run(connector) is False

        connector.helper.set_state.assert_not_called()

    def test_a_non_commercial_error_does_not_fall_back(self, connector):
        connector.spamhaus_client = FakeSpamhausClient(error=RuntimeError("bug"))

        assert run(connector) is False

        connector.download_csv.assert_not_called()


class TestCommunityMode:
    def test_without_a_spamhaus_client_the_csv_is_used(self, connector):
        connector.spamhaus_client = None
        connector.download_csv = MagicMock(return_value=iter([]))

        assert run(connector) is True

        connector.download_csv.assert_called_once()


class TestSecrets:
    def test_failure_messages_and_logs_hold_no_secret(self, connector):
        connector.community_fallback = False
        connector.spamhaus_client = FakeSpamhausClient(
            error=SpamhausAuthenticationError(
                "Spamhaus rejected the login (HTTP 401): check the Spamhaus credentials"
            )
        )

        run(connector)

        text = logged(connector)
        assert PASSWORD not in text
        assert TOKEN not in text
