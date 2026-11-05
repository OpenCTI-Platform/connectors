"""Tests for the Google/Yandex Safe Browsing enrichment connector."""

from unittest.mock import MagicMock

import pytest
import requests

POST_PATH = "connector.connector.requests.post"


def _domain_observable(**overrides):
    observable = {
        "id": "observable-1",
        "standard_id": "domain-name--11111111-1111-4111-8111-111111111111",
        "entity_type": "Domain-Name",
        "value": "malware-driveby.test.safebrowsing.yandex",
        "objectMarking": [],
    }
    observable.update(overrides)
    return observable


def _enrichment_data(observable, event_type="INTERNAL_ENRICHMENT"):
    data = {
        "entity_id": observable["standard_id"],
        "enrichment_entity": observable,
        "stix_objects": [{"id": observable["standard_id"]}],
        "stix_entity": {"id": observable["standard_id"]},
    }
    if event_type:
        data["event_type"] = event_type
    return data


def _match_response(status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "WINDOWS",
                "threatEntryType": "URL",
            }
        ]
    }
    return response


def _posted_url(post_mock):
    return post_mock.call_args.args[0]


class TestApiUrlResolution:
    def test_default_url_when_unset(self, connector, mocker):
        post = mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(_domain_observable())
        assert _posted_url(post).startswith(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        )

    def test_empty_url_falls_back_to_default(self, make_connector, mocker):
        # Regression: an empty value (e.g. `SAFE_BROWSING_API_URL=` in compose)
        # must not override the default and produce an invalid `/v4/...` URL.
        connector = make_connector({"api_key": "k", "api_url": ""})
        post = mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(_domain_observable())
        assert _posted_url(post).startswith("https://safebrowsing.googleapis.com/v4/")

    def test_custom_yandex_url_strips_trailing_slash(self, make_connector, mocker):
        connector = make_connector(
            {"api_key": "k", "api_url": "https://sba.yandex.net/"}
        )
        post = mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(_domain_observable())
        url = _posted_url(post)
        assert url.startswith("https://sba.yandex.net/v4/threatMatches:find")
        assert "yandex.net//v4" not in url

    def test_request_has_timeout(self, connector, mocker):
        post = mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(_domain_observable())
        assert post.call_args.kwargs["timeout"] == 30


class TestApiKeyFallback:
    def test_legacy_key_used_when_new_unset(self, make_connector, mocker):
        connector = make_connector({}, google_safe_browsing={"api_key": "legacy"})
        post = mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(_domain_observable())
        assert "key=legacy" in _posted_url(post)

    def test_new_key_is_preferred(self, make_connector, mocker):
        connector = make_connector(
            {"api_key": "new"}, google_safe_browsing={"api_key": "legacy"}
        )
        post = mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(_domain_observable())
        assert "key=new" in _posted_url(post)


class TestEnrichmentResults:
    def test_domain_match_sends_bundle_and_label(self, connector, mocker):
        mocker.patch(POST_PATH, return_value=_match_response())
        connector.helper.send_stix2_bundle.return_value = ["bundle"]
        result = connector.google_safe_browsing(_domain_observable())
        connector.helper.stix2_create_bundle.assert_called_once()
        connector.helper.send_stix2_bundle.assert_called_once()
        connector.helper.api.stix_cyber_observable.add_label.assert_called_once()
        assert "bundles to OpenCTI" in result

    def test_url_observable(self, connector, mocker):
        mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(
            _domain_observable(
                entity_type="Url",
                standard_id="url--22222222-2222-4222-8222-222222222222",
                value="http://malware-driveby.test.safebrowsing.yandex",
            )
        )
        connector.helper.send_stix2_bundle.assert_called_once()

    def test_hostname_observable(self, connector, mocker):
        mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(
            _domain_observable(
                entity_type="Hostname",
                standard_id="hostname--33333333-3333-4333-8333-333333333333",
            )
        )
        connector.helper.send_stix2_bundle.assert_called_once()

    def test_existing_description_is_preserved(self, connector, mocker):
        mocker.patch(POST_PATH, return_value=_match_response())
        connector.google_safe_browsing(
            _domain_observable(x_opencti_description="preexisting")
        )
        connector.helper.send_stix2_bundle.assert_called_once()

    def test_no_match_does_not_send_bundle(self, connector, mocker):
        empty = MagicMock()
        empty.status_code = 200
        empty.json.return_value = {}
        mocker.patch(POST_PATH, return_value=empty)
        assert connector.google_safe_browsing(_domain_observable()) is None
        connector.helper.send_stix2_bundle.assert_not_called()

    def test_error_status_logs_and_returns_none(self, connector, mocker):
        mocker.patch(POST_PATH, return_value=_match_response(status_code=503))
        assert connector.google_safe_browsing(_domain_observable()) is None
        connector.helper.connector_logger.error.assert_called_once()

    def test_request_exception_is_handled(self, connector, mocker):
        # A timeout / connection error must be caught and treated as an error
        # path (log + return None), not propagated out and crash the worker.
        mocker.patch(POST_PATH, side_effect=requests.exceptions.Timeout("timed out"))
        assert connector.google_safe_browsing(_domain_observable()) is None
        connector.helper.connector_logger.error.assert_called_once()
        connector.helper.send_stix2_bundle.assert_not_called()

    def test_request_exception_does_not_log_api_key(self, make_connector, mocker):
        connector = make_connector({"api_key": "super-secret"})
        mocker.patch(
            POST_PATH,
            side_effect=requests.exceptions.ConnectionError(
                "Max retries exceeded with url: /v4/threatMatches:find?key=super-secret"
            ),
        )
        connector.google_safe_browsing(_domain_observable())
        logged = str(connector.helper.connector_logger.error.call_args)
        assert "super-secret" not in logged


class TestProcessMessage:
    @pytest.mark.parametrize(
        "entity_type, standard_id",
        [
            ("Domain-Name", "domain-name--11111111-1111-4111-8111-111111111111"),
            ("Url", "url--22222222-2222-4222-8222-222222222222"),
            ("Hostname", "hostname--33333333-3333-4333-8333-333333333333"),
        ],
    )
    def test_routes_supported_observables(
        self, connector, mocker, entity_type, standard_id
    ):
        mocker.patch(POST_PATH, return_value=_match_response())
        observable = _domain_observable(
            entity_type=entity_type, standard_id=standard_id
        )
        connector.process_message(_enrichment_data(observable))
        # The entity is taken from the enrichment message, not re-read from the API
        connector.helper.api.stix_cyber_observable.read.assert_not_called()
        connector.helper.send_stix2_bundle.assert_called_once()

    def test_out_of_scope_entity_is_skipped(self, connector, mocker):
        post = mocker.patch(POST_PATH, return_value=_match_response())
        observable = _domain_observable(
            entity_type="IPv4-Addr",
            standard_id="ipv4-addr--44444444-4444-4444-8444-444444444444",
        )
        assert connector.process_message(_enrichment_data(observable)) is None
        post.assert_not_called()
        connector.helper.send_stix2_bundle.assert_not_called()
        connector.helper.connector_logger.warning.assert_called_once()

    def test_out_of_scope_playbook_entity_sends_original_bundle(
        self, connector, mocker
    ):
        post = mocker.patch(POST_PATH, return_value=_match_response())
        observable = _domain_observable(
            entity_type="IPv4-Addr",
            standard_id="ipv4-addr--44444444-4444-4444-8444-444444444444",
        )
        data = _enrichment_data(observable, event_type=None)
        connector.process_message(data)
        post.assert_not_called()
        connector.helper.stix2_create_bundle.assert_called_once_with(
            data["stix_objects"]
        )
        connector.helper.send_stix2_bundle.assert_called_once()

    def test_entity_above_max_tlp_is_skipped(self, connector, mocker):
        post = mocker.patch(POST_PATH, return_value=_match_response())
        observable = _domain_observable(
            objectMarking=[{"definition_type": "TLP", "definition": "TLP:RED"}]
        )
        assert connector.process_message(_enrichment_data(observable)) is None
        post.assert_not_called()
        connector.helper.send_stix2_bundle.assert_not_called()
        connector.helper.connector_logger.warning.assert_called_once()

    def test_entity_within_max_tlp_is_enriched(self, connector, mocker):
        post = mocker.patch(POST_PATH, return_value=_match_response())
        observable = _domain_observable(
            objectMarking=[{"definition_type": "TLP", "definition": "TLP:GREEN"}]
        )
        connector.process_message(_enrichment_data(observable))
        post.assert_called_once()
        connector.helper.send_stix2_bundle.assert_called_once()
