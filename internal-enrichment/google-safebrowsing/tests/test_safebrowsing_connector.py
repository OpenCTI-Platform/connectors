"""Tests for the Google/Yandex Safe Browsing enrichment connector."""

from unittest.mock import MagicMock

import pytest
import requests
from lib import SafeBrowsing as safebrowsing_module


def _domain_observable(**overrides):
    observable = {
        "id": "observable-1",
        "standard_id": "domain-name--11111111-1111-4111-8111-111111111111",
        "entity_type": "Domain-Name",
        "value": "malware-driveby.test.safebrowsing.yandex",
    }
    observable.update(overrides)
    return observable


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
    def test_default_url_when_unset(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        post = mocker.patch(
            "lib.SafeBrowsing.requests.post", return_value=_match_response()
        )
        connector.google_safe_browsing(_domain_observable())
        assert _posted_url(post).startswith(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        )

    def test_empty_url_falls_back_to_default(self, connector, mocker, monkeypatch):
        # Regression: an empty value (e.g. `SAFE_BROWSING_API_URL=` in compose)
        # must not override the default and produce an invalid `/v4/...` URL.
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        monkeypatch.setenv("SAFE_BROWSING_API_URL", "")
        post = mocker.patch(
            "lib.SafeBrowsing.requests.post", return_value=_match_response()
        )
        connector.google_safe_browsing(_domain_observable())
        assert _posted_url(post).startswith("https://safebrowsing.googleapis.com/v4/")

    def test_custom_yandex_url_strips_trailing_slash(
        self, connector, mocker, monkeypatch
    ):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        monkeypatch.setenv("SAFE_BROWSING_API_URL", "https://sba.yandex.net/")
        post = mocker.patch(
            "lib.SafeBrowsing.requests.post", return_value=_match_response()
        )
        connector.google_safe_browsing(_domain_observable())
        url = _posted_url(post)
        assert url.startswith("https://sba.yandex.net/v4/threatMatches:find")
        assert "yandex.net//v4" not in url

    def test_request_has_timeout(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        post = mocker.patch(
            "lib.SafeBrowsing.requests.post", return_value=_match_response()
        )
        connector.google_safe_browsing(_domain_observable())
        assert post.call_args.kwargs["timeout"] == 30


class TestApiKeyFallback:
    def test_legacy_key_used_when_new_unset(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "legacy")
        post = mocker.patch(
            "lib.SafeBrowsing.requests.post", return_value=_match_response()
        )
        connector.google_safe_browsing(_domain_observable())
        assert "key=legacy" in _posted_url(post)

    def test_new_key_is_preferred(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "new")
        monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "legacy")
        post = mocker.patch(
            "lib.SafeBrowsing.requests.post", return_value=_match_response()
        )
        connector.google_safe_browsing(_domain_observable())
        assert "key=new" in _posted_url(post)


class TestEnrichmentResults:
    def test_domain_match_sends_bundle_and_label(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        mocker.patch("lib.SafeBrowsing.requests.post", return_value=_match_response())
        connector.helper.send_stix2_bundle.return_value = ["bundle"]
        result = connector.google_safe_browsing(_domain_observable())
        connector.helper.stix2_create_bundle.assert_called_once()
        connector.helper.send_stix2_bundle.assert_called_once()
        connector.helper.api.stix_cyber_observable.add_label.assert_called_once()
        assert "bundles to OpenCTI" in result

    def test_url_observable(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        mocker.patch("lib.SafeBrowsing.requests.post", return_value=_match_response())
        connector.google_safe_browsing(
            _domain_observable(
                entity_type="Url",
                standard_id="url--22222222-2222-4222-8222-222222222222",
                value="http://malware-driveby.test.safebrowsing.yandex",
            )
        )
        connector.helper.send_stix2_bundle.assert_called_once()

    def test_hostname_observable(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        mocker.patch("lib.SafeBrowsing.requests.post", return_value=_match_response())
        connector.google_safe_browsing(
            _domain_observable(
                entity_type="Hostname",
                standard_id="hostname--33333333-3333-4333-8333-333333333333",
            )
        )
        connector.helper.send_stix2_bundle.assert_called_once()

    def test_existing_description_is_preserved(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        mocker.patch("lib.SafeBrowsing.requests.post", return_value=_match_response())
        connector.google_safe_browsing(
            _domain_observable(x_opencti_description="preexisting")
        )
        connector.helper.send_stix2_bundle.assert_called_once()

    def test_no_match_does_not_send_bundle(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        empty = MagicMock()
        empty.status_code = 200
        empty.json.return_value = {}
        mocker.patch("lib.SafeBrowsing.requests.post", return_value=empty)
        assert connector.google_safe_browsing(_domain_observable()) is None
        connector.helper.send_stix2_bundle.assert_not_called()

    def test_error_status_logs_and_returns_none(self, connector, mocker, monkeypatch):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        mocker.patch(
            "lib.SafeBrowsing.requests.post",
            return_value=_match_response(status_code=503),
        )
        assert connector.google_safe_browsing(_domain_observable()) is None
        connector.helper.log_error.assert_called_once()

    def test_request_exception_is_handled(self, connector, mocker, monkeypatch):
        # A timeout / connection error must be caught and treated as an error
        # path (log + return None), not propagated out and crash the worker.
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        mocker.patch(
            "lib.SafeBrowsing.requests.post",
            side_effect=requests.exceptions.Timeout("timed out"),
        )
        assert connector.google_safe_browsing(_domain_observable()) is None
        connector.helper.log_error.assert_called_once()
        connector.helper.send_stix2_bundle.assert_not_called()


class TestUpdateExistingDataConfig:
    def _build(self, mocker):
        mocker.patch.object(
            safebrowsing_module, "OpenCTIConnectorHelper", return_value=MagicMock()
        )
        return safebrowsing_module.SafeBrowsingConnector()

    def test_invalid_value_falls_back_to_false(self, mocker, monkeypatch):
        # An invalid CONNECTOR_UPDATE_EXISTING_DATA must warn and default to
        # "false" rather than crashing __init__ with an AttributeError.
        monkeypatch.setenv("CONNECTOR_UPDATE_EXISTING_DATA", "yes")
        connector = self._build(mocker)
        assert connector.update_existing_data == "false"
        connector.helper.log_warning.assert_called_once()

    def test_valid_true_value_is_kept(self, mocker, monkeypatch):
        monkeypatch.setenv("CONNECTOR_UPDATE_EXISTING_DATA", "TRUE")
        connector = self._build(mocker)
        assert connector.update_existing_data == "true"


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
        self, connector, mocker, monkeypatch, entity_type, standard_id
    ):
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
        mocker.patch("lib.SafeBrowsing.requests.post", return_value=_match_response())
        observable = _domain_observable(
            entity_type=entity_type, standard_id=standard_id
        )
        connector.helper.api.stix_cyber_observable.read.return_value = observable
        connector.process_message({"entity_id": "entity-1"})
        connector.helper.api.stix_cyber_observable.read.assert_called_once_with(
            id="entity-1"
        )
        connector.helper.send_stix2_bundle.assert_called_once()
