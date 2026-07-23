"""Tests for the IPGeolocation API client (mocked HTTP layer)."""

from unittest.mock import MagicMock, patch

import pytest

from src.api_client import IPGeolocationAPIError, IPGeolocationClient
from tests.mock_responses import (
    MOCK_ABUSE_RESPONSE,
    MOCK_ASN_DETAILED,
    MOCK_IPGEO_FULL,
    MOCK_SECURITY_DEDICATED,
)


def _mock_response(json_data, status_code=200, headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = str(json_data)
    resp.headers = headers or {"X-Credits-Charged": "1"}
    return resp


class TestIPGeolocationClient:

    def setup_method(self):
        self.client = IPGeolocationClient(
            api_key="test_key_1234",
            base_url="https://api.ipgeolocation.io",
            timeout=10,
            max_retries=1,
        )

    @patch("src.api_client.requests.Session.get")
    def test_lookup_unified(self, mock_get):
        mock_get.return_value = _mock_response(MOCK_IPGEO_FULL)
        intel = self.client.lookup_unified("2.56.188.34")
        assert intel.ip == "2.56.188.34"
        assert intel.location.country_name == "United States"
        assert intel.security.threat_score == 80
        assert intel.security.is_vpn is True
        assert intel.abuse.emails == ["abuse@packethub.net"]

    @patch("src.api_client.requests.Session.get")
    def test_lookup_geo(self, mock_get):
        mock_get.return_value = _mock_response(MOCK_IPGEO_FULL)
        data = self.client.lookup_geo("2.56.188.34")
        assert data["ip"] == "2.56.188.34"

    @patch("src.api_client.requests.Session.get")
    def test_lookup_security(self, mock_get):
        mock_get.return_value = _mock_response(MOCK_SECURITY_DEDICATED)
        data = self.client.lookup_security("2.56.188.34")
        assert data["security"]["threat_score"] == 80

    @patch("src.api_client.requests.Session.get")
    def test_lookup_asn(self, mock_get):
        mock_get.return_value = _mock_response(MOCK_ASN_DETAILED)
        data = self.client.lookup_asn("8.8.8.8")
        assert "asn" in data

    @patch("src.api_client.requests.Session.get")
    def test_lookup_abuse(self, mock_get):
        mock_get.return_value = _mock_response(MOCK_ABUSE_RESPONSE)
        data = self.client.lookup_abuse("8.8.8.8")
        assert data["abuse"]["emails"] == ["network-abuse@google.com"]

    @patch("src.api_client.requests.Session.get")
    def test_api_error_raises_exception(self, mock_get):
        error_resp = _mock_response(
            {"message": "Invalid API key"},
            status_code=401,
        )
        mock_get.return_value = error_resp
        with pytest.raises(IPGeolocationAPIError) as exc_info:
            self.client.lookup_geo("1.1.1.1")
        assert exc_info.value.status_code == 401

    @patch("src.api_client.requests.Session.get")
    def test_enrich_single_call_mode(self, mock_get):
        """Single-call mode should make 2 calls: ipgeo + asn."""
        mock_get.return_value = _mock_response(MOCK_IPGEO_FULL)
        intel = self.client.enrich(
            "2.56.188.34",
            single_call=True,
            use_geo=True,
            use_security=True,
            use_asn=True,
            use_abuse=True,
        )
        assert intel.ip == "2.56.188.34"
        # 2 calls: unified + ASN dedicated
        assert mock_get.call_count == 2

    @patch("src.api_client.requests.Session.get")
    def test_enrich_dedicated_mode(self, mock_get):
        """Dedicated mode calls each endpoint separately."""
        mock_get.side_effect = [
            _mock_response(MOCK_IPGEO_FULL),  # geo
            _mock_response(MOCK_SECURITY_DEDICATED),  # security
            _mock_response(MOCK_ASN_DETAILED),  # asn
            _mock_response(MOCK_ABUSE_RESPONSE),  # abuse
        ]
        intel = self.client.enrich(
            "2.56.188.34",
            single_call=False,
            use_geo=True,
            use_security=True,
            use_asn=True,
            use_abuse=True,
        )
        assert intel.ip == "2.56.188.34"
        assert mock_get.call_count == 4

    @patch("src.api_client.requests.Session.get")
    def test_graceful_failure_on_asn(self, mock_get):
        """ASN failure in single-call mode should not break enrichment."""
        # First call succeeds, second (ASN) fails
        mock_get.side_effect = [
            _mock_response(MOCK_IPGEO_FULL),
            _mock_response({"message": "Not found"}, status_code=404),
        ]
        intel = self.client.enrich(
            "2.56.188.34",
            single_call=True,
            use_geo=True,
            use_security=True,
            use_asn=True,
            use_abuse=True,
        )
        # Should still have basic ASN from ipgeo response
        assert intel.asn.as_number == "AS15169"

    def test_api_key_redacted_in_logs(self):
        from src.api_client import _redact

        params = {"apiKey": "secret_key_12345", "ip": "1.1.1.1"}
        redacted = _redact(params)
        assert "secret_key_12345" not in str(redacted)
        assert redacted["apiKey"].startswith("secr")
        assert redacted["ip"] == "1.1.1.1"
