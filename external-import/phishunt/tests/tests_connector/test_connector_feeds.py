import importlib.metadata
import ssl
import urllib.request
from io import BytesIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connector import ConnectorSettings, Phishunt
from pycti import OpenCTIConnectorHelper


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "phishunt": {
                    "api_key": None,
                    "create_indicators": False,
                    "default_x_opencti_score": 40,
                    "x_opencti_score_domain": 40,
                    "x_opencti_score_ip": 40,
                    "x_opencti_score_url": 40,
                },
            }
        )


@pytest.fixture
def phishunt_connector():
    module_import_path = "pycti.connector.opencti_connector_helper"
    with (
        patch(f"{module_import_path}.killProgramHook"),
        patch(f"{module_import_path}.sched.scheduler"),
        patch(f"{module_import_path}.ConnectorInfo"),
        patch(f"{module_import_path}.OpenCTIApiClient"),
        patch(f"{module_import_path}.OpenCTIConnector"),
        patch(f"{module_import_path}.OpenCTIMetricHandler"),
        patch(f"{module_import_path}.PingAlive"),
    ):
        settings = StubConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        return Phishunt(config=settings, helper=helper)


class TestProcessPublicFeed:
    def test_user_agent_uses_pycti_version(self, phishunt_connector):
        """_process_public_feed must send the pycti version in the User-Agent header (fix #6177)."""
        expected_version = importlib.metadata.version("pycti")
        expected_user_agent = f"OpenCTI-Phishunt-Connector/{expected_version}"

        feed_content = b"# comment\n# comment\n# comment\nhttp://phishing.example.com\n"
        captured_requests = []

        def fake_urlopen(req, context=None):
            captured_requests.append(req)
            fp = BytesIO(feed_content)
            fp.__enter__ = lambda s: s
            fp.__exit__ = MagicMock(return_value=False)
            return fp

        with (
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch.object(
                phishunt_connector.helper, "send_stix2_bundle", return_value=[]
            ),
            patch.object(
                phishunt_connector.helper,
                "api",
                MagicMock(
                    work=MagicMock(initiate_work=MagicMock(return_value="work_id"))
                ),
            ),
        ):
            phishunt_connector._process_public_feed("work_id")

        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert isinstance(req, urllib.request.Request)
        assert req.get_header("User-agent") == expected_user_agent

    def test_request_uses_ssl_context(self, phishunt_connector):
        """_process_public_feed must pass an SSL context to urlopen."""
        feed_content = b"# comment\n# comment\n# comment\n"
        captured_kwargs = {}

        def fake_urlopen(req, context=None):
            captured_kwargs["context"] = context
            fp = BytesIO(feed_content)
            fp.__enter__ = lambda s: s
            fp.__exit__ = MagicMock(return_value=False)
            return fp

        with (
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch.object(
                phishunt_connector.helper, "send_stix2_bundle", return_value=[]
            ),
        ):
            phishunt_connector._process_public_feed("work_id")

        assert isinstance(captured_kwargs["context"], ssl.SSLContext)


class TestProcessPrivateFeed:
    def test_iterates_over_results_key(self, phishunt_connector):
        """_process_private_feed must iterate over data['results'] when API returns paginated dict."""
        api_response = {
            "count": 1,
            "offset": 0,
            "limit": 100,
            "results": [
                {"url": "http://phishing.example.com"},
            ],
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()

        with (
            patch("requests.request", return_value=mock_resp),
            patch.object(
                phishunt_connector.helper, "send_stix2_bundle", return_value=[]
            ),
        ):
            # Should not raise TypeError: string indices must be integers
            phishunt_connector._process_private_feed("work_id")

    def test_iterates_over_list_response(self, phishunt_connector):
        """_process_private_feed must also handle a plain list response (backward compat)."""
        api_response = [{"url": "http://phishing.example.com"}]
        mock_resp = MagicMock()
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()

        with (
            patch("requests.request", return_value=mock_resp),
            patch.object(
                phishunt_connector.helper, "send_stix2_bundle", return_value=[]
            ),
        ):
            phishunt_connector._process_private_feed("work_id")
