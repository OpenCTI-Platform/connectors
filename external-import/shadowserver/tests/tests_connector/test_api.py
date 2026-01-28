import json
import os
from unittest.mock import MagicMock

import pytest
import requests
from pycti import OpenCTIConnectorHelper
from shadowserver.api import ShadowserverAPI
from shadowserver.utils import from_list_to_csv

FIXTURES_DIR = "fixtures"


class TestShadowserverAPI:
    api_key = "test_api_key"
    api_secret = "test_api_secret"
    marking_refs = "TLP:WHITE"
    default_date = "2024-01-11"

    @pytest.fixture
    def shadow_server_api(self):
        """Create an instance of the API class."""
        return ShadowserverAPI(self.api_key, self.api_secret, self.marking_refs)

    def load_fixture(self, filename):
        """Load a fixture file and return its content.

        Args:
            filename (str): The name of the fixture file.

        Returns:
            dict: The content of the fixture file, parsed as a JSON object.

        Raises:
            FileNotFoundError: If the fixture file does not exist.
            ValueError: If the fixture file is empty.
        """
        filepath = os.path.join(os.path.dirname(__file__), "..", FIXTURES_DIR, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Fixture {filename} not found.")

        with open(filepath, "r") as file:
            content = file.read().strip()

        if not content:
            raise ValueError(f"Fixture {filename} is empty.")

        return json.loads(content)

    def shadowserver_fixture(self, fixture: str, shadow_server_api, fixture_mocker):
        """Load a fixture file and return its content."""
        mock_request = fixture_mocker.patch.object(shadow_server_api, "_request")
        mock_request.return_value = self.load_fixture(fixture)

    def test_init_api_key(self, shadow_server_api):
        assert shadow_server_api.api_key == "test_api_key"

    def test_init_api_secret(self, shadow_server_api):
        assert shadow_server_api.api_secret == "test_api_secret"

    def test_init_marking_refs(self, shadow_server_api):
        assert shadow_server_api.marking_refs.name == "TLP:WHITE"

    def test_init_marking_refs_invalid(self):
        with pytest.raises(KeyError):
            ShadowserverAPI(
                api_key="test_api_key",
                api_secret="test_api_secret",
                marking_refs="invalid_marking_refs",
            )

    def test_init_session(self, shadow_server_api):
        """Test the session property."""
        assert shadow_server_api.session is not None

    def test_get_report_list(self, shadow_server_api, mocker):
        """Test the get_report_list method."""
        self.shadowserver_fixture(
            "report_list.json",
            fixture_mocker=mocker,
            shadow_server_api=shadow_server_api,
        )
        report_list = shadow_server_api.get_report_list(self.default_date)
        assert len(report_list) > 0
        assert len(report_list) == 12

    def test_get_subscriptions(self, shadow_server_api, mocker):
        """Test the get_subscriptions method."""
        self.shadowserver_fixture(
            "subscriptions.json",
            fixture_mocker=mocker,
            shadow_server_api=shadow_server_api,
        )
        subscriptions = shadow_server_api.get_subscriptions()
        assert len(subscriptions) > 0
        assert len(subscriptions) == 13

    def test_get_report(self, shadow_server_api, mocker):
        """Test the get_report method."""
        # Load the fixture and convert to CSV
        fixture_data = self.load_fixture("report_type_blocklist.json")
        csv_content = from_list_to_csv(fixture_data).encode("utf-8")

        # Mock the session.get to return CSV content
        mock_response = MagicMock()
        mock_response.content = csv_content
        mock_response.raise_for_status = MagicMock()
        mock_get = mocker.patch.object(shadow_server_api.session, "get")
        mock_get.return_value = mock_response

        reports = shadow_server_api.get_report(report_id="test_report_id")
        assert reports == csv_content
        assert len(reports) > 0

    def test_get_report_id_invalid(self, shadow_server_api, mocker):
        """Test the get_report method with an invalid report ID."""
        # Mock session.get to raise HTTPError
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "404 Not Found"
        )
        mock_get = mocker.patch.object(shadow_server_api.session, "get")
        mock_get.return_value = mock_response

        # get_report logs the error and returns empty bytes
        result = shadow_server_api.get_report(report_id="invalid_report_id")
        assert result == b""

    def test_all_fixture_types(self, shadow_server_api, mocker):

        self.api_helper = MagicMock(spec=OpenCTIConnectorHelper)
        self.api_helper.connector_logger = MagicMock()
        self.api_helper.connector_logger.debug = MagicMock()
        self.api_helper.connector_logger.info = MagicMock()
        self.api_helper.connector_logger.error = MagicMock()

        filepath = os.path.join(os.path.dirname(__file__), "..", FIXTURES_DIR)
        report_files = [f for f in os.listdir(filepath) if f.startswith("report_type")]
        for report_file in report_files:
            report_type = report_file.replace("report_type_", "").replace(".json", "")

            # Load the JSON fixture and convert to CSV
            fixture_data = self.load_fixture(report_file)

            csv_content = from_list_to_csv(fixture_data).encode("utf-8")

            # Mock get_report to return CSV content
            mock_get_report = mocker.patch.object(shadow_server_api, "get_report")
            mock_get_report.return_value = csv_content

            report = {"id": "test_report_id", "report": report_type}

            stix_reports = shadow_server_api.get_stix_report(
                report=report, api_helper=self.api_helper
            )

            assert len(stix_reports) > 0
