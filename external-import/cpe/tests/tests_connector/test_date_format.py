"""Date-based import: the dates sent to the NIST API must survive URL decoding."""

from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest
from cpe.connector import CPEConnector


def _connector() -> CPEConnector:
    """Build a CPEConnector with every external dependency mocked."""
    config = MagicMock()
    config.cpe.base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    config.cpe.api_key.get_secret_value.return_value = "api-key"

    connector = CPEConnector(config=config, helper=MagicMock())
    connector.last_run = 1761800000
    connector.current_run = 1761803600
    return connector


@pytest.fixture
def mock_session(monkeypatch):
    """Patch requests.Session so no HTTP call is made."""
    session = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
    }
    session.get.return_value = response
    monkeypatch.setattr("cpe.connector.requests.Session", lambda: session)
    return session


def test_date_is_utc_iso_8601_with_z_suffix():
    assert _connector()._get_date_iso(1761800000) == "2025-10-30T04:53:20Z"


def test_import_date_sends_dates_the_api_can_parse(mock_session):
    """A "+00:00" offset is decoded as " 00:00" and NIST answers 404 (#7864)."""
    _connector()._import_date("work-id")

    api_url = mock_session.get.call_args.args[0]
    query = parse_qs(urlsplit(api_url).query)
    assert query["lastModStartDate"] == ["2025-10-30T04:53:20Z"]
    assert query["lastModEndDate"] == ["2025-10-30T05:53:20Z"]
