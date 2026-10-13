"""Error handling of the CPE connector: NIST API failures must not be silenced."""

from unittest.mock import MagicMock

import pytest
from cpe.connector import CPEConnector, NistApiError


def _connector() -> CPEConnector:
    """Build a CPEConnector with every external dependency mocked."""
    config = MagicMock()
    config.cpe.base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    config.cpe.api_key.get_secret_value.return_value = "invalid-key"
    config.connector.duration_period.total_seconds.return_value = 3600

    helper = MagicMock()
    helper.connect_name = "Common Platform Enumeration"
    helper.connect_id = "connector-id"

    connector = CPEConnector(config=config, helper=helper)
    connector.current_run = 1787638904
    return connector


def _response(status_code: int, headers: dict | None = None, payload=None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.json.return_value = payload
    return response


@pytest.fixture
def mock_session(monkeypatch):
    """Patch requests.Session so no HTTP call is made."""
    session = MagicMock()
    monkeypatch.setattr("cpe.connector.requests.Session", lambda: session)
    return session


class TestNistApiErrors:
    """A non-200 answer must raise, carrying the NIST `message` header."""

    def test_request_params_raises_with_message_header(self, mock_session):
        """NIST answers 404 with an empty body and the reason in a header."""
        mock_session.get.return_value = _response(
            404, headers={"message": "Invalid apiKey."}
        )
        connector = _connector()

        with pytest.raises(NistApiError) as err:
            connector._get_request_params(connector.base_url)

        assert "404" in str(err.value)
        assert "Invalid apiKey." in str(err.value)

    def test_cpe_list_raises_with_message_header(self, mock_session):
        mock_session.get.return_value = _response(
            403, headers={"message": "Rate limit exceeded."}
        )
        connector = _connector()

        with pytest.raises(NistApiError) as err:
            connector._get_cpe_list(connector.base_url)

        assert "403" in str(err.value)
        assert "Rate limit exceeded." in str(err.value)

    def test_error_is_explicit_when_no_message_header(self, mock_session):
        """The header is not guaranteed: the status code must still be reported."""
        mock_session.get.return_value = _response(500)
        connector = _connector()

        with pytest.raises(NistApiError) as err:
            connector._get_request_params(connector.base_url)

        assert "500" in str(err.value)

    def test_request_params_returned_on_success(self, mock_session):
        mock_session.get.return_value = _response(
            200,
            payload={"resultsPerPage": 10, "startIndex": 0, "totalResults": 1234},
        )
        connector = _connector()

        assert connector._get_request_params(connector.base_url) == {
            "resultsPerPage": 10,
            "startIndex": 0,
            "totalResults": 1234,
        }


class TestExecuteImport:
    """A failed import must be reported as such, and must not advance the state."""

    def test_failure_reports_work_in_error_and_keeps_state(self):
        connector = _connector()
        failing_import = MagicMock(side_effect=NistApiError("boom"))

        connector._execute_import(failing_import, interval=3600)

        # The work is reported in error...
        connector.helper.api.work.to_processed.assert_called_once()
        assert connector.helper.api.work.to_processed.call_args.kwargs.get(
            "in_error"
        ) or connector.helper.api.work.to_processed.call_args.args[2:] == (True,)
        # ...the failure is logged at ERROR level...
        connector.helper.log_error.assert_called_once()
        # ...and last_run is left untouched so the next run retries.
        connector.helper.set_state.assert_not_called()

    def test_failure_is_not_reported_as_success(self):
        connector = _connector()
        connector._execute_import(MagicMock(side_effect=NistApiError("boom")), 3600)

        logged = [str(call) for call in connector.helper.log_info.call_args_list]
        assert not any("successfully run" in line for line in logged)

    def test_success_advances_state_and_reports_work(self):
        connector = _connector()
        connector.helper.get_state.return_value = {"last_run": 1}

        connector._execute_import(MagicMock(), 3600)

        connector.helper.set_state.assert_called_once_with(
            {"last_run": connector.current_run}
        )
        assert connector.helper.api.work.to_processed.call_args.kwargs.get(
            "in_error", False
        ) in (False, None)
        connector.helper.log_error.assert_not_called()
