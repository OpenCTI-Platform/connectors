from unittest import mock

import pytest
import requests


@pytest.mark.usefixtures("setup_config")
class TestApiClient(object):

    @pytest.mark.parametrize(
        "exceptions_type, exception_raised, status_code, error_message",
        [
            (
                requests.exceptions.HTTPError(),
                requests.exceptions.HTTPError,
                401,
                "Permissions Error, Kaspersky returned a 401, please check your API key",
            ),
            (
                requests.exceptions.HTTPError(),
                requests.exceptions.HTTPError,
                404,
                "File not found on Kaspersky, no enrichment possible",
            ),
            (
                requests.exceptions.HTTPError(),
                requests.exceptions.HTTPError,
                None,
                "Http error",
            ),
            (
                requests.exceptions.ConnectionError(),
                requests.exceptions.ConnectionError,
                None,
                "Error connecting",
            ),
            (
                requests.exceptions.Timeout(),
                requests.exceptions.Timeout,
                None,
                "Timeout error",
            ),
            (
                requests.exceptions.RequestException(),
                requests.exceptions.RequestException,
                None,
                "Something else happened",
            ),
        ],
    )
    @pytest.mark.usefixtures("fixture_data")
    def test_api_errors(
        self, exceptions_type, exception_raised, status_code, error_message
    ):
        mock_response = mock.MagicMock()
        mock_response.raise_for_status.side_effect = exceptions_type
        with mock.patch.object(self.mock_helper, "connect_scope", "Hostname"):
            with mock.patch(
                "kaspersky_client.api_client.requests.Session.get"
            ) as mock_get:
                mock_get.return_value = mock_response
                if status_code:
                    mock_get.return_value.status_code = status_code
                with pytest.raises(exception_raised):
                    self.api_client._request_data("https://test.com", {})
                self.mock_helper.connector_logger.error.assert_called_with(
                    error_message, {"error": exceptions_type}
                )
