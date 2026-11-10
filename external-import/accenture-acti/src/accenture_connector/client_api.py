from typing import Any

import requests
from connectors_sdk import (
    ProviderApiAuthenticationError,
    ProviderApiAuthorizationError,
    ProviderApiConnectionError,
    ProviderApiError,
    ProviderApiInvalidResponseError,
    ProviderApiNotFoundError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    ProviderApiUnknownError,
)
from pycognito import Cognito

# The standardized error raised for each HTTP status the source API answers with
HTTP_STATUS_ERRORS: dict[int, type[ProviderApiError]] = {
    401: ProviderApiAuthenticationError,
    403: ProviderApiAuthorizationError,
    404: ProviderApiNotFoundError,
    429: ProviderApiRateLimitError,
}


def _request_error_class(
    err: requests.exceptions.RequestException,
) -> type[ProviderApiError]:
    """Return the standardized error matching a failed request to the source API."""
    if isinstance(err, requests.exceptions.HTTPError):
        status_code = err.response.status_code if err.response is not None else None
        if status_code in HTTP_STATUS_ERRORS:
            return HTTP_STATUS_ERRORS[status_code]
        if status_code is not None and status_code >= 500:
            return ProviderApiServerError
        return ProviderApiUnknownError
    # Before ConnectionError: ConnectTimeout is both a ConnectionError and a Timeout
    if isinstance(err, requests.exceptions.Timeout):
        return ProviderApiTimeoutError
    if isinstance(err, requests.exceptions.ConnectionError):
        return ProviderApiConnectionError
    if isinstance(err, requests.exceptions.JSONDecodeError):
        return ProviderApiInvalidResponseError
    return ProviderApiUnknownError


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.base_api_url = "https://api.intel.accenture.com"
        self.session = requests.Session()

    def _refresh_and_set_token(self):
        """
        :return:
        """
        try:
            u = Cognito(
                user_pool_id=self.config.accenture_acti.user_pool_id,
                client_id=self.config.accenture_acti.client_id,
                username=self.config.accenture_acti.username,
            )
            u.authenticate(self.config.accenture_acti.password.get_secret_value())
            id_token = u.id_token

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "Authorization": f"Bearer {id_token}",
            }
            self.session.headers.update(headers)

        except Exception as err:
            error_msg = f"[API] Error while retrieving token: {err}"
            self.helper.connector_logger.error(error_msg, {"error": str(err)})

            raise ProviderApiAuthenticationError(error_msg) from err

    def get_reports(self, since: str, until: str) -> Any:
        """
        :param since:
        :return:
        :raises ProviderApiError: The standardized error matching the failure.
        """
        # Raises ProviderApiAuthenticationError, which must not be wrapped below
        self._refresh_and_set_token()

        try:
            api_url = self.base_api_url + "/collections/acti/collections"
            params = {"start_date": since, "end_date": until}
            r = self.session.get(api_url, params=params)
            r.raise_for_status()
            return r.json()

        except requests.exceptions.RequestException as err:
            error_msg = f"[API] Error while retrieving reports since: {since}: {err}"
            self.helper.connector_logger.error(error_msg)
            raise _request_error_class(err)(error_msg) from err
