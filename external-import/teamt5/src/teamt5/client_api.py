from datetime import datetime, timedelta, timezone

import requests

_OAUTH_TOKEN_URL = "https://api.threatvision.org/oauth/token"


class ConnectorClient:
    def __init__(self, helper, config) -> None:
        """
        Initialises the the ConnectorClient.

        :param helper: The OpenCTI connector helper object.
        :param config: The connector configuration object.
        """

        self.helper = helper
        self.config = config

        self.session = requests.Session()

        if config.client_id and config.client_secret:
            self._token = None
            self._token_expires_at = None
            self._refresh_token()
        else:
            self.session.headers.update({"Authorization": f"Bearer {config.api_key}"})

    def _refresh_token(self):
        resp = requests.post(
            _OAUTH_TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        expires_in = int(data.get("expires_in", 3600))
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=expires_in - 60
        )
        self.session.headers.update({"Authorization": f"Bearer {self._token}"})

    def _ensure_valid_token(self):
        if not (self.config.client_id and self.config.client_secret):
            return
        if (
            self._token_expires_at is None
            or datetime.now(timezone.utc) >= self._token_expires_at
        ):
            self._refresh_token()

    def _request_data(self, url: str, params=None):
        """
        Makes a get request to a Team T5 API url.

        :param url: The URL to request data from.
        :param params: Optional dictionary of query parameters.
        :return: A response object on success, or None on failure.
        """
        self._ensure_valid_token()

        timeout = 10

        try:
            # validate the response and add a small delay as to not overload the API
            response = self.session.get(url, params=params, timeout=timeout)

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "Request Error while fetching data",
                {"url_path": {url}, "error": {str(err)}},
            )
        return None
