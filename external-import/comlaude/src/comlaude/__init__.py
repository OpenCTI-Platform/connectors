import json
import logging
from datetime import datetime, timedelta

import jwt  # pip install pyjwt
from requests import Session

API_BASE_URL = "https://api.comlaude.com"

DEFAULT_PAGE_LIMIT = 500
DEFAULT_TIMEOUT = 30

LOGGER = logging.getLogger(__name__)

# API Documentation: https://api.comlaude.com


class ComLaudeAuth(object):
    """ComLaude API to collect audit data."""

    def __init__(  # noqa: WPS211
        self,
        username,
        password,
        api_key,
        comlaude_token=None,
        http_session=None,
        timeout=DEFAULT_TIMEOUT,
    ):
        """
        Initialize the data object.
        Args:
            tenant: ComLaude tenant for organization
                (https://{tenant}.api.identitynow.com)
            username: Authorized User.
            password: Authorized User Password.
            api_key: ComLaude token.
            comlaude_token: Authorization token.
            http_session: Requests Session()
            timeout: Requests timeout for throttling.
        """

        self._creds = {
            "username": username,
            "password": password,
            "api_key": api_key,
        }

        if http_session is None:
            self._http_session = Session()
        else:
            self._http_session = http_session

        self._timeout = timeout
        self._token = None
        self._decoded_token = None
        self.authorization_header = None
        self.api_base_url = API_BASE_URL

        self._load_token(comlaude_token)
        self._verify_token()

    def get_token(self):
        """
            Return authorization token for session.
        Returns:
            Returns the current JWT token.
        """
        return self._token

    def refresh_token(self):
        """Refresh authorization token for session."""
        self.retrieve_token()

    def retrieve_token(self):
        """Return authorization token for session."""
        self._load_token(self._request_token())

    def _load_token(self, token):
        """
        Update _token, decode token, and auth header.
        Args:
            token: Authentication bearer token to be decoded.
        """
        jwt_options = {"verify_signature": False}
        self._token = token
        try:
            self._decoded_token = jwt.decode(
                self._token["access_token"], options=jwt_options
            )
        except jwt.exceptions.DecodeError:
            LOGGER.debug("Poorly formatted Access Token, fetching token using _creds")
            self.retrieve_token()
        except TypeError:
            LOGGER.debug("Token TypeError, fetching token using _creds")
            self.retrieve_token()

        self.authorization_header = {
            "authorization": "Bearer {0}".format(self._token.get("access_token")),
        }

    def _request_token(self):
        """
        Request Authorization Payload.
        Returns:
            Return response Authentication Bearer token from request.
        """
        auth_endpoint = "{}{}".format(self.api_base_url, "/api_login")
        headers = {"content-type": "application/json"}
        response = self._http_session.request(
            "POST",
            auth_endpoint,
            json=self._creds,
            headers=headers,
            timeout=self._timeout,
            verify=False,
        )

        LOGGER.debug("Token JSON: %s", self._creds)
        LOGGER.debug("Token Response: %s", response.text)

        _response_error(
            "Can't get token for user {0}".format(self._creds.get("username")), response
        )
        return json.loads(response.text)["data"]

    def _verify_token(self):
        """Check to see if token is expiring in 12 hours."""
        token_expiration = datetime.fromtimestamp(self._decoded_token["exp"])
        time_difference = datetime.now() + timedelta(hours=12)

        LOGGER.debug("Token expiration time: %s", token_expiration)
        LOGGER.debug("Token comparison time: %s", time_difference)

        if token_expiration <= time_difference:
            self.refresh_token()


class ComLaudeSearch(object):
    """Get Domain List from ComLaude."""

    def __init__(
        self,
        comlaude_auth,
        group_id,
        min_updated_time,
        max_updated_time,
        http_session=None,
        timeout=DEFAULT_TIMEOUT,
    ):
        """
        Initialize the data object.
        Args:
            comlaude_auth: Authentication object.
            group_id: GroupID to search against.
            min_updated_time: Minimum time created to search.
            max_updated_time: Maximum time created to search.
            http_session: Requests Session()
            timeout: Requests timeout for throttling.
        """
        self._timeout = timeout
        self._comlaude_auth = comlaude_auth
        self._group_id = group_id

        self.has_next = False
        self.results = None
        self.api_base_url = comlaude_auth.api_base_url

        self.parameters = {
            "limit": DEFAULT_PAGE_LIMIT,
            "page": 1,  # Start on first page.
            "filter[updated_before]": max_updated_time,
            "filter[updated_after]": min_updated_time,
        }

        if http_session is None:
            self._http_session = Session()
        else:
            self._http_session = http_session

        self.get_search_results()

    def _request_search(self):
        api_search_url = "{}{}{}{}".format(
            self._comlaude_auth.api_base_url,
            "/groups/",
            self._group_id,
            "/domains/search",
        )

        headers = dict(
            {"content-type": "application/json"},
            **self._comlaude_auth.authorization_header
        )

        response = self._http_session.request(
            "POST",
            api_search_url,
            headers=headers,
            params=self.parameters,
            timeout=self._timeout,
            verify=False,
        )

        LOGGER.debug("get_events Response: %s", response.text)

        _response_error("Impossible to retreive events", response)
        return response.json()

    def get_search_results(self):
        """
        Return first events from ComLaude API
        within specified period of time and limit.
        """

        self.results = self._request_search()

        # Check if API_SEARCH_LIMIT event count is being returned.
        if self.results["pagination"]["next"] is not None:
            self.has_next = True
        else:
            self.has_next = False

    def get_next_page(self):
        """
        Return next set of events from ComLaude API
        within specified period of time and limit.
        """
        if self.has_next:
            self.parameters["page"] = self.parameters["page"] + 1
            self.get_search_results()
        else:
            raise "Next page DNE."


def _response_error(message, response):
    if response.status_code == 200:
        return

    if response.status_code == 400:
        error_message = json.loads(response.text)
    else:
        error_message = json.loads(response.text)

    print(
        "Message:{0}. Response code returned:{1}. Error message returned:{2}.".format(
            message, response.status_code, error_message
        )
    )

    raise Exception(
        """Message:{0}.
            Response code returned:{1}.
            Error message returned:{2}.""".format(
            message, response.status_code, error_message
        )
    )
