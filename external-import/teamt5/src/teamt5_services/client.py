import time
from typing import Optional

import requests
from connectors_sdk import (
    ErrorStore,
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
from teamt5_services.adapters import RetryingAdapter
from teamt5_services.auth import JWTClientCredentialAuth, TokenRequestError

# The standardized error raised for each HTTP status the TeamT5 API answers with
HTTP_STATUS_ERRORS: dict[int, type[ProviderApiError]] = {
    401: ProviderApiAuthenticationError,
    403: ProviderApiAuthorizationError,
    404: ProviderApiNotFoundError,
    429: ProviderApiRateLimitError,
}


def _request_error_class(
    err: requests.exceptions.RequestException,
) -> type[ProviderApiError]:
    """Return the standardized error matching a failed request to the TeamT5 API."""
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
    # response.json() raises it on a body that is not JSON: it is a RequestException
    if isinstance(err, requests.exceptions.JSONDecodeError):
        return ProviderApiInvalidResponseError
    return ProviderApiUnknownError


def _token_error_class(
    err: requests.exceptions.RequestException | ValueError | KeyError,
) -> type[ProviderApiError]:
    """Return the standardized error matching a failed OAuth token exchange.

    The token endpoint answers rejected credentials (``invalid_client``) with a 400 as
    often as with a 401, so a 400 is an authentication failure here only. A body that
    is not JSON, or JSON without ``access_token`` or with an invalid ``expires_in``, is
    an invalid response.
    """
    if isinstance(err, requests.exceptions.RequestException):
        if (
            isinstance(err, requests.exceptions.HTTPError)
            and err.response is not None
            and err.response.status_code == 400
        ):
            return ProviderApiAuthenticationError
        return _request_error_class(err)
    return ProviderApiInvalidResponseError


class Teamt5Client:

    # Safety margin (seconds) before the OAuth token expiry at which a new token
    # is requested, so a token about to expire is never sent to the API.
    _TOKEN_EXPIRY_MARGIN_SEC = 60

    # Attempts of a request, and the wait before the second one, in seconds,
    # doubled before each next one (see ``RetryingAdapter``)
    _MAX_ATTEMPTS = 5
    _RETRY_BACKOFF_SEC = 1

    def __init__(self, helper, config) -> None:
        """
        Initialises the the Teamt5Client.

        :param helper: The OpenCTI connector helper object.
        :param config: The connector configuration object.
        """

        self.helper = helper
        self.config = config

        self.session = requests.Session()
        # Every request of the session is retried on a network error, a timeout
        # or a server error: the adapter replaces the default ones, mounted on
        # these prefixes. ``request_data`` reports a failure once the retries
        # are exhausted.
        retrying_adapter = RetryingAdapter(
            max_attempts=self._MAX_ATTEMPTS, backoff=self._RETRY_BACKOFF_SEC
        )
        self.session.mount("https://", retrying_adapter)
        self.session.mount("http://", retrying_adapter)

        teamt5_cfg = self.config.teamt5
        self._api_base_url = teamt5_cfg.api_base_url
        self._client_id = (
            teamt5_cfg.client_id.get_secret_value()
            if teamt5_cfg.client_id is not None
            else None
        )
        self._client_secret = (
            teamt5_cfg.client_secret.get_secret_value()
            if teamt5_cfg.client_secret is not None
            else None
        )
        self._api_key = (
            teamt5_cfg.api_key.get_secret_value()
            if teamt5_cfg.api_key is not None
            else None
        )

        if self._client_id and self._client_secret:
            # OAuth takes precedence when both auth paths are present. The auth
            # requests a token on the first request, requests a new one before it
            # expires, and once when the API answers 401.
            self.session.auth = JWTClientCredentialAuth(
                token_url=f"{self._api_base_url.rstrip('/')}/oauth/token",
                client_id=self._client_id,
                client_secret=self._client_secret,
                leeway=self._TOKEN_EXPIRY_MARGIN_SEC,
            )
        elif self._api_key:
            self.session.headers.update({"Authorization": f"Bearer {self._api_key}"})
        # The settings model's validator guarantees one of the two paths is
        # populated, so no further branch is needed here.

    def request_data(
        self, url: str, params=None, throttle: bool = False
    ) -> Optional[dict]:
        """
        Make a GET request to a TeamT5 API URL and return the decoded JSON body.

        :param url: The URL to request data from.
        :param params: Optional dictionary of query parameters.
        :param throttle: When ``True``, sleep for one second AFTER a
            successful response. Reserved for tight pagination loops
            (``BaseHandler.retrieve_bundle_references``) where back-to-back
            GETs against the same listing endpoint are paced to avoid
            hammering the upstream API. The default ``False`` keeps
            STIX bundle downloads (``BaseHandler.push_objects``) unthrottled —
            on a run with many bundles, an unconditional one-second
            sleep after every GET would silently add minutes to the
            wall-clock time of every cycle.
        :return: The decoded JSON object of the response on success, or ``None`` on failure (HTTP error, network error, or a body that is not a JSON object), recorded in the ``ErrorStore`` as the matching standardized error. A request fails only once its retries are exhausted (see ``RetryingAdapter``).
        """
        timeout = 15

        try:
            response = self.session.get(
                url, params=params, timeout=timeout
            )  # This GET is retried on network errors, timeouts and server errors by the RetryingAdapter mounted on the session
            response.raise_for_status()  # Raises only HTTPError, which is a RequestException subclass, on 4xx/5xx responses
            payload = response.json()
            if not isinstance(payload, dict):
                # A ``null`` body or a JSON array: ``None`` then always means a
                # failure already recorded here
                error_msg = (
                    f"Invalid response from: {url}: the body is not a JSON object"
                )
                ErrorStore().record_error(ProviderApiInvalidResponseError(error_msg))
                self.helper.connector_logger.warning(error_msg)
                return None
            # Only the pagination caller opts into the throttle (see the
            # ``throttle`` argument docstring above) — bundle downloads
            # do NOT pay this cost.
            if throttle:
                time.sleep(1)
            return payload

        # ``requests.RequestException`` is the root of the requests
        # exception hierarchy and covers ``HTTPError`` /
        # ``ConnectionError`` / ``ConnectTimeout`` / ``ReadTimeout``
        # alongside the less-common ``SSLError`` / ``TooManyRedirects``
        # / ``ChunkedEncodingError`` / ``ContentDecodingError`` /
        # ``ProxyError`` / ``MissingSchema`` shapes that the previous
        # narrow tuple let bubble up and crash the run. Catching the
        # root keeps the contract — "transport errors return ``None``,
        # callers handle the failure" — consistent across every
        # ``requests`` exception class current and future.
        #
        # The failure is recorded in the ``ErrorStore`` as the matching
        # standardized error, without being raised, so the run reports it.
        # A body that is not JSON lands here too: ``requests``'
        # ``JSONDecodeError`` is a ``RequestException``.
        # The OAuth token request failed. It is recorded like any failed request,
        # as the standardized error matching its cause, and ``None`` stops the
        # caller: the run continues with the next handler, whose requests may
        # succeed. The original exception is kept as the error's cause.
        except TokenRequestError as err:
            cause = err.__cause__
            error = _token_error_class(cause)(
                f"Failed to obtain OAuth token from TeamT5: {cause}"
            )
            error.__cause__ = cause
            ErrorStore().record_error(error)
            self.helper.connector_logger.error(
                "TeamT5 OAuth token exchange failed",
                meta={"token_url": self.session.auth.token_url, "error": str(cause)},
            )
        except requests.RequestException as err:
            error_msg = f"Failed request to: {url} {err}"
            ErrorStore().record_error(_request_error_class(err)(error_msg))
            self.helper.connector_logger.warning(error_msg)
        return None
