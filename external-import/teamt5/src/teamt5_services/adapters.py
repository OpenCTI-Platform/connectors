import time

import requests
from requests.adapters import HTTPAdapter

# The server errors that do not go away by retrying: method not implemented, HTTP
# version not supported, network authentication required. Any other 5xx is
# retried, the non-standard ones of a CDN (520 to 524) included.
NOT_RETRIED_STATUSES = frozenset({501, 505, 511})
# The methods safe to send again: a POST is never sent twice
RETRY_METHODS = frozenset({"GET", "HEAD"})


def is_retried_status(status_code: int) -> bool:
    """Tell whether a response status is a server error worth retrying."""
    return status_code >= 500 and status_code not in NOT_RETRIED_STATUSES


class RetryingAdapter(HTTPAdapter):
    """A transport adapter sending a request up to ``max_attempts`` times.

    Only a ``GET`` or ``HEAD`` request (``RETRY_METHODS``) is retried; any other
    method is sent once, as by ``HTTPAdapter``. A ``GET`` or ``HEAD`` request is
    sent again while it fails with a network error, a timeout, a connection cut
    while the body is read, or a server error status (see ``is_retried_status``),
    waiting ``backoff * 2 ** (attempt - 1)`` seconds between two attempts (1, 2,
    4, 8 seconds with the default backoff).

    When every attempt fails, the last outcome is returned as is: the last server
    error response, or the last exception raised. The caller sees one call, whatever
    the number of attempts.

    The body is read inside ``send``, so that a connection cut while reading it is
    retried too: urllib3's own ``Retry`` stops once the headers are received. This
    defeats ``stream=True``, which suits small JSON responses only.
    """

    def __init__(self, max_attempts: int = 5, backoff: float = 1.0, **kwargs) -> None:
        """
        :param max_attempts: The number of attempts, the first one included.
        :param backoff: The wait, in seconds, before the second attempt; it doubles
            before each next attempt.
        :param kwargs: The arguments of ``HTTPAdapter``.
        """
        super().__init__(**kwargs)
        self.max_attempts = max_attempts
        self.backoff = backoff

    def send(self, request, **kwargs) -> requests.Response:
        if request.method not in RETRY_METHODS:
            return super().send(request, **kwargs)
        # The count is local: every call has its own ``max_attempts``
        attempt = 1
        while True:
            last_attempt = attempt >= self.max_attempts
            try:
                response = super().send(request, **kwargs)
                if not is_retried_status(response.status_code) or last_attempt:
                    response.content  # read the body: a cut connection is retried
                    return response
                response.close()
            except requests.exceptions.SSLError:
                # A certificate problem does not go away by retrying
                raise
            except (
                requests.ConnectionError,
                requests.Timeout,
                requests.exceptions.ChunkedEncodingError,
            ):
                if last_attempt:
                    raise
            time.sleep(self.backoff * 2 ** (attempt - 1))
            attempt += 1
