""" Wrapper function for http requests."""

# third-party
import requests

# first-party
from http_.exceptions import ApiResponseException

TIMEOUT = 10.0


def http_request(
    method,
    url: str,
    ok_code: int,
    timeout: int = TIMEOUT,
    **kwargs,
):
    """Wrap request method for handling status codes."""
    response = requests.request(
        method=method,
        url=url,
        timeout=timeout,
        **kwargs,
    )
    if response.status_code != ok_code:
        raise ApiResponseException(method, url=url, res=response)
    if response.status_code == requests.codes["no_content"]:
        return None
    return response.json()
