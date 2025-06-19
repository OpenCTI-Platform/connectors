#!/usr/bin/env python3
import requests
from requests.compat import urljoin


class Onyphe:
    """Wrapper around the Onyphe REST API
    :param key: The Onyphe API key
    :type key: str
    :param base_url: The Onyphe API URL
    :type key: str
    """

    def __init__(self, key: str, base_url: str):
        """Intializes the API object
        :param key: The Onyphe API key
        :type key: str
        """
        self.api_key = key
        self.base_url = base_url
        self._session = requests.Session()

    def _request(self, path: str, query_params=None):
        """Specialized wrapper around the requests module to request data from Onyphe
        :param path: The URL path after the onyphe FQDN
        :type path: str
        :param query_params: The dictionnary of query parameters that gets appended to the URL
        :type query_params: str
        """

        if query_params is None:
            query_params = {}
        query_params["apikey"] = self.api_key
        url = urljoin(self.base_url, path)

        try:
            response = self._session.get(url=url, data=query_params)
        except Exception as exc:
            raise APIGeneralError(f"Couldn't connect to ONYPHE API : {url}") from exc

        if response.status_code == 429:
            raise APIRateLimiting(response.text)
        try:
            response_data = response.json()
        except Exception as exc:
            raise APIError(f"Couldn't parse response JSON from: {url}") from exc

        if response_data["error"] > 0:
            raise APIGeneralError(
                f'Error {response_data["error"]} {response_data["text"]} : {url}'
            )

        return response_data

    def summary(self, data: str, datatype: str):
        """Return a summary of all information we have for the given IPv{4,6} address."""
        if datatype == "domain":
            url_path = f"summary/domain/{data}"
        elif datatype == "fqdn":
            url_path = f"summary/hostname/{data}"
        else:
            url_path = f"summary/ip/{data}"
        return self._request(path=url_path)

    def search_oql(self, oql: str):
        """Return data from specified category using Search API and the provided data as the OQL filter."""
        url_path = f"search/?q={oql}"
        return self._request(path=url_path)


class APIError(Exception):
    """This exception gets raised when the returned error code is non-zero positive"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class APIRateLimiting(Exception):
    """This exception gets raised when the 429 HTTP code is returned"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class APIGeneralError(Exception):
    """This exception gets raised when there is a general API connection error"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class OtherError(Exception):
    """This exception gets raised when we can't parse an other observable"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
