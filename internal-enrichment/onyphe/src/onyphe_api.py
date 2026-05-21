#!/usr/bin/env python3
import time

import requests
from requests.compat import urljoin


class Onyphe:
    """Wrapper around the Onyphe REST API
    :param key: The Onyphe API key
    :type key: str
    :param base_url: The Onyphe API URL
    :type key: str
    """

    def __init__(self, key: str, base_url: str, max_retries: int = 3):
        """Intializes the API object
        :param key: The Onyphe API key
        :type key: str
        """
        self.api_key = key
        self.base_url = base_url
        self.max_retries = max_retries
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

        for attempt in range(self.max_retries + 1):
            try:
                response = self._session.get(url=url, params=query_params)
            except Exception as exc:
                raise APIGeneralError(
                    f"Couldn't connect to ONYPHE API : {url}"
                ) from exc

            if response.status_code != 429:
                break

            if attempt == self.max_retries:
                raise APIRateLimiting(response.text)

            retry_after = response.headers.get("Retry-After")
            wait = int(retry_after) if retry_after else 2 ** (attempt + 1)
            time.sleep(wait)

        try:
            response_data = response.json()
        except Exception as exc:
            raise OtherError(f"Couldn't parse response JSON from: {url}") from exc

        if response_data["error"] > 0:
            raise APIGeneralError(
                f'Error {response_data["error"]} {response_data["text"]} : {url}'
            )

        return response_data

    def search_oql(self, oql: str, size: int = None, page: int = None):
        """Return a single page of results from the Search API for the provided OQL query."""
        url_path = f"search/?q={oql}"
        query_params = {}
        if size is not None:
            query_params["size"] = size
        if page is not None:
            query_params["page"] = page
        return self._request(
            path=url_path, query_params=query_params if query_params else None
        )

    def search_oql_paginated(self, oql: str, limit: int):
        """Fetch up to limit results, paginating in batches of 100 (API max page size).
        The API caps at 100 pages (10,000 results maximum).
        Returns a dict with 'total' (from the API) and 'results' (accumulated list).
        """
        PAGE_SIZE = 100
        MAX_PAGES = 100

        first_response = self.search_oql(oql, size=min(PAGE_SIZE, limit), page=1)
        total = first_response.get("total", 0)
        results = first_response.get("results", [])

        page = 2
        while len(results) < min(limit, total) and page <= MAX_PAGES:
            remaining = min(limit, total) - len(results)
            page_response = self.search_oql(
                oql, size=min(PAGE_SIZE, remaining), page=page
            )
            page_results = page_response.get("results", [])
            if not page_results:
                break
            results.extend(page_results)
            page += 1

        return {"total": total, "results": results}


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
    """This exception gets raised when we can't parse the json response"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
