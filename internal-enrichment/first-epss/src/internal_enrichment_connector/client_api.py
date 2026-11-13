from connectors_sdk import BaseClientApi


class ConnectorClient(BaseClientApi):
    """Client for the FIRST EPSS API (https://www.first.org/epss/api)."""

    def get_epss_scores(self, cve: str) -> list[dict[str, str]]:
        """Return the EPSS records of a CVE.

        Transient errors (408, 429, 5xx, connection errors) are retried with
        exponential backoff by `BaseClientApi` before an exception is raised.

        Returns:
            The `data` list of the API response (`cve`, `epss`, `percentile`
            and `date` as strings), empty when FIRST has no EPSS score for
            this CVE.

        Raises:
            ApiClientError: On an HTTP error, after retries for transient ones.
            requests.RequestException: On a network error, after retries.
        """
        # The configured base URL is the endpoint itself: pass it as an absolute URL
        response = self._get(self._base_url, params={"cve": cve})
        return response.get("data") or []
