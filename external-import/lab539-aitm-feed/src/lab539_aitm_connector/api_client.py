"""Lab539 AiTM Feed API client."""

import requests
from pydantic import SecretStr


class AiTMFeedClient:
    """Client for the Lab539 AiTM Feed API."""

    def __init__(self, api_key: SecretStr, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Bearer {api_key.get_secret_value()}"}
        )

    def get_last_event(self) -> str | None:
        """
        Lightweight pre-check for new data via the last-event endpoint.

        Uses the shared session (connection reuse, proxies) and only swallows
        request-level errors, returning None so the caller fails open and pulls
        the full dataset rather than masking unexpected errors.
        """
        try:
            response = self.session.get(f"{self.base_url}/last-event", timeout=10)
            response.raise_for_status()
            return response.json().get("eventid")
        except requests.exceptions.RequestException:
            return None

    def get_records(self, after: int | None = None, before: int | None = None) -> list:
        """
        Fetch records from the AiTM feed.
        If no parameters passed, returns full 7 day dataset.
        """
        params = {}
        if after is not None:
            params["after"] = str(after)
        if before is not None:
            params["before"] = str(before)

        try:
            response = self.session.get(
                f"{self.base_url}/list",
                params=params,
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            raise RuntimeError(
                f"AiTM Feed API error: {e.response.status_code} - {e.response.text}"
            ) from e
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError("AiTM Feed API unreachable") from e
        except requests.exceptions.Timeout as e:
            raise RuntimeError("AiTM Feed API request timed out") from e
