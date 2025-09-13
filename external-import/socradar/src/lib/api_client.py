from datetime import datetime, timedelta, timezone

import requests
from requests.adapters import HTTPAdapter, Retry


class RadarAPIError(Exception):
    """Custom wrapper for exceptions raised in RadarAPIClient"""


class RadarFeedItemExtraInfo:
    """Represent a feed item extra info in GET /feed_list/:collection_id.json response."""

    def __init__(self, score: int, seen_count: int):
        self.score: None | int = score
        self.seen_count: int = seen_count


class RadarFeedItem:
    """Represent a feed item in GET /feed_list/:collection_id.json response."""

    def __init__(
        self,
        feed: str,
        feed_type: str,
        first_seen_date: str,
        latest_seen_date: str,
        maintainer_name: str,
        extra_info: dict,
    ):
        self.feed = feed
        self.feed_type = feed_type
        self.maintainer_name = maintainer_name
        self.first_seen_date: datetime = (
            datetime.fromisoformat(first_seen_date).replace(tzinfo=timezone.utc)
            if first_seen_date
            else None
        )
        self.latest_seen_date: datetime = (
            datetime.fromisoformat(latest_seen_date).replace(tzinfo=timezone.utc)
            if latest_seen_date
            else None
        )
        self.extra_info = RadarFeedItemExtraInfo(
            score=extra_info.get("score"),
            seen_count=extra_info.get("seen_count"),
        )


class RadarAPIClient:
    def __init__(
        self,
        api_base_url: str,
        api_key: str,
        retry: int = 3,
        backoff: timedelta = timedelta(seconds=1),
    ):
        """
        Initialize the client with necessary configurations
        """
        self.api_base_url = api_base_url
        self.api_key = api_key

        # Define headers in session and update when needed
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

        retry_strategy = Retry(
            total=retry,
            backoff_factor=backoff.total_seconds(),
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False,  # do not raise MaxRetryError - let response.raise_for_status() raise exceptions
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount(self.api_base_url, adapter)

    def _send_request(self, method: str, url: str, **kwargs):
        """
        Send a request to SOCRadar API.
        :param method: Request HTTP method
        :param url: Request URL
        :param kwargs: Any arguments valid for session.request() method
        :return: Any data returned by the API
        """
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            if response.content:
                return response.json()
        except requests.RequestException as err:
            raise RadarAPIError(
                f"Error while fetching SOCRadar API: {err}",
                {"url": f"{method.upper()} {url}", "error": err},
            ) from err

    def get_feed(self, collection_id: str) -> list[dict]:
        """
        Get feed for given collection ID.
        :param collection_id: Collection ID to get feed from.
        :return: Collection's feed items
        """
        url = f"{self.api_base_url}{collection_id}.json?v=2&key={self.api_key}"
        data = self._send_request("GET", url, timeout=30)

        return [RadarFeedItem(**item) for item in data]
