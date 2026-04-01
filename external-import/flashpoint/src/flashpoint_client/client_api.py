import base64
from datetime import datetime, timedelta
from typing import Generator

import requests
from pydantic import ValidationError
from requests.adapters import HTTPAdapter, Retry

from .models import CompromisedCredentialSighting


class FlashpointClientError(Exception):
    """
    Custom exception for Flashpoint client errors
    """


class FlashpointClient:

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
        self.api_base_url = (
            api_base_url.rstrip("/") if isinstance(api_base_url, str) else api_base_url
        )

        # Define headers in session and update when needed
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

        retry_strategy = Retry(
            total=retry,
            backoff_factor=backoff.total_seconds(),
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False,  # do not raise MaxRetryError - let response.raise_for_status() raise exceptions
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount(self.api_base_url, adapter)

    @staticmethod
    def _to_flashpoint_datetime(value: datetime) -> str:
        return value.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )  # UTC as +00:00 offset leads to 400 Bad Request

    def get_communities_doc(self, doc_id):
        """
        :param doc_id:
        :return:
        """
        url = self.api_base_url + "/sources/v2/communities/" + doc_id
        params = {}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def communities_search(self, query: str, start_date: datetime) -> list[dict]:
        """
        :param query:
        :param start_date:
        :return:
        """
        url = self.api_base_url + "/sources/v2/communities"
        page = 0
        body_params = {
            "query": query,
            "include": {
                "date": {
                    "start": self._to_flashpoint_datetime(start_date),
                    "end": "",
                }
            },
            "size": "1000",
            "sort": {"date": "asc"},
            "page": page,
        }
        results = []
        has_more = True
        while has_more:
            response = self.session.post(url, json=body_params)
            response.raise_for_status()
            data = response.json()
            results.extend(data.get("items"))
            if len(results) < data.get("total").get("value"):
                page += 1
            else:
                has_more = False
        return results

    def get_media_doc(self, doc_id):
        """
        :param doc_id:
        :return:
        """
        url = self.api_base_url + "/sources/v2/media/" + doc_id
        params = {}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def get_media(self, media_id):
        """
        :return:
        """
        url = self.api_base_url + "/sources/v1/media"
        params = {"cdn": False, "asset_id": media_id}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return base64.b64encode(response.content), response.headers.get("Content-Type")

    def get_alerts(self, start_date: datetime) -> list[dict]:
        """
        :return:
        """
        alerts = []
        url = self.api_base_url + "/alert-management/v1/notifications"
        params = {"created_after": self._to_flashpoint_datetime(start_date)}
        has_more = True
        while has_more:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            if data.get("pagination").get("next"):
                url = data.get("pagination").get("next")
            else:
                has_more = False
            alerts.extend(data.get("items"))
        return alerts

    def get_reports(self, start_date: datetime) -> list[dict]:
        """
        :return:
        """
        url = self.api_base_url + "/finished-intelligence/v1/reports"
        limit = 100
        params = {
            "since": self._to_flashpoint_datetime(start_date),
            "limit": limit,
            "skip": 0,
            "sort": "updated_at:asc",
            "embed": "asset",
        }
        has_more = True
        reports = []
        while has_more:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            response_json = response.json()
            total = response_json.get("total")
            reports.extend(response_json.get("data", []))
            params["skip"] += limit
            if len(reports) == total:
                has_more = False
        return reports

    def iter_indicators_pages(
        self, start_date: datetime, size: int = 500
    ) -> Generator[list[dict], None, None]:
        """
        Iterate over indicator pages from Flashpoint Technical Intelligence v2 API.

        :param start_date: Include indicators modified on or after this datetime.
        :param size: Pagination size, must be between 1 and 500.
        :yield: Page of indicators.
        """
        page_size = max(1, min(size, 500))
        url = self.api_base_url + "/technical-intelligence/v2/indicators"
        params = {
            "size": page_size,
            "from": 0,
            "sort": "modified_at:asc",
            "modified_after": self._to_flashpoint_datetime(start_date),
            "include_total_count": False,
            "embed": "all",
        }
        fallback_from = 0

        has_more = True
        while has_more:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            response_json = response.json()
            page_items = response_json.get("items")
            if page_items:
                yield page_items

            next_page = (response_json.get("pagination") or {}).get("next")
            if next_page:
                url = next_page
                params = None
            else:
                if params is not None and len(page_items) == page_size:
                    # In case of missing pagination info, fallback to from/size pagination.
                    # (This mimics the returned results if the API had returned a next page link with from/size parameters.)
                    fallback_from += page_size
                    params["from"] = fallback_from
                else:
                    has_more = False

    def get_compromised_credential_sightings(
        self, since: datetime | None = None, fresh_only: bool = True
    ) -> Generator[CompromisedCredentialSighting, None, None]:
        """
        Get Compromised Credentials Sightings from Flashpoint API.

        :param since: The minimum date to search for Compromised Credentials Sightings.
        :param fresh_only: If True (default), only return fresh sightings, otherwise return all sightings.
        :return: Found Compromised Credentials Sightings

        Doc: https://docs.flashpoint.io/flashpoint/reference/common-use-cases-2#retrieve-compromised-credential-sightings-for-the-last-24-hours-or-a-specified-time-interval
        """
        url = self.api_base_url + "/sources/v1/noncommunities/search"

        since_timestamp = int(datetime.timestamp(since)) if since else None
        body = {
            "query": (
                "+basetypes:(credential-sighting)"
                + (f" +header_.indexed_at: [{since_timestamp} TO now]" if since else "")
                + (" +is_fresh:(true)" if fresh_only else "")
            ),
            "sort": ["header_.indexed_at:asc"],
            "size": 25,
            "scroll": "2m",
        }

        try:
            sightings_count = 0
            while True:
                response = self.session.post(url, json=body)
                response.raise_for_status()
                data: dict = response.json()

                # /search endpoint returns total hits as an integer
                total_hits: int = data["hits"]["total"]
                # /scroll endpoint returns total hits as a dict {'relation': str, 'value': int}
                if isinstance(total_hits, dict):
                    total_hits: int = data["hits"]["total"]["value"]  # type: ignore[no-redef]

                results: list[dict] = data["hits"]["hits"]
                for result in results:
                    try:
                        sighting = CompromisedCredentialSighting.model_validate(
                            result["_source"]
                        )
                        yield sighting
                    except ValidationError as err:
                        raise FlashpointClientError(
                            "Invalid Compromised Credential Sighting data"
                        ) from err

                sightings_count += len(results)
                if sightings_count == total_hits:
                    break

                url = self.api_base_url + "/sources/v1/noncommunities/scroll?scroll=2m"
                body = {"scroll_id": data["_scroll_id"]}
        except requests.HTTPError as err:
            raise FlashpointClientError(
                "Failed to fetch Compromised Credential Sightings"
            ) from err
