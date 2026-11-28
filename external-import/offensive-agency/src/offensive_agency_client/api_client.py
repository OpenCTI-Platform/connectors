"""HTTP client of the offensive.agency STIX feed.

The feed is one public JSON file (a STIX 2.1 bundle of about 7 MB), with no
authentication and no pagination.
"""

from typing import Any

import requests
from connectors_sdk import (
    ApiClientError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    BaseClientApi,
    ProviderApiConnectionError,
    ProviderApiInvalidResponseError,
    ProviderApiNotFoundError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    ProviderApiUnknownError,
)
from offensive_agency_client.models import (
    Feed,
    FeedBundle,
    FeedIndicator,
    FeedRelationship,
    FeedTool,
)
from pydantic import ValidationError

FEED_PATH = "/feeds/stix.json"
# The file is large: give the download more time than the SDK default (60 s).
REQUEST_TIMEOUT_SECONDS = 180
USER_AGENT = "OpenCTI-connector-offensive-agency"


class OffensiveAgencyClient(BaseClientApi):
    """Download and validate the offensive.agency STIX feed.

    `BaseClientApi` provides the session, the retries with backoff on 429/5xx
    and the typed HTTP errors.
    """

    def __init__(self, base_url: str, logger: Any) -> None:
        """Initialize the client.

        Args:
            base_url: Root of the offensive.agency API (e.g.
                `https://www.offensive.agency/api/v1`).
            logger: The connector logger.
        """
        super().__init__(base_url=base_url, timeout=REQUEST_TIMEOUT_SECONDS)
        self._logger = logger

    @property
    def session_headers(self) -> dict[str, str]:
        """Headers sent with every request (the feed needs no authentication)."""
        return {"User-Agent": USER_AGENT}

    def get_feed(self) -> Feed:
        """Download the feed and keep the tools, indicators and relationships.

        Each object is validated on its own: an invalid one is logged at
        WARNING and skipped. Objects of other types (the feed `identity`) are
        ignored, since the connector defines its own author.

        Returns:
            Feed: The validated feed objects.

        Raises:
            ProviderApiError: A concrete subclass when the download fails
                (timeout, connection, rate limit, server error...) or when the
                response is not a STIX bundle. The connector logs it at the top
                level, so it is not logged here.
        """
        data = self._download()

        try:
            bundle = FeedBundle.model_validate(data)
        except ValidationError as err:
            raise ProviderApiInvalidResponseError(
                "The feed did not return a STIX bundle"
            ) from err

        feed = Feed()
        for raw_object in bundle.objects:
            self._add_object(feed, raw_object)

        self._logger.info(
            "Feed downloaded",
            meta={
                "objects": len(bundle.objects),
                "tools": len(feed.tools),
                "indicators": len(feed.indicators),
                "relationships": len(feed.relationships),
            },
        )
        return feed

    def _download(self) -> Any:
        """GET the feed, turning HTTP and network errors into SDK provider errors."""
        try:
            return self._get(FEED_PATH)
        except requests.Timeout as err:
            raise ProviderApiTimeoutError("Timed out downloading the feed") from err
        except requests.ConnectionError as err:
            raise ProviderApiConnectionError("Could not reach the feed") from err
        except ApiRateLimitError as err:
            raise ProviderApiRateLimitError("The feed is rate limited") from err
        except ApiServerError as err:
            raise ProviderApiServerError("The feed server returned an error") from err
        except ApiNotFoundError as err:
            raise ProviderApiNotFoundError("The feed URL was not found") from err
        except ApiClientError as err:
            raise ProviderApiUnknownError("Failed to download the feed") from err

    def _add_object(self, feed: Feed, raw_object: dict[str, Any]) -> None:
        """Validate one raw feed object and add it to the matching list."""
        object_type = raw_object.get("type")
        try:
            if object_type == "tool":
                feed.tools.append(FeedTool.model_validate(raw_object))
            elif object_type == "indicator":
                feed.indicators.append(FeedIndicator.model_validate(raw_object))
            elif object_type == "relationship":
                feed.relationships.append(FeedRelationship.model_validate(raw_object))
        except ValidationError as err:
            self._logger.warning(
                "Invalid feed object, skipping it",
                meta={
                    "id": raw_object.get("id"),
                    "type": object_type,
                    "error": str(err),
                },
            )
