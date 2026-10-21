import time

from connectors_sdk import ApiClientError, BaseClientApi
from spur_client.models import IPContext, TagMetadata

# Tag metadata describes a service and changes slowly: it is cached to save quota
TAG_METADATA_CACHE_TTL_SECONDS = 24 * 60 * 60


class SpurClient(BaseClientApi):
    """Client for the Spur Context API (https://docs.spur.us/context-api/endpoints)."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 60) -> None:
        self._api_key = api_key
        self._tag_metadata_cache: dict[str, tuple[float, TagMetadata | None]] = {}
        super().__init__(base_url, timeout=timeout)

    @property
    def session_headers(self) -> dict[str, str]:
        return {"Token": self._api_key}

    def get_ip_context(self, ip: str) -> IPContext | None:
        """Return the IP Context object of a public IPv4 or IPv6 address.

        Each call consumes one query of the Context API quota.

        Returns:
            The IP Context object, or `None` when Spur rejects the address
            (HTTP 400, e.g. a private or reserved IP).

        Raises:
            ApiClientError: On any other HTTP error (401 invalid token, 403 no
                Context API access, 429 quota exhausted, 5xx...).
            pydantic.ValidationError: When the response is not a valid IP Context object.
        """
        try:
            response = self._get(f"/v2/context/{ip}")
        except ApiClientError as err:
            if err.status_code == 400:
                return None
            raise
        return IPContext.model_validate(response)

    def get_tag_metadata(self, tag: str) -> TagMetadata | None:
        """Return the Tag Metadata object of a service tag (e.g. `PROTON_VPN`).

        Each call to Spur consumes one query of the Context API quota, even for an
        unknown tag. Results, including unknown tags, are cached for
        `TAG_METADATA_CACHE_TTL_SECONDS` for the lifetime of the client.

        Returns:
            The Tag Metadata object, or `None` when Spur does not know the tag (HTTP 404).

        Raises:
            ApiClientError: On any other HTTP error.
            pydantic.ValidationError: When the response is not a valid Tag Metadata object.
        """
        cached = self._tag_metadata_cache.get(tag)
        if cached is not None and time.monotonic() - cached[0] < (
            TAG_METADATA_CACHE_TTL_SECONDS
        ):
            return cached[1]
        try:
            tag_metadata: TagMetadata | None = TagMetadata.model_validate(
                self._get(f"/v2/metadata/tags/{tag}")
            )
        except ApiClientError as err:
            if err.status_code != 404:
                raise
            tag_metadata = None
        self._tag_metadata_cache[tag] = (time.monotonic(), tag_metadata)
        return tag_metadata
