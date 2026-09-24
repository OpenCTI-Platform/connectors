"""HTTP client for the HoneyLabs TAXII 2.1 server.

Authentication is HTTP Basic with the fixed username `taxii` and a HoneyLabs
API key as the password, which is how every TAXII consumer of HoneyLabs
authenticates. The server answers with `application/taxii+json`, which the
SDK's default parser treats as text, so responses are parsed here.
"""

from base64 import b64encode
from datetime import datetime
from typing import Any, Generator

import requests
from connectors_sdk import BaseClientApi
from honeylabs_client.models import (
    TaxiiCollection,
    TaxiiEnvelope,
    TaxiiIndicator,
    TaxiiPage,
)

TAXII_MEDIA = "application/taxii+json;version=2.1"
USER_AGENT = (
    "opencti-honeylabs-connector/1.0 (+https://honeylabs.net/integrations/opencti)"
)


class TaxiiPaginationError(RuntimeError):
    """The server's envelope cannot be followed to the end of the collection."""


class HoneyLabsTaxiiClient(BaseClientApi):
    def __init__(self, api_root: str, api_key: str, logger: Any) -> None:
        super().__init__(
            base_url=api_root.rstrip("/"), timeout=60, max_retries=3, backoff_factor=2.0
        )
        self._basic = b64encode(f"taxii:{api_key}".encode()).decode()
        self.logger = logger

    @property
    def session_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Basic {self._basic}",
            "Accept": TAXII_MEDIA,
            "User-Agent": USER_AGENT,
        }

    def _parse_response(self, response: requests.Response) -> Any:
        content_type = response.headers.get("Content-Type", "").lower()
        if "taxii+json" in content_type or "stix+json" in content_type:
            return response.json()
        return super()._parse_response(response)

    def get_collections(self) -> list[TaxiiCollection]:
        body = self._get("/collections/")
        return [
            TaxiiCollection.model_validate(c)
            for c in (body or {}).get("collections", [])
        ]

    def _get_envelope(
        self, path: str, params: dict[str, Any]
    ) -> tuple[TaxiiEnvelope, datetime | None]:
        """One TAXII request, returning the envelope and the server's
        `X-TAXII-Date-Added-Last` header parsed as a datetime."""
        response = self._raw_request("GET", path, params=params)
        if not response.ok:
            self._raise_for_status(response, "GET", path)
        envelope = TaxiiEnvelope.model_validate(self._parse_response(response) or {})
        header = response.headers.get("X-TAXII-Date-Added-Last")
        last = datetime.fromisoformat(header.replace("Z", "+00:00")) if header else None
        return envelope, last

    def iter_objects(
        self, collection: str, added_after: datetime | None, limit: int
    ) -> Generator[TaxiiPage, None, None]:
        """Yield the collection's indicators page by page.

        Pagination follows TAXII 2.1 section 3.5: while the envelope says
        `more`, the next request repeats the original query parameters and
        adds the server's `next` cursor. When `more` is true but no cursor is
        given, the client resumes with `added_after` set to the page's
        `X-TAXII-Date-Added-Last` header, as the specification allows. If the
        server gives neither, the run raises rather than ending as if the
        import were complete, so a partial import is never checkpointed."""
        params: dict[str, Any] = {"limit": limit}
        if added_after is not None:
            params["added_after"] = _rfc3339(added_after)
        path = f"/collections/{collection}/objects/"
        while True:
            envelope, date_added_last = self._get_envelope(path, params)
            page: list[TaxiiIndicator] = []
            for obj in envelope.objects:
                if obj.get("type") != "indicator":
                    continue
                try:
                    page.append(TaxiiIndicator.model_validate(obj))
                except Exception as exc:  # noqa: BLE001
                    self.logger.warning(
                        "Skipping an object the server sent in an unexpected shape",
                        {"error": str(exc), "id": obj.get("id")},
                    )
            yield TaxiiPage(objects=page, date_added_last=date_added_last)
            if not envelope.more:
                return
            if envelope.next:
                params = {**params, "next": envelope.next}
            elif date_added_last is not None:
                params = {k: v for k, v in params.items() if k != "next"} | {
                    "added_after": _rfc3339(date_added_last)
                }
            else:
                raise TaxiiPaginationError(
                    f"{collection}: the server reported more objects but sent "
                    "neither a `next` cursor nor X-TAXII-Date-Added-Last; "
                    "not treating this import as complete"
                )


def _rfc3339(value: datetime) -> str:
    """Millisecond RFC 3339 in UTC, the form the HoneyLabs server accepts."""
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
