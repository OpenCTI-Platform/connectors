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

from honeylabs_client.models import TaxiiCollection, TaxiiEnvelope, TaxiiIndicator

TAXII_MEDIA = "application/taxii+json;version=2.1"
USER_AGENT = (
    "opencti-honeylabs-connector/1.0 (+https://honeylabs.net/integrations/opencti)"
)


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

    def iter_objects(
        self, collection: str, added_after: datetime | None, limit: int
    ) -> Generator[list[TaxiiIndicator], None, None]:
        """Yield the collection's indicators page by page, following the
        envelope's `next` cursor while `more` is true."""
        params: dict[str, Any] = {"limit": limit}
        if added_after is not None:
            params["added_after"] = (
                added_after.strftime("%Y-%m-%dT%H:%M:%S.")
                + f"{added_after.microsecond // 1000:03d}Z"
            )
        path = f"/collections/{collection}/objects/"
        pages = 0
        while True:
            envelope = TaxiiEnvelope.model_validate(
                self._get(path, params=params) or {}
            )
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
            pages += 1
            yield page
            if not envelope.more or not envelope.next:
                return
            params["next"] = envelope.next
