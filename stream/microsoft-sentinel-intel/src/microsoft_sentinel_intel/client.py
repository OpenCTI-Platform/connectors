import json
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from azure.core import PipelineClient
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline.policies import BearerTokenCredentialPolicy, RetryPolicy
from azure.core.pipeline.transport._base import HttpRequest, HttpResponse
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from microsoft_sentinel_intel.errors import ConnectorClientError
from microsoft_sentinel_intel.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class IncidentListing:
    """Incidents of a listing bounded by a page limit, read lazily, oldest first.

    `truncated` is set once the iteration stopped at the page limit with a `nextLink`
    left: incidents were left unread, whatever the number of incidents listed.
    """

    def __init__(self, incidents: Iterable[dict[str, Any]] = ()) -> None:
        self.incidents: Iterable[dict[str, Any]] = incidents
        self.truncated = False

    def mark_truncated(self) -> None:
        self.truncated = True

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.incidents)


class ConnectorClient:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.config = config

        self.security_insights_endpoint = (
            f"/subscriptions/{self.config.microsoft_sentinel_intel.subscription_id}"
            f"/resourceGroups/{self.config.microsoft_sentinel_intel.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.config.microsoft_sentinel_intel.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
        )
        self.management_endpoint = (
            f"{self.security_insights_endpoint}/threatIntelligence/main"
        )
        if config.microsoft_sentinel_intel.auth_type == "app_registration":
            credential = ClientSecretCredential(
                tenant_id=config.microsoft_sentinel_intel.tenant_id,
                client_id=config.microsoft_sentinel_intel.client_id,
                client_secret=config.microsoft_sentinel_intel.client_secret.get_secret_value(),
            )
        else:
            credential = DefaultAzureCredential()

        policies = [
            BearerTokenCredentialPolicy(
                credential, "https://management.azure.com/.default"
            ),
            RetryPolicy(),
        ]

        self.threat_intel_client = PipelineClient(
            base_url="https://api.ti.sentinel.azure.com", policies=policies
        )
        self.management_client = PipelineClient(
            base_url="https://management.azure.com", policies=policies
        )

    @staticmethod
    def _send_request(client: PipelineClient, request: HttpRequest) -> HttpResponse:
        """Send an HTTP request and return the response."""
        try:
            response = client.send_request(request=request)
            response.raise_for_status()
            return response
        except HttpResponseError as err:
            raise ConnectorClientError(
                message="[API] An error occurred during request",
                metadata={"url_path": str(request), "error": str(err)},
            ) from err

    @staticmethod
    def _parse_body(response: HttpResponse) -> dict[str, Any]:
        """Decode the JSON object returned by the API."""
        try:
            body = json.loads(response.body())
        except (json.decoder.JSONDecodeError, TypeError) as err:
            raise ConnectorClientError(
                message="[API] Failed to decode response body",
                metadata={"error": str(err)},
            ) from err
        if not isinstance(body, dict):
            raise ConnectorClientError(
                message="[API] Unexpected response format: not a JSON object",
                metadata={"response_body": str(body)},
            )
        return body

    def _iter_pages(
        self,
        request: HttpRequest,
        api_version: str,
        max_pages: int,
        complete: bool = True,
        on_truncated: Callable[[], None] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield the items of a paginated management API response.

        The next pages are read with a GET on the `nextLink` returned by the API, as
        documented for the Azure Resource Manager pageable operations.

        :param request: The request of the first page.
        :param api_version: API version added to a `nextLink` that does not carry it.
        :param max_pages: Maximum number of pages read.
        :param complete: When `True`, exceeding `max_pages` raises (the listing must be
            complete); otherwise the iteration stops after `max_pages` pages.
        :param on_truncated: Called when a listing that need not be complete stops at
            `max_pages` with a `nextLink` left, so the caller knows items were left.
        :raises ConnectorClientError: On any error, a missing `value` key, a repeated
            `nextLink` or, for complete listings, when the listing exceeds `max_pages`
            (a partial listing is never returned silently).
        """
        pages = 0
        seen_links: set[str] = set()
        while True:
            body = self._parse_body(self._send_request(self.management_client, request))
            pages += 1
            items = body.get("value")
            if not isinstance(items, list):
                raise ConnectorClientError(
                    message="[API] Unexpected response format: missing 'value' key",
                    metadata={"response_body": str(body)[:1000]},
                )
            yield from (item for item in items if isinstance(item, dict))
            next_link = body.get("nextLink")
            if not next_link:
                return
            if pages >= max_pages and not complete:
                self.helper.connector_logger.warning(
                    message="[API] Listing stopped after the maximum number of pages",
                    meta={"max_pages": max_pages},
                )
                if on_truncated is not None:
                    on_truncated()
                return
            if pages >= max_pages or next_link in seen_links:
                raise ConnectorClientError(
                    message="[API] Listing aborted: too many pages or a repeated nextLink",
                    metadata={"pages": pages, "max_pages": max_pages},
                )
            seen_links.add(next_link)
            request = self.management_client.get(
                url=next_link, params={"api-version": api_version}
            )

    def iter_indicators(
        self, source_system: str, page_size: int, max_pages: int
    ) -> Iterator[dict[str, Any]]:
        """Yield the threat intelligence indicators of a source system.

        Uses the management API `threatIntelligence/main/query` endpoint
        (`query_api_version`), paginated with `nextLink`.

        :param source_system: The source of the indicators (the connector `source_system`).
        :param page_size: The `maxPageSize` of the query.
        :param max_pages: Maximum number of pages read.
        :return: The TI objects (`id`, `name`, `kind`, `properties.data`...).
        """
        api_version = self.config.microsoft_sentinel_intel.query_api_version
        content = {
            "condition": {
                "clauses": [
                    {
                        "field": "source",
                        "operator": "Equals",
                        "values": [source_system],
                    }
                ],
                "conditionConnective": "And",
                "stixObjectType": "indicator",
            },
            "maxPageSize": page_size,
        }
        request = self.management_client.post(
            url=f"{self.management_endpoint}/query",
            params={"api-version": api_version},
            content=content,
            headers={"Content-Type": "application/json"},
        )
        return self._iter_pages(request, api_version, max_pages)

    def delete_ti_object(self, resource_id: str) -> HttpResponse:
        """Delete a threat intelligence object by its resource id (as returned by `/query`)."""
        return self._send_request(
            client=self.management_client,
            request=self.management_client.delete(
                # The 'id' field of a TI object is the endpoint of the resource
                url=resource_id,
                params={
                    "api-version": self.config.microsoft_sentinel_intel.query_api_version
                },
            ),
        )

    def iter_incidents(
        self, modified_since: datetime, page_size: int, max_pages: int
    ) -> "IncidentListing":
        """List the Microsoft Sentinel incidents modified since a date, oldest first.

        Uses the `Microsoft.SecurityInsights/incidents` list API
        (`management_api_version`) with `$filter`, `$orderby` and `$top`, paginated
        with `nextLink`.

        :param modified_since: Only incidents with `lastModifiedTimeUtc` on or after it.
        :param page_size: The `$top` of each page.
        :param max_pages: Maximum number of pages read (the oldest incidents first).
        :return: The incidents, read lazily; `truncated` tells, once iterated, whether
            the page limit left incidents unread (pages can be shorter than `$top`).
        """
        api_version = self.config.microsoft_sentinel_intel.management_api_version
        since = (
            modified_since.astimezone(UTC).replace(microsecond=0).isoformat()
        ).replace("+00:00", "Z")
        request = self.management_client.get(
            url=f"{self.security_insights_endpoint}/incidents",
            params={
                "api-version": api_version,
                "$filter": quote(
                    f"properties/lastModifiedTimeUtc ge {since}", safe="/:"
                ),
                "$orderby": quote("properties/lastModifiedTimeUtc asc", safe="/"),
                "$top": str(page_size),
            },
        )
        listing = IncidentListing()
        listing.incidents = self._iter_pages(
            request,
            api_version,
            max_pages,
            complete=False,
            on_truncated=listing.mark_truncated,
        )
        return listing

    def list_incident_entities(self, incident_id: str) -> list[dict[str, Any]]:
        """Return the entities of an incident.

        :param incident_id: The incident resource id (`id` of the incident) or name.
        """
        incident_url = (
            incident_id
            if incident_id.startswith("/")
            else f"{self.security_insights_endpoint}/incidents/{incident_id}"
        )
        body = self._parse_body(
            self._send_request(
                client=self.management_client,
                request=self.management_client.post(
                    url=f"{incident_url}/entities",
                    params={
                        "api-version": self.config.microsoft_sentinel_intel.management_api_version
                    },
                ),
            )
        )
        entities = body.get("entities")
        if not isinstance(entities, list):
            # Never read as "no match": the hit window would move past this incident.
            raise ConnectorClientError(
                message="[API] Unexpected response format: missing 'entities' list",
                metadata={
                    "incident_id": incident_id,
                    "response_body": str(body)[:1000],
                },
            )
        return [entity for entity in entities if isinstance(entity, dict)]

    def upload_stix_objects(
        self, stix_objects: list[dict[str, Any]], source_system: str
    ) -> HttpResponse:
        return self._send_request(
            client=self.threat_intel_client,
            request=self.threat_intel_client.post(
                url=f"/workspaces/{self.config.microsoft_sentinel_intel.workspace_id}/threat-intelligence-stix-objects:upload",
                params={
                    "api-version": self.config.microsoft_sentinel_intel.workspace_api_version
                },
                content={"stixobjects": stix_objects, "sourcesystem": source_system},
            ),
        )

    def query_indicators(self, stix_id: str, source_system: str) -> HttpResponse:
        content = {
            "condition": {
                "clauses": [
                    {
                        "field": "id",
                        "operator": "Equals",
                        "values": [stix_id],
                    },
                    {
                        "field": "source",
                        "operator": "Equals",
                        "values": [source_system],
                    },
                ],
                "conditionConnective": "And",
                "stixObjectType": "indicator",
            },
        }
        return self._send_request(
            client=self.management_client,
            request=self.management_client.post(
                url=f"{self.management_endpoint}/query",
                params={
                    "api-version": self.config.microsoft_sentinel_intel.query_api_version
                },
                content=content,
                headers={"Content-Type": "application/json"},
            ),
        )

    def delete_indicator_by_id(
        self, indicator_id: str, source_system: str
    ) -> HttpResponse | None:
        response = self.query_indicators(
            stix_id=indicator_id, source_system=source_system
        )

        try:
            body = json.loads(response.body())
        except json.decoder.JSONDecodeError as e:
            raise ConnectorClientError(
                message=f"[API] Failed to decode response body: {response.body()}",
                metadata={"error": str(e)},
            )

        indicators = body.get("value")
        if indicators is None:
            raise ConnectorClientError(
                message="[API] Unexpected response format: missing 'value' key",
                metadata={"response_body": str(body)},
            )
        if not indicators:
            self.helper.connector_logger.warning(
                message=f"[API] Indicator not found for source system '{source_system}', skipping deletion",
                meta={
                    "indicator_stix_id": indicator_id,
                    "source_system": source_system,
                },
            )
            return None

        if len(indicators) > 1:
            self.helper.connector_logger.warning(
                message=f"[API] Found {len(indicators)} indicators matching the query, deleting all",
                meta={
                    "indicator_stix_id": indicator_id,
                    "count": len(indicators),
                },
            )

        last_response = None
        errors: list[ConnectorClientError] = []
        for indicator in indicators:
            indicator_microsoft_id = indicator.get("id")

            if not isinstance(indicator_microsoft_id, str):
                error_message = (
                    "[API] Failed to retrieve indicator identifier for deletion"
                )
                error = ConnectorClientError(
                    message=error_message,
                    metadata={
                        "indicator_stix_id": indicator_id,
                        "indicator_microsoft_id": indicator_microsoft_id,
                    },
                )
                self.helper.connector_logger.error(
                    message=error_message, meta=error.metadata
                )
                errors.append(error)
                continue

            try:
                last_response = self.delete_ti_object(indicator_microsoft_id)
            except ConnectorClientError as err:
                self.helper.connector_logger.error(
                    message="[API] Failed to delete indicator",
                    meta={
                        "indicator_stix_id": indicator_id,
                        "indicator_microsoft_id": indicator_microsoft_id,
                    },
                )
                errors.append(err)

        if errors:
            raise ConnectorClientError(
                message=f"[API] Failed to delete {len(errors)}/{len(indicators)} indicators",
                metadata={"errors": [str(e) for e in errors]},
            )
        return last_response
