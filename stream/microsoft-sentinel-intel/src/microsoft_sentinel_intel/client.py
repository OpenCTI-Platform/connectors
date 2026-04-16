import json
from typing import Any

from azure.core import PipelineClient
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline.policies import BearerTokenCredentialPolicy, RetryPolicy
from azure.core.pipeline.transport._base import HttpRequest, HttpResponse
from azure.identity import ClientSecretCredential
from microsoft_sentinel_intel.errors import ConnectorClientError
from microsoft_sentinel_intel.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class ConnectorClient:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.config = config

        self.management_endpoint = (
            f"/subscriptions/{self.config.microsoft_sentinel_intel.subscription_id}"
            f"/resourceGroups/{self.config.microsoft_sentinel_intel.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.config.microsoft_sentinel_intel.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/threatIntelligence/main"
        )

        policies = [
            BearerTokenCredentialPolicy(
                ClientSecretCredential(
                    tenant_id=config.microsoft_sentinel_intel.tenant_id,
                    client_id=config.microsoft_sentinel_intel.client_id,
                    client_secret=config.microsoft_sentinel_intel.client_secret.get_secret_value(),
                ),
                "https://management.azure.com/.default",
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

    def query_indicators(self, content: dict[str, Any]) -> HttpResponse:
        return self._send_request(
            client=self.management_client,
            request=self.management_client.post(
                url=f"{self.management_endpoint}/queryIndicators",
                params={
                    "api-version": self.config.microsoft_sentinel_intel.management_api_version
                },
                content=content,
                headers={"Content-Type": "application/json"},
            ),
        )

    def delete_indicator_by_id(
        self, indicator_id: str, source_system: str, pattern_type: str | None = None
    ) -> HttpResponse | None:
        content: dict[str, Any] = {"keywords": indicator_id, "sources": [source_system]}
        if pattern_type:
            content["patternTypes"] = [pattern_type]
        response = self.query_indicators(content=content)

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
                meta={"indicator_id": indicator_id, "source_system": source_system},
            )
            return None

        if len(indicators) > 1:
            self.helper.connector_logger.warning(
                message=f"[API] Found {len(indicators)} indicators matching the query, deleting all",
                meta={"indicator_id": indicator_id, "count": len(indicators)},
            )

        last_response = None
        errors: list[ConnectorClientError] = []
        for indicator in indicators:
            try:
                last_response = self._send_request(
                    client=self.management_client,
                    request=self.management_client.delete(
                        url=f"{self.management_endpoint}/indicators/{indicator['name']}",
                        params={
                            "api-version": self.config.microsoft_sentinel_intel.management_api_version
                        },
                    ),
                )
            except ConnectorClientError as err:
                self.helper.connector_logger.error(
                    message=f"[API] Failed to delete indicator '{indicator['name']}'",
                    meta=err.metadata,
                )
                errors.append(err)

        if errors:
            raise ConnectorClientError(
                message=f"[API] Failed to delete {len(errors)}/{len(indicators)} indicators",
                metadata={"errors": [str(e) for e in errors]},
            )
        return last_response
