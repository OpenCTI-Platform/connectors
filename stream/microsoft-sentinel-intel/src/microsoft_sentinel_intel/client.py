import json
from typing import Any

from azure.core import PipelineClient
from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline.policies import BearerTokenCredentialPolicy, RetryPolicy
from azure.core.pipeline.transport._base import HttpRequest, HttpResponse
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from microsoft_sentinel_intel.config import ConnectorSettings
from microsoft_sentinel_intel.errors import ConnectorClientError
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

        credential = self._make_credential(
            tenant_id=config.microsoft_sentinel_intel.tenant_id,
            client_id=config.microsoft_sentinel_intel.client_id,
            client_secret=config.microsoft_sentinel_intel.client_secret,
        )
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
    def _make_credential(
        tenant_id: str | None,
        client_id: str | None,
        client_secret: str | None,
    ) -> TokenCredential:
        if tenant_id and client_id and client_secret:
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        # Fallback chain: Managed Identity → Azure CLI …
        return DefaultAzureCredential(exclude_shared_token_cache_credential=True)

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

    def delete_indicator_by_id(self, indicator_id: str) -> HttpResponse:
        response = self.query_indicators(content={"keywords": indicator_id})

        try:
            body = json.loads(response.body())
        except json.decoder.JSONDecodeError as e:
            raise ConnectorClientError(
                message=f"[API] Failed to decode response body: {response.body()}",
                metadata={"error": str(e)},
            )

        if len(body["value"]) != 1:
            raise ConnectorClientError(
                message=f"[API] Expected exactly one indicator, found {len(body['value'])}",
                metadata={"indicators": body["value"]},
            )

        return self._send_request(
            client=self.management_client,
            request=self.management_client.delete(
                url=f"{self.management_endpoint}/indicators/{body['value'][0]['name']}",
                params={
                    "api-version": self.config.microsoft_sentinel_intel.management_api_version
                },
            ),
        )
