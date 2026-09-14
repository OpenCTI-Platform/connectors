from typing import Any, Dict, Generator

import httpx

from censys_enrichmentapis.errors import EntityHasNoUsableHashError
from censys_platform import (
    SDK,
    Certificate,
    Host,
    HostEnrichment,
    SearchQueryInputBody,
    V3GlobaldataSearchQueryResponse,
)


class Client:
    def __init__(self, organisation_id: str, token: str):
        self.organisation_id = organisation_id
        self.token = token

    def fetch_ip(self, ip: str) -> HostEnrichment:
        """Fetch host enrichment data for a given IP address from Censys.
        Args:
            ip (str): The IP address to fetch data for.
        Returns:
            HostEnrichment: The host enrichment data retrieved from Censys.
        Raises:
            ValueError: If no data is found for the given IP address.
        """
        raw_response: dict[str, Any] = {}

        def preserve_response(response: httpx.Response) -> None:
            # The generated Censys SDK currently omits service ``software``
            # and ``vulns`` from HostEnrichmentService. Read the response once
            # in a hook so the fields can be restored after SDK deserialization.
            try:
                response.read()
                raw_response.update(response.json())
            except (ValueError, TypeError):
                pass

        with httpx.Client(
            follow_redirects=True, event_hooks={"response": [preserve_response]}
        ) as http_client, SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
            client=http_client,
        ) as sdk:
            res = sdk.global_data.get_host_enrichment(host_ip=ip)
            if host_asset := res.result.result:
                self._restore_service_fields(host_asset.resource, raw_response)
                return host_asset.resource
            raise ValueError(f"No data found for IP {ip}")

    @staticmethod
    def _restore_service_fields(
        host: HostEnrichment, response: dict[str, Any]
    ) -> None:
        """Restore service fields not yet represented by censys-platform 0.16."""
        resource = response.get("result", {}).get("result", {}).get("resource", {})
        raw_services = resource.get("services", []) if isinstance(resource, dict) else []
        for service, raw_service in zip(host.services or [], raw_services, strict=False):
            if not isinstance(raw_service, dict):
                continue
            for field in ("software", "vulns"):
                if field in raw_service:
                    # Generated Pydantic models ignore unknown API fields, but
                    # their instances remain safely extensible for conversion.
                    service.__dict__[field] = raw_service[field]

    def fetch_certs(self, hashes: Dict[str, str]) -> Generator[Certificate, None, None]:
        """Fetch certificates by their hashes

        Args:
            hashes (Dict[str, str]): A dictionary containing one or more of the following keys
                with their corresponding hash values:
                    - "MD5"
                    - "SHA-1"
                    - "SHA-256"
        Yields:
            Certificate: Censys Certificate objects matching the provided hashes.
        Raises:
            EntityHasNoUsableHashError: If none of the required hashes are provided.
        """
        if not any(h in hashes for h in ("MD5", "SHA-1", "SHA-256")):
            raise EntityHasNoUsableHashError(
                "At least one hash (MD5, SHA1, SHA256) must be provided."
            )
        parts = []
        if "MD5" in hashes:
            parts.append(f'cert.fingerprint_md5 = "{hashes["MD5"]}"')
        if "SHA-1" in hashes:
            parts.append(f'cert.fingerprint_sha1 = "{hashes["SHA-1"]}"')
        if "SHA-256" in hashes:
            parts.append(f'cert.fingerprint_sha256 = "{hashes["SHA-256"]}"')
        query = " or ".join(parts)
        search_query = SearchQueryInputBody(query=query)
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            ## TODO: change to use get_property instead of search on port 443
            res: V3GlobaldataSearchQueryResponse = sdk.global_data.search(
                search_query_input_body=search_query
            )
            if res.result.result:
                for hit in res.result.result.hits:
                    if hit.certificate_v1:
                        yield hit.certificate_v1.resource

    def fetch_hosts(self, hostname: str) -> Generator[Host, None, None]:
        """Fetch hosts by hostname
        Args:
            hostname (str): The hostname to search for.
        Yields:
            Generator[Host, None, None]: Yields Host objects matching the hostname.
        """
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            query = f"host.dns.names = '{hostname}'"
            search_query = SearchQueryInputBody(query=query)
            res: V3GlobaldataSearchQueryResponse = sdk.global_data.search(
                search_query_input_body=search_query
            )
            if res.result.result:
                for hit in res.result.result.hits:
                    if hit.host_v1:
                        yield hit.host_v1.resource

    def fetch_certs_by_domain(self, domain: str) -> Generator[Certificate, None, None]:
        """Fetch certificates that reference a domain in their names

        Args:
            domain (str): The domain name to search for.

        Yields:
            Generator[Certificate, None, None]: Yields Certificate objects matching the domain.
        """
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            query = f"cert.names = '{domain}'"
            search_query = SearchQueryInputBody(query=query)
            res: V3GlobaldataSearchQueryResponse = sdk.global_data.search(
                search_query_input_body=search_query
            )
            if res.result.result:
                for hit in res.result.result.hits:
                    if hit.certificate_v1:
                        yield hit.certificate_v1.resource
