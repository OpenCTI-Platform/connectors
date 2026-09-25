import re
from typing import Any, Generator

import httpx
from censys_enrichmentapis.errors import EntityHasNoUsableHashError
from censys_platform import (
    SDK,
    Certificate,
    ErrorModel,
    HostEnrichment,
    SearchQueryInputBody,
    V3GlobaldataSearchQueryResponse,
    Webproperty,
)

_HEX_DIGITS_RE = re.compile(r"^[0-9a-fA-F]+$")

# Upper bound on the certificates returned by one Censys search. Popular
# domains match thousands of historical certificates; every extra page costs
# a search credit and inflates the bundle, so pagination stops at this cap.
MAX_SEARCH_RESULTS = 100
# Largest page the Censys search API serves.
_MAX_PAGE_SIZE = 100


class Client:
    def __init__(self, organisation_id: str, token: str) -> None:
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
    def _restore_service_fields(host: HostEnrichment, response: dict[str, Any]) -> None:
        """Restore service fields not yet represented by censys-platform 0.16.

        ``HostEnrichmentService`` declares ``labels``, ``port``, ``protocol``,
        ``scan_time`` and ``threats`` (deserialized as SDK models, e.g.
        ``Threat`` / ``ThreatMalware`` / ``Evidence``). The API also returns
        ``software`` and ``vulns`` per service, which the generated model
        silently drops; they are re-attached here as the raw dicts of the
        response, so the builders must accept both SDK models and dicts.
        """
        resource = response.get("result", {}).get("resource", {})
        raw_services = (
            resource.get("services", []) if isinstance(resource, dict) else []
        )
        for service, raw_service in zip(
            host.services or [], raw_services, strict=False
        ):
            if not isinstance(raw_service, dict):
                continue
            for field in ("software", "vulns"):
                if field in raw_service:
                    # Generated Pydantic models ignore unknown API fields, but
                    # their instances remain safely extensible for conversion.
                    service.__dict__[field] = raw_service[field]

    def _search_certificates(
        self, query: str, max_results: int = MAX_SEARCH_RESULTS
    ) -> Generator[Certificate, None, None]:
        """Run a Censys search query and yield the matching certificates.

        Follows ``next_page_token`` until *max_results* certificates have been
        yielded or the result set is exhausted.
        """
        if max_results <= 0:
            return
        yielded = 0
        page_token: str | None = None
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            while True:
                res: V3GlobaldataSearchQueryResponse = sdk.global_data.search(
                    search_query_input_body=SearchQueryInputBody(
                        query=query,
                        page_size=min(_MAX_PAGE_SIZE, max_results - yielded),
                        page_token=page_token,
                    )
                )
                result = res.result.result
                if not result:
                    return
                for hit in result.hits or []:
                    if hit.certificate_v1:
                        yield hit.certificate_v1.resource
                        yielded += 1
                        if yielded >= max_results:
                            return
                page_token = result.next_page_token
                if not isinstance(page_token, str) or not page_token:
                    return

    def fetch_certs(self, hashes: dict[str, str]) -> Generator[Certificate, None, None]:
        """Fetch certificates by their hashes

        Args:
            hashes (dict[str, str]): A dictionary containing one or more of the following keys
                with their corresponding hash values:
                    - "MD5"
                    - "SHA-1"
                    - "SHA-256"
        Yields:
            Certificate: Censys Certificate objects matching the provided hashes.
        Raises:
            EntityHasNoUsableHashError: If none of the provided hashes are usable
                (missing, or not a hexadecimal fingerprint).
        """
        parts = []
        for field, key in (
            ("cert.fingerprint_md5", "MD5"),
            ("cert.fingerprint_sha1", "SHA-1"),
            ("cert.fingerprint_sha256", "SHA-256"),
        ):
            value = hashes.get(key)
            if value and _HEX_DIGITS_RE.match(value):
                parts.append(f'{field} = "{value}"')
        if not parts:
            raise EntityHasNoUsableHashError(
                "At least one hash (MD5, SHA-1, SHA-256) must be provided."
            )
        yield from self._search_certificates(" or ".join(parts))

    def fetch_web_properties(
        self, hostname: str, ports: tuple[int, ...] = (80, 443)
    ) -> Generator[Webproperty, None, None]:
        """Fetch the web properties exposed by a hostname on selected ports.

        Args:
            hostname (str): The hostname to search for.
            ports: Ports used to construct Censys web-property identifiers.

        Yields:
            Webproperty: Each web property found by Censys.
        """
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            for port in ports:
                webproperty_id = f"{hostname}:{port}"
                try:
                    response = sdk.global_data.get_web_property(
                        webproperty_id=webproperty_id
                    )
                except ErrorModel as error:
                    # It is normal for a domain to expose only HTTP or HTTPS.
                    if error.status_code == 404:
                        continue
                    raise

                if webproperty_asset := response.result.result:
                    yield webproperty_asset.resource

    def fetch_certs_by_domain(self, domain: str) -> Generator[Certificate, None, None]:
        """Fetch certificates that reference a domain in their names

        Args:
            domain (str): The domain name to search for.

        Yields:
            Generator[Certificate, None, None]: Yields Certificate objects matching the domain.
        """
        if any(c in domain for c in "'\"\\"):
            # A domain can't legally contain a quote; a value that does would
            # break out of the Censys search-query string literal below.
            return
        yield from self._search_certificates(f"cert.names = '{domain}'")
