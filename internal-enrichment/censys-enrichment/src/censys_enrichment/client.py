from typing import Dict, Generator

from censys_platform import (
    SDK,
    Certificate,
    Host,
    SearchQueryInputBody,
    V3GlobaldataSearchQueryResponse,
)


class EntityHasNoUsableHashError(Exception):
    """Custom exception for entity having no usable hash"""


class Client:
    def __init__(self, organisation_id: str, token: str):
        self.organisation_id = organisation_id
        self.token = token

    def fetch_ip(self, ip: str) -> Host:
        """Fetch host data for a given IP address from Censys.
        Args:
            ip (str): The IP address to fetch data for.
        Returns:
            Host: The host data retrieved from Censys.
        Raises:
            ValueError: If no data is found for the given IP address.
        """
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            res = sdk.global_data.get_host(host_id=ip)
            if host_asset := res.result.result:
                return host_asset.resource
            raise ValueError(f"No data found for IP {ip}")

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
