"""Host search client of the Shodan hunt connector."""

from typing import Any

import requests
from connectors_sdk import RateLimit
from connectors_sdk.connectors.internal_hunt import (
    Host,
    HostSearchResult,
    HuntApiClient,
    RunDeadline,
    as_list,
    as_mapping,
    json_object,
    new_host,
    parse_asn,
    text_value,
)

SEARCH_PATH = "/shodan/host/search"
PAGE_SIZE = 100
"""Banners per page of the host search (each page costs a query credit)."""

DN_ORDER = ("CN", "OU", "O", "L", "ST", "C")
"""Order of the attributes of a distinguished name rebuilt from a certificate."""


def distinguished_name(attributes: Any) -> str | None:
    """Rebuild a distinguished name from the attributes Shodan gives.

    Args:
        attributes: Subject or issuer attributes (``{"CN": ..., "O": ...}``).

    Returns:
        The distinguished name (``CN=..., O=...``), or ``None`` without attributes.
    """
    values = {
        str(name): text_value(value)
        for name, value in as_mapping(attributes).items()
        if text_value(value)
    }
    names = [name for name in DN_ORDER if name in values]
    names += sorted(name for name in values if name not in DN_ORDER)
    return ", ".join(f"{name}={values[name]}" for name in names) or None


class ShodanClient(HuntApiClient):
    """Client of the Shodan host search.

    Shodan answers 1 request per second on every plan: the client paces its
    requests, waiting rather than failing. The API key travels in the query
    string, so it is redacted from the network errors, which carry the URL.
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the Shodan API.
            api_key: API key.
        """
        super().__init__(
            base_url=base_url,
            rate_limit=RateLimit(1, "second"),
            raise_on_limit_exceeded=False,
        )
        self._api_key = api_key

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a request, redacting the API key from network errors."""
        try:
            return super()._raw_request(method, path, **kwargs)
        except requests.RequestException as err:
            raise type(err)(str(err).replace(self._api_key, "<redacted>")) from None

    def search(self, query: str, limit: int, deadline: RunDeadline) -> HostSearchResult:
        """Search the banners matching a Shodan query.

        Args:
            query: Shodan search query.
            limit: Maximum number of banners read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        hosts: list[Host] = []
        total: int | None = None
        read = 0
        page = 0
        while read < limit:
            page += 1
            answer = json_object(
                self.hunt_request(
                    "GET",
                    SEARCH_PATH,
                    deadline,
                    "The Shodan search",
                    params={"key": self._api_key, "query": query, "page": page},
                ),
                "The Shodan search",
            )
            if isinstance(answer.get("total"), int):
                total = int(answer["total"])
            returned = as_list(answer.get("matches"))
            matches = returned[: limit - read]
            read += len(matches)
            for banner in matches:
                host = shodan_host(as_mapping(banner))
                if host is not None:
                    hosts.append(host)
            if len(returned) < PAGE_SIZE or (total is not None and read >= total):
                break
        return HostSearchResult(hosts, total, read, requests=page)


def shodan_host(banner: dict[str, Any]) -> Host | None:
    """Map a Shodan banner (one service of a host).

    Args:
        banner: Banner of the search answer.

    Returns:
        The host, or ``None`` without an address.
    """
    host = new_host(banner.get("ip_str"))
    if host is None:
        return None
    for name in as_list(banner.get("hostnames")) + as_list(banner.get("domains")):
        host.add_domain(name)
    host.add_port(banner.get("port"))
    host.asn = parse_asn(banner.get("asn"))
    http = as_mapping(banner.get("http"))
    host.add_fingerprint("http.title", http.get("title"))
    host.add_fingerprint("http.server", http.get("server"))
    ssl = as_mapping(banner.get("ssl"))
    cert = as_mapping(ssl.get("cert"))
    host.add_certificate(
        as_mapping(cert.get("fingerprint")).get("sha256"),
        distinguished_name(cert.get("subject")),
        distinguished_name(cert.get("issuer")),
    )
    host.add_fingerprint("jarm", ssl.get("jarm"))
    for tag in as_list(banner.get("tags")):
        host.add_tag(tag)
    host.seen(banner.get("timestamp"))
    return host
