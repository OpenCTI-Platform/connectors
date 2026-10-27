"""Shodan InternetDB input models.

``ShodanInternetDbResult`` is copied from
``internal-enrichment/shodan-internetdb/src/shodan_internetdb/client.py``.
"""

from pydantic import BaseModel


class ShodanInternetDbResult(BaseModel):
    """Shodan InternetDB response for one IP address."""

    cpes: list[str]  # Common Platform Enumeration (CPE)
    hostnames: list[str]
    ip: str
    ports: list[int]
    tags: list[str]
    vulns: list[str]


class ShodanInternetDbHostInput(BaseModel):
    """Enrichment of one IPv4 observable with its InternetDB result."""

    observable_value: str
    result: ShodanInternetDbResult
