from urllib.parse import urlparse

import validators
from connectors_sdk.models import URL
from connectors_sdk.models.enums import RelationshipType

from .domain_enricher import DomainEnricher
from .enricher import Enricher
from .ip_enricher import IPv4Enricher, IPv6Enricher


class URLEnricher(Enricher):
    """
    The URL Enrichment class
    """

    def parse_url(self, value: str) -> tuple[str, str | None]:
        """
        Parses a URL to extract the IP or Domain.
        Return (type, result)
        - type: ipv4 | ipv6 | domain | unknown
        - result: extracted ip or domain, None if unknown
        """
        parsed = urlparse(value)
        host = parsed.hostname or value

        if validators.ipv4(host):
            return "ipv4", host

        if validators.ipv6(host):
            return "ipv6", host

        if validators.domain(host):
            return "domain", host

        return "unknown", None

    def enrich(self) -> None:
        """
        Enriches a URL by extracting the IP or Domain from it
        """

        url_type, value = self.parse_url(self.stix_entity.get("value"))
        match url_type:
            case "ipv4":
                enricher_class = IPv4Enricher
            case "ipv6":
                enricher_class = IPv6Enricher
            case "domain":
                enricher_class = DomainEnricher
            case "unknown":
                raise ValueError(f"{url_type} is not a supported entity type.")
        stix_child_entity = self.stix_entity.copy()
        stix_child_entity["value"] = value
        enricher = enricher_class(self.helper, self.client, stix_child_entity)
        enricher.enrich()

        url = URL(value=self.stix_entity.get("value"))
        enricher.add_target_and_relationship(
            url, RelationshipType.RELATED_TO, f"URL {url_type}"
        )

        self.octi_observables = enricher.octi_observables
