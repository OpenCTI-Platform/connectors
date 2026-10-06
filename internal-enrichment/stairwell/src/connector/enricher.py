from __future__ import annotations

import logging
from typing import Any

from .asn_enricher import AsnEnricher
from .domain_enricher import DomainEnricher
from .file_enricher import FileEnricher
from .ip_enricher import IpEnricher
from .stairwell import StairwellClient

logger = logging.getLogger(__name__)


class Dispatcher:
    def __init__(
        self,
        helper,
        client: StairwellClient,
        default_tlp: str,
        variant_limit: int = 25,
        resolutions_limit: int = 50,
        sightings_limit: int = 100,
        opencti_base_url: str = "http://localhost:8080",
    ) -> None:
        self.helper = helper
        self.file = FileEnricher(
            helper,
            client,
            default_tlp,
            variant_limit=variant_limit,
            sightings_limit=sightings_limit,
            opencti_base_url=opencti_base_url,
        )
        self.domain = DomainEnricher(
            helper, client, default_tlp, resolutions_limit=resolutions_limit
        )
        self.ip = IpEnricher(helper, client, default_tlp)
        self.asn = AsnEnricher(helper, client, default_tlp)

    def dispatch(self, observable: dict[str, Any]) -> str:
        entity_type = (observable.get("entity_type") or "").lower()
        if entity_type in ("stixfile", "file", "artifact"):
            return self.file.enrich(observable)
        if entity_type == "domain-name":
            return self.domain.enrich(observable)
        if entity_type in ("ipv4-addr", "ipv6-addr"):
            return self.ip.enrich(observable)
        if entity_type == "autonomous-system":
            return self.asn.enrich(observable)
        return f"Unsupported entity_type for Stairwell enrichment: {entity_type!r}"
