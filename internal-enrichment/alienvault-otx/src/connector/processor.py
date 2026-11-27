from typing import Any

from connector.settings import ConnectorSettings
from connectors_sdk import BaseEnrichmentProcessor, EnrichmentMessage


class AlienVaultOtxProcessor(BaseEnrichmentProcessor[ConnectorSettings]):
    """Enrich IPv4 addresses, domain names and URLs with AlienVault OTX.

    SKELETON: this processor is a placeholder. The scope and TLP checks, the playbook
    handling and the bundle sending are done by `InternalEnrichmentConnector`, but
    nothing is fetched from OTX and no STIX object is created yet. The OTX lookup,
    the external reference, the summary note and the country sightings are added by
    the next sub-issues of epic #8537.
    """

    handled_entity_types = frozenset({"IPv4-Addr", "Domain-Name", "Url"})

    def collect(self, message: EnrichmentMessage) -> Any:
        """Collect OTX data about the entity.

        Placeholder: the OTX lookup is implemented in a next sub-issue of epic #8537.
        """
        self.logger.debug(
            "OTX lookup not implemented yet, nothing collected",
            meta=message.to_log_metadata(),
        )
        return None

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        """Convert OTX data to STIX objects.

        Placeholder: the external reference, the summary note and the country
        sightings are implemented in next sub-issues of epic #8537. Nothing is sent
        until then, and in a playbook the connector sends the original bundle back.
        """
        return []
