from datetime import datetime, timezone

from connectors_sdk.models import BaseIdentifiedEntity, Indicator, ObservedData
from connectors_sdk.models.enums import RelationshipType

from .domain_enricher import DomainEnricher
from .enricher import Enricher
from .ip_enricher import IPv4Enricher, IPv6Enricher
from .url_enricher import URLEnricher


class IndicatorEnricher(Enricher):
    """
    The Indicator enrichment class
    """

    def _is_sco(self, object: BaseIdentifiedEntity) -> bool:
        return object.id.split("--", 1)[0] in {
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
            "url",
            "hostname",
            "autonomous-system",
        }

    def enrich(self) -> None:
        """
        Enriches IPv4, IPv6, Domain and URLs observables within the indicator
        """
        ENRICHER_MAP = {
            "IPv4-Addr": IPv4Enricher,
            "IPv6-Addr": IPv6Enricher,
            "Domain-Name": DomainEnricher,
            "Hostname": DomainEnricher,
            "Url": URLEnricher,
        }

        for observable in self.stix_entity.get("x_opencti_observable_values", []):
            self.helper.connector_logger.debug(f"x_opencti_observable: {observable}")
            if observable.get("type") not in ENRICHER_MAP:
                continue
            enricher = ENRICHER_MAP.get(observable.get("type"))(
                self.helper, self.client, observable
            )
            enricher.enrich()
            self.octi_observables.extend(enricher.octi_observables)

        self.octi_observables = list(set(self.octi_observables))

        indicator = Indicator(
            name=self.stix_entity.get("name"),
            pattern=self.stix_entity.get("pattern"),
            pattern_type=self.stix_entity.get("pattern_type"),
        )

        entities_for_observed_data = [
            observable
            for observable in self.octi_observables
            if self._is_sco(observable)
        ]

        observed_data = ObservedData(
            first_observed=datetime.now(tz=timezone.utc),
            last_observed=datetime.now(tz=timezone.utc),
            number_observed=1,
            entities=entities_for_observed_data,
        )

        self.octi_observables.append(observed_data)
        self.add_target_and_relationship(
            target=indicator,
            relationship_type=RelationshipType.RELATED_TO,
            description="Indicator observables",
            source=observed_data,
        )
