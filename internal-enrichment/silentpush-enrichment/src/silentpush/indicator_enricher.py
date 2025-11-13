from datetime import datetime

import pycti
from pycti import StixCoreRelationship
from stix2 import ObservedData, Relationship

from .domain_enricher import DomainEnricher
from .enricher import Enricher
from .ipv4_enricher import IPv4Enricher
from .ipv6_enricher import IPv6Enricher
from .url_enricher import URLEnricher


class IndicatorEnricher(Enricher):
    """
    The Indicator enrichment class
    """

    def enrich(self):
        """
        Enriches IPv4, IPv6, Domain and URLs observables within the indicator
        """

        self._observed_data_refs = list()
        self._stix_objects = list()
        for observable in self._stix_entity.get("x_opencti_observable_values"):
            self._helper.log_debug(f"x_opencti_observable: {observable}")
            self._stix_entity["value"] = observable.get(
                "value"
            )  # @NOTE: should we use a new stix entity?
            match observable.get("type"):
                case "IPv4-Addr":
                    enricher = IPv4Enricher(self._helper, self._stix_entity)
                case "IPv6-Addr":
                    enricher = IPv6Enricher(self._helper, self._stix_entity)
                case "Domain-Name" | "Hostname":
                    enricher = DomainEnricher(self._helper, self._stix_entity)
                case "Url":
                    enricher = URLEnricher(self._helper, self._stix_entity)
            if not enricher:
                continue
            enricher._observed_data_refs = list()
            self._stix_objects.extend(enricher.process())
            self._observed_data_refs.extend(enricher._observed_data_refs)
        self._helper.log_debug(
            f"self._observed_data_refs: {set(self._observed_data_refs)}"
        )

    def process(self) -> list:
        """
        Adds enriched data as observed data to the stix bundle

        :return: the stix objects list
        """

        self._helper.log_debug(
            f"x_opencti_observable_values: {self._stix_entity.get('x_opencti_observable_values'):}"
        )
        self.enrich()
        observed_data = ObservedData(
            id=pycti.ObservedData.generate_id(list(set(self._observed_data_refs))),
            type="observed-data",
            first_observed=datetime.now(),
            last_observed=datetime.now(),
            object_refs=list(set(self._observed_data_refs)),
            number_observed=1,
            created_by_ref=self._author["id"],
        )
        self._stix_objects.append(observed_data)
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", observed_data.id, self._stix_entity.get("id")
            ),
            relationship_type="related-to",
            target_ref=self._stix_entity.get("id"),
            description="Indicator observables",
            source_ref=observed_data.id,
            allow_custom=True,
            created_by_ref=self._author["id"],
        )
        self._stix_objects.append(relationship)
        return self._stix_objects
