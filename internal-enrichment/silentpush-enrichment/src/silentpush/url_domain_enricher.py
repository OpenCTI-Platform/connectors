from pycti import StixCoreRelationship
from stix2 import Relationship

from .domain_enricher import DomainEnricher


class URLDomainEnricher(DomainEnricher):
    """
    The Domain based URL Enrichment class

    :param helper: the OpenCTIConnectorHelper instance
    :param stix_entity: the dictionary stix entity data
    :param domain: the Domain to be enriched
    """

    def __init__(self, helper, stix_entity, domain):
        super().__init__(helper, stix_entity)
        self._stix_entity["value"] = domain
        self._helper.log_debug(f"self._stix_entity: {self._stix_entity}")

    def _build_domain(self):
        """
        Adds Domain enriched data to the stix bundle with a relationship to the URL
        """

        super()._build_domain()
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", self._domain.value, self._stix_entity.get("id")
            ),
            relationship_type="related-to",
            target_ref=self._stix_entity.get("id"),
            description="URL domain",
            source_ref=self._domain.id,
            allow_custom=True,
            created_by_ref=self._author["id"],
        )
        self._stix_objects.append(relationship)
