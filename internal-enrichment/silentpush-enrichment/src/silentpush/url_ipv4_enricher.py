from pycti import StixCoreRelationship
from stix2 import Relationship

from .ipv4_enricher import IPv4Enricher


class URLIPv4Enricher(IPv4Enricher):
    """
    The IPv4 based URL Enrichment class

    :param helper: the OpenCTIConnectorHelper instance
    :param stix_entity: the dictionary stix entity data
    :param ipv4: the IPv4 to be enriched
    """

    def __init__(self, helper, stix_entity, ipv4):
        super().__init__(helper, stix_entity)
        self._stix_entity["value"] = ipv4
        self._helper.log_debug(f"self._stix_entity: {self._stix_entity}")

    def _build_ip(self):
        """
        Adds IPv4 enriched data to the stix bundle with a relationship to the URL
        """

        super()._build_ip()
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", self._ip.value, self._stix_entity.get("id")
            ),
            relationship_type="related-to",
            target_ref=self._stix_entity.get("id"),
            description="URL IPv4",
            source_ref=self._ip.id,
            allow_custom=True,
            created_by_ref=self._author["id"],
        )
        self._stix_objects.append(relationship)
