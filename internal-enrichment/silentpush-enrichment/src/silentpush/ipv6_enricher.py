import uuid

import requests
from pycti import StixCoreRelationship
from settings import API_KEY, API_VERIFY_CERT
from stix2 import IPv6Address, Relationship

from .ip_enricher import IPEnricher


class IPv6Enricher(IPEnricher):
    """
    The IPv6 Enrichment class
    """

    def _build_subnet(self):
        """
        Adds subnet enriched data to the stix bundle
        """

        subnet_data = self._extract_subnet()
        if not subnet_data.get("subnet"):
            return
        self._helper.log_debug(f"building Subnet: {subnet_data.get('subnet')}")
        subnet = IPv6Address(
            id=f"ipv6-addr--{uuid.uuid4()}",
            type="ipv6-addr",
            value=subnet_data.get("subnet"),
        )
        if subnet.value == self._ip.value:
            return
        self._observed_data_refs.append(subnet.id)
        self._stix_objects.append(subnet)
        self._helper.log_debug(subnet)
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", self._ip.value, subnet.id
            ),
            relationship_type="related-to",
            target_ref=subnet.id,
            description="Subnet",
            source_ref=self._ip.id,
            allow_custom=True,
            created_by_ref=self._author["id"],
        )
        self._stix_objects.append(relationship)

    def _build_ip(self):
        """
        Adds IPv6 enriched data to the stix bundle
        """

        self._ip = IPv6Address(
            id=f"ipv6-addr--{uuid.uuid4()}",
            type="ipv6-addr",
            value=self._sanitized_ip,
            custom_properties={
                "score": self._enriched_data.get("sp_risk_score"),
                "x_density": self._enriched_data.get("density"),
                **self._extract_reputations(),
                **self._extract_scores(),
            },
            **self._build_extensions(),
        )
        self._observed_data_refs.append(self._ip.id)
        self._stix_objects.append(self._ip)

    def _do_request(self):
        """
        Calls Silent Push API to enrich IPv6
        """

        import re

        from settings import enrich_uri

        self._sanitized_ip = re.sub(r"/\d+", "", self._stix_entity.get("value"))
        enrich_uri = enrich_uri.format(type="ipv6", ioc=self._sanitized_ip)
        return requests.get(
            enrich_uri, headers={"x-api-key": API_KEY}, verify=API_VERIFY_CERT
        )
