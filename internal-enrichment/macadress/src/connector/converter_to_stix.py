"""STIX shaping for the macadress.com enrichment connector.

The enriched Mac-Addr observable is updated in place by the connector via
``OpenCTIStix2.put_attribute_in_extension``. This module only mints the extra
SDOs: the author Identity, the registering-vendor Organization Identity and the
relationship linking the observable to it. Every object carries a deterministic
STIX id.
"""

import stix2
from pycti import Identity, StixCoreRelationship


class ConverterToStix:
    def __init__(self, author: stix2.Identity, default_score: int) -> None:
        self.author = author
        self.default_score = default_score

    @staticmethod
    def make_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(
                name="macadress.com", identity_class="organization"
            ),
            name="macadress.com",
            identity_class="organization",
            description=(
                "MAC/OUI vendor, device and MAC-randomization intelligence "
                "(macadress.com)."
            ),
        )

    def vendor_identity(self, organization: str, country: str | None) -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name=organization, identity_class="organization"),
            name=organization,
            identity_class="organization",
            description="IEEE-registered MAC address block holder (via macadress.com).",
            created_by_ref=self.author["id"],
            custom_properties={
                "x_opencti_organization_type": "vendor",
                "x_opencti_labels": ["macadress"],
                "x_opencti_reliability": "B - Usually reliable",
                "x_opencti_aliases": [country] if country else [],
            },
        )

    def relationship(
        self,
        source_ref: str,
        relationship_type: str,
        target_ref: str,
        description: str | None = None,
        object_marking_refs: list[str] | None = None,
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_ref, target_ref
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            description=description,
            created_by_ref=self.author["id"],
            object_marking_refs=object_marking_refs or [],
        )
