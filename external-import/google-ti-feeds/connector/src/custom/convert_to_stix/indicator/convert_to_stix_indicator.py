"""Convert IOC delta entries to STIX objects."""

import ipaddress
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaEntry,
    IOCDeltaRelationshipItem,
)
from connectors_sdk.models import (
    AttackPattern,
    Campaign,
    ExternalReference,
    Indicator,
    IntrusionSet,
    Malware,
    Relationship,
    Tool,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType
from stix2.base import _STIXBase

if TYPE_CHECKING:
    import logging

    from connector.src.custom.configs import GTIConfig

LOG_PREFIX = "[ConvertToSTIXIndicator]"


class ConvertToSTIXIndicator(BaseConvertToSTIX):
    """Convert IOC delta entries to STIX objects."""

    def __init__(self, config: "GTIConfig", logger: "logging.Logger", tlp_level: str):
        super().__init__(config, logger, tlp_level)

        self._converter = {
            "domain": self._convert_domain,
            "file": self._convert_file,
            "ip_address": self._convert_ip,
            "url": self._convert_url,
        }

        self._relation_mappings = {
            "malware_families": self._create_relation_malware_family,
            # "campaigns": self._create_relation_campaign,
            "threat_actors": self._create_relation_threat_actor,
            "software_toolkits": self._create_relation_software_toolkit,
            "attack_techniques": self._create_relation_attack_technique,
        }

    def _is_below_min_score(self, entry: IOCDeltaEntry) -> bool:
        """Check whether an IOC entry's GTI score is below the configured minimum.

        The filter is disabled entirely (nothing is discarded) when
        indicator_min_score is None or set to 100. Entries without a GTI score
        are never filtered out, since there is no score to compare against the
        threshold.
        """
        min_score = self.config.indicator_min_score
        if min_score is None or min_score >= 100:
            return False

        attrs = entry.attributes
        if (
            attrs is None
            or attrs.gti_assessment is None
            or attrs.gti_assessment.threat_score is None
            or attrs.gti_assessment.threat_score.value is None
        ):
            return False

        return attrs.gti_assessment.threat_score.value < min_score

    def _lacks_required_association(self, entry: IOCDeltaEntry) -> bool:
        """Check whether an IOC entry lacks the required malware/threat actor associations.

        The filter is disabled when both indicator_require_malware_family and
        indicator_require_threat_actor are False (default). When one or both are
        enabled, the indicator must have at least one matching association (OR
        logic between the two). This filter is combined with the score filter
        using AND logic.
        """
        require_malware = self.config.indicator_require_malware_family
        require_threat_actor = self.config.indicator_require_threat_actor

        if not require_malware and not require_threat_actor:
            return False

        rels = entry.relationships

        has_malware = (
            rels is not None
            and rels.malware_families is not None
            and len(rels.malware_families.data) > 0
        )
        has_threat_actor = (
            rels is not None
            and rels.threat_actors is not None
            and len(rels.threat_actors.data) > 0
        )

        if require_malware and not require_threat_actor:
            return not has_malware
        if require_threat_actor and not require_malware:
            return not has_threat_actor
        # Both required: OR logic — at least one must be present
        return not (has_malware or has_threat_actor)

    def convert(self, ioc_data: dict[str, Any]) -> list[Any]:
        """Convert a single IOC delta entry to STIX objects."""
        try:
            entry = IOCDeltaEntry.model_validate(ioc_data)
        except Exception as e:
            self.logger.warning(
                "Failed to parse IOC delta entry",
                {"prefix": LOG_PREFIX, "error": str(e), "data": str(ioc_data)[:200]},
            )
            return []

        if self._is_below_min_score(entry):
            self.logger.debug(
                "IOC entry below minimum GTI score, skipping",
                {
                    "prefix": LOG_PREFIX,
                    "type": entry.type,
                    "id": entry.id,
                    "min_score": self.config.indicator_min_score,
                },
            )
            return []

        if self._lacks_required_association(entry):
            self.logger.debug(
                "IOC entry lacks required malware/threat actor association, skipping",
                {
                    "prefix": LOG_PREFIX,
                    "type": entry.type,
                    "id": entry.id,
                },
            )
            return []

        try:
            self.logger.debug(
                "Converting IOC delta entry to STIX",
                {"prefix": LOG_PREFIX, "type": entry.type, "id": entry.id},
            )
            if converter := self._converter.get(entry.type):
                ioc_entry = converter(entry)
            else:
                self.logger.debug(
                    "Unknown IOC type, skipping",
                    {"prefix": LOG_PREFIX, "type": entry.type, "id": entry.id},
                )
                return []
        except Exception as e:
            self.logger.warning(
                "Failed to convert IOC entry to STIX",
                {
                    "prefix": LOG_PREFIX,
                    "type": entry.type,
                    "id": entry.id,
                    "error": str(e),
                },
            )
            return []

        if not ioc_entry:
            self.logger.debug(
                "Conversion returned None, skipping",
                {"prefix": LOG_PREFIX, "type": entry.type, "id": entry.id},
            )
            return []

        rel_objects = self._build_relationships(entry, ioc_entry)

        return rel_objects

    def _convert_file(self, entry: IOCDeltaEntry) -> Indicator | None:
        """Convert a file IOC delta entry to a STIX Indicator with file observable."""
        attrs = entry.attributes
        if attrs is None:
            return None

        hashes = {}
        patterns = []
        for hash_algo, hash_value in [
            (HashAlgorithm.SHA256, attrs.sha256),
            (HashAlgorithm.MD5, attrs.md5),
            (HashAlgorithm.SHA1, attrs.sha1),
        ]:
            if hash_value is None:
                continue
            patterns.append(f"file:hashes.'{hash_algo.value}' = '{hash_value}'")
            hashes[hash_algo] = hash_value

        if not patterns:
            return None

        pattern = f"[{' OR '.join(patterns)}]"

        if attrs.gti_assessment and attrs.gti_assessment.threat_score:
            score = attrs.gti_assessment.threat_score.value
        else:
            score = None

        return Indicator(
            name=attrs.meaningful_name if attrs.meaningful_name else entry.id,
            pattern=pattern,
            pattern_type="stix",
            main_observable_type="StixFile",
            author=self.organization,
            markings=[self.tlp_marking],
            score=score,
            valid_from=(
                datetime.fromtimestamp(attrs.creation_date, tz=timezone.utc)
                if attrs.creation_date
                else None
            ),
            create_observables=True,
            external_references=[
                ExternalReference(
                    source_name=f"[GTI] File {entry.id}",
                    description="Google Threat Intelligence File Link",
                    url=f"https://www.virustotal.com/gui/file/{entry.id}",
                )
            ],
        )

    def _detect_ip_version(self, ip_addr: str) -> str:
        """Detect if IP is IPv4 or IPv6.

        Returns:
            str: "ipv4" or "ipv6"

        Raises:
            ValueError: If IP format is invalid

        """
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return "ipv4"
            else:
                return "ipv6"
        except ValueError as e:
            raise ValueError(f"Invalid IP address format '{ip_addr}': {e}") from e

    def _convert_ip(self, entry: IOCDeltaEntry) -> Indicator | None:
        """Convert an IP address IOC delta entry to a STIX Indicator with IP observable."""
        attrs = entry.attributes

        if attrs is None:
            return None

        ip_version = self._detect_ip_version(entry.id)
        pattern = f"[{ip_version}-addr:value = '{entry.id}']"
        observable_type = "IPv4-Addr" if ip_version == "ipv4" else "IPv6-Addr"

        return Indicator(
            name=entry.id,
            pattern=pattern,
            pattern_type="stix",
            main_observable_type=observable_type,
            author=self.organization,
            markings=[self.tlp_marking],
            score=(
                attrs.gti_assessment.threat_score.value
                if attrs.gti_assessment and attrs.gti_assessment.threat_score
                else None
            ),
            valid_from=(
                datetime.fromtimestamp(attrs.creation_date, tz=timezone.utc)
                if attrs.creation_date
                else None
            ),
            create_observables=True,
            external_references=[
                ExternalReference(
                    source_name=f"[GTI] IP {entry.id}",
                    description="Google Threat Intelligence IP Link",
                    url=f"https://www.virustotal.com/gui/ip-address/{entry.id}",
                )
            ],
        )

    def _convert_url(self, entry: IOCDeltaEntry) -> Indicator | None:
        """Convert a URL IOC delta entry to a STIX Indicator with URL observable."""
        attrs = entry.attributes
        if attrs is None or attrs.url is None:
            return None

        return Indicator(
            name=attrs.url,
            pattern=f"[url:value = '{attrs.url}']",
            pattern_type="stix",
            main_observable_type="Url",
            author=self.organization,
            markings=[self.tlp_marking],
            score=(
                attrs.gti_assessment.threat_score.value
                if attrs.gti_assessment and attrs.gti_assessment.threat_score
                else None
            ),
            valid_from=(
                datetime.fromtimestamp(attrs.creation_date, tz=timezone.utc)
                if attrs.creation_date
                else None
            ),
            create_observables=True,
            external_references=[
                ExternalReference(
                    source_name=f"[GTI] URL {attrs.url}",
                    description="Google Threat Intelligence URL Link",
                    url=f"https://www.virustotal.com/gui/url/{entry.id}",
                )
            ],
        )

    def _convert_domain(self, entry: IOCDeltaEntry) -> Indicator | None:
        """Convert a domain IOC delta entry to a STIX Indicator with domain observable."""
        attrs = entry.attributes
        if attrs is None:
            return None

        return Indicator(
            name=entry.id,
            pattern=f"[domain-name:value = '{entry.id}']",
            pattern_type="stix",
            main_observable_type="Domain-Name",
            author=self.organization,
            markings=[self.tlp_marking],
            score=(
                attrs.gti_assessment.threat_score.value
                if attrs.gti_assessment and attrs.gti_assessment.threat_score
                else None
            ),
            valid_from=(
                datetime.fromtimestamp(attrs.creation_date, tz=timezone.utc)
                if attrs.creation_date
                else None
            ),
            create_observables=True,
            external_references=[
                ExternalReference(
                    source_name=f"[GTI] Domain {entry.id}",
                    description="Google Threat Intelligence Domain Link",
                    url=f"https://www.virustotal.com/gui/domain/{entry.id}",
                )
            ],
        )

    def _build_relationships(
        self, entry: IOCDeltaEntry, ioc_entry: Indicator
    ) -> list[_STIXBase]:
        """Build STIX relationship objects based on the relationships in the IOC delta entry."""
        if not entry.relationships:
            return []

        rels: list[_STIXBase] = [ioc_entry.to_stix2_object()]

        for rel_field, rel_func in self._relation_mappings.items():
            rel_data = getattr(entry.relationships, rel_field, None)
            if not rel_data:
                continue
            for item in rel_data.data:
                rels.extend(rel_func(ioc_entry, item))

        return rels

    def _create_relation_malware_family(
        self, ioc_entry: Indicator, malware_data: IOCDeltaRelationshipItem
    ) -> list[_STIXBase]:

        if not malware_data.attributes or not malware_data.attributes.name:
            return []

        malware_name = malware_data.attributes.name

        malware = Malware(
            name=malware_name.upper(),
            is_family=True,
            author=self.organization,
            markings=[self.tlp_marking],
        )

        relationship = Relationship(
            type=RelationshipType.INDICATES,
            source=ioc_entry,
            target=malware,
            author=self.organization,
            markings=[self.tlp_marking],
        )

        return [
            malware.to_stix2_object(),
            relationship.to_stix2_object(),
        ]

    def _create_relation_campaign(
        self, ioc_entry: Indicator, campaign_data: IOCDeltaRelationshipItem
    ) -> list[_STIXBase]:
        if not campaign_data.attributes or not campaign_data.attributes.name:
            return []

        campaign_name = campaign_data.attributes.name

        campaign = Campaign(
            name=campaign_name,
            author=self.organization,
            markings=[self.tlp_marking],
        )

        relationship = Relationship(
            type=RelationshipType.INDICATES,
            source=ioc_entry,
            target=campaign,
            author=self.organization,
            markings=[self.tlp_marking],
        )

        return [
            campaign.to_stix2_object(),
            relationship.to_stix2_object(),
        ]

    def _create_relation_threat_actor(
        self,
        ioc_entry: Indicator,
        threat_actor_data: IOCDeltaRelationshipItem,
    ) -> list[_STIXBase]:
        if not threat_actor_data.attributes or not threat_actor_data.attributes.name:
            return []

        threat_actor_name = threat_actor_data.attributes.name

        intrusion_set = IntrusionSet(
            name=threat_actor_name.upper(),
            author=self.organization,
            markings=[self.tlp_marking],
        )
        relationship = Relationship(
            type=RelationshipType.INDICATES,
            source=ioc_entry,
            target=intrusion_set,
            author=self.organization,
            markings=[self.tlp_marking],
        )

        return [
            intrusion_set.to_stix2_object(),
            relationship.to_stix2_object(),
        ]

    def _create_relation_software_toolkit(
        self,
        ioc_entry: Indicator,
        software_toolkit_data: IOCDeltaRelationshipItem,
    ) -> list[_STIXBase]:
        if (
            not software_toolkit_data.attributes
            or not software_toolkit_data.attributes.name
        ):
            return []

        software_toolkit_name = software_toolkit_data.attributes.name

        software_toolkit = Tool(
            name=software_toolkit_name.upper(),
            author=self.organization,
            markings=[self.tlp_marking],
        )

        relationship = Relationship(
            type=RelationshipType.INDICATES,
            source=ioc_entry,
            target=software_toolkit,
            author=self.organization,
            markings=[self.tlp_marking],
        )

        return [
            software_toolkit.to_stix2_object(),
            relationship.to_stix2_object(),
        ]

    def _create_relation_attack_technique(
        self,
        ioc_entry: Indicator,
        attack_technique_data: IOCDeltaRelationshipItem,
    ) -> list[_STIXBase]:
        if not attack_technique_data.id:
            return []

        attack_technique_id = attack_technique_data.id

        attack_pattern = AttackPattern(
            name=attack_technique_id.upper(),
            mitre_id=attack_technique_id.upper(),
            author=self.organization,
            markings=[self.tlp_marking],
        )

        relationship = Relationship(
            type=RelationshipType.INDICATES,
            source=ioc_entry,
            target=attack_pattern,
            author=self.organization,
            markings=[self.tlp_marking],
        )

        return [
            attack_pattern.to_stix2_object(),
            relationship.to_stix2_object(),
        ]
