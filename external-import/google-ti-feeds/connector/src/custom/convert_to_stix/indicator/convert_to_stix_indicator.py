"""Convert IOC delta entries to STIX objects."""

import ipaddress
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX
from connector.src.custom.mappers.gti_iocs.gti_links import gti_external_reference
from connector.src.custom.mappers.gti_iocs.ioc_assessment import (
    build_ioc_description,
    ioc_tag_labels,
)
from connector.src.custom.mappers.gti_iocs.ioc_infrastructure import (
    INFRASTRUCTURE_RULES,
    InfrastructureRule,
    related_value,
)
from connector.src.custom.mappers.gti_iocs.ioc_scoring import (
    compute_ioc_score,
    meets_min_verdict,
)
from connector.src.custom.mappers.gti_iocs.stix_pattern import escape_pattern_value
from connector.src.custom.mappers.relationship_reasons import (
    ioc_delta_association_reason,
    ioc_threat_evidence,
    optional_reason,
)
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
    IOCDeltaRelationshipItem,
)
from connectors_sdk.models import (
    URL,
    AttackPattern,
    Campaign,
    DomainName,
    ExternalReference,
    File,
    Indicator,
    IntrusionSet,
    IPV4Address,
    IPV6Address,
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

# Delta relationship list -> STIX type of the threat, for the GTI evidence.
DELTA_THREAT_TYPES = {
    "malware_families": "malware",
    "threat_actors": "intrusion-set",
    "software_toolkits": "tool",
    "attack_techniques": "attack-pattern",
    "campaigns": "campaign",
}


class ConvertToSTIXIndicator(BaseConvertToSTIX):
    """Convert IOC delta entries to STIX objects."""

    def __init__(self, config: "GTIConfig", logger: "logging.Logger", tlp_level: str):
        super().__init__(config, logger, tlp_level)

        # Attack techniques skipped for lack of a name since the last pop
        self._skipped_attack_technique_count = 0

        self._converter = {
            "domain": self._convert_domain,
            "file": self._convert_file,
            "ip_address": self._convert_ip,
            "url": self._convert_url,
        }

        relation_mappings = {
            "malware_families": self._create_relation_malware_family,
            # "campaigns": self._create_relation_campaign,
            "threat_actors": self._create_relation_threat_actor,
            "software_toolkits": self._create_relation_software_toolkit,
            "attack_techniques": self._create_relation_attack_technique,
        }
        self._relation_mappings = {
            subentity: create_relation
            for subentity, create_relation in relation_mappings.items()
            if subentity in config.indicator_subentities
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

    def _has_required_association(self, entry: IOCDeltaEntry) -> bool:
        """Check whether an IOC entry has the required malware/threat actor associations.

        The filter is disabled when both indicator_require_malware_family and
        indicator_require_threat_actor are False (default), in which case this
        always returns True. When one or both are enabled, the indicator must
        have at least one matching association (OR logic between the two). This
        filter is combined with the score filter using AND logic.
        """
        require_malware = self.config.indicator_require_malware_family
        require_threat_actor = self.config.indicator_require_threat_actor

        if not require_malware and not require_threat_actor:
            return True

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
            return has_malware
        if require_threat_actor and not require_malware:
            return has_threat_actor
        # Both required: OR logic — at least one must be present
        return has_malware or has_threat_actor

    def pop_skipped_attack_technique_count(self) -> int:
        """Return and reset the count of attack techniques skipped for lack of a name.

        Returns:
            The number of skipped attack technique references since the last call.

        """
        count = self._skipped_attack_technique_count
        self._skipped_attack_technique_count = 0
        return count

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

        if not meets_min_verdict(entry.attributes, self.config.indicator_min_verdict):
            self.logger.debug(
                "IOC entry below minimum GTI verdict, skipping",
                {
                    "prefix": LOG_PREFIX,
                    "type": entry.type,
                    "id": entry.id,
                    "min_verdict": self.config.indicator_min_verdict,
                },
            )
            return []

        if not self._has_required_association(entry):
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
        if rel_objects:
            rel_objects.extend(self._build_infrastructure(entry))

        return rel_objects

    def _get_score(self, attrs: IOCDeltaAttributes) -> int | None:
        """Compute the indicator score with the configured scoring strategy."""
        return compute_ioc_score(attrs, self.config.indicator_scoring)

    def _get_description(self, attrs: IOCDeltaAttributes) -> str | None:
        """Build the GTI assessment description when enabled."""
        if not self.config.extended_descriptions:
            return None
        return build_ioc_description(attrs)

    def _get_labels(self, attrs: IOCDeltaAttributes) -> list[str] | None:
        """Return the GTI tags as labels when enabled."""
        if not self.config.ioc_tags_as_labels:
            return None
        return ioc_tag_labels(attrs.tags)

    def _build_indicator(
        self,
        attrs: IOCDeltaAttributes,
        name: str,
        pattern: str,
        observable_type: str,
        reference: dict[str, str],
    ) -> Indicator:
        """Return the indicator of an IOC delta entry, with its observable created by OpenCTI.

        Args:
            attrs: The entry attributes: score, description, labels and valid from date.
            name: The indicator name.
            pattern: The STIX pattern.
            observable_type: The OpenCTI type of the main observable.
            reference: The external reference to the GTI page of the IOC.

        """
        return Indicator(
            name=name,
            pattern=pattern,
            pattern_type="stix",
            main_observable_type=observable_type,
            author=self.organization,
            markings=[self.tlp_marking],
            score=self._get_score(attrs),
            description=self._get_description(attrs),
            labels=self._get_labels(attrs),
            valid_from=(
                datetime.fromtimestamp(attrs.creation_date, tz=timezone.utc)
                if attrs.creation_date
                else None
            ),
            create_observables=True,
            external_references=[ExternalReference(**reference)],
        )

    def _convert_file(self, entry: IOCDeltaEntry) -> Indicator | None:
        """Convert a file IOC delta entry to a STIX Indicator with file observable."""
        attrs = entry.attributes
        if attrs is None:
            return None

        patterns = []
        for hash_algo, hash_value in [
            (HashAlgorithm.SHA256, attrs.sha256),
            (HashAlgorithm.MD5, attrs.md5),
            (HashAlgorithm.SHA1, attrs.sha1),
        ]:
            if hash_value is None:
                continue
            patterns.append(f"file:hashes.'{hash_algo.value}' = '{hash_value}'")

        if not patterns:
            return None

        pattern = f"[{' OR '.join(patterns)}]"

        return self._build_indicator(
            attrs,
            name=attrs.meaningful_name if attrs.meaningful_name else entry.id,
            pattern=pattern,
            observable_type="StixFile",
            reference=gti_external_reference("file", entry.id),
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

        return self._build_indicator(
            attrs,
            name=entry.id,
            pattern=pattern,
            observable_type=observable_type,
            reference=gti_external_reference("ip_address", entry.id),
        )

    def _convert_url(self, entry: IOCDeltaEntry) -> Indicator | None:
        """Convert a URL IOC delta entry to a STIX Indicator with URL observable."""
        attrs = entry.attributes
        if attrs is None or attrs.url is None:
            return None

        return self._build_indicator(
            attrs,
            name=attrs.url,
            pattern=f"[url:value = '{escape_pattern_value(attrs.url)}']",
            observable_type="Url",
            reference=gti_external_reference("url", entry.id, attrs.url),
        )

    def _convert_domain(self, entry: IOCDeltaEntry) -> Indicator | None:
        """Convert a domain IOC delta entry to a STIX Indicator with domain observable."""
        attrs = entry.attributes
        if attrs is None:
            return None

        return self._build_indicator(
            attrs,
            name=entry.id,
            pattern=f"[domain-name:value = '{escape_pattern_value(entry.id)}']",
            observable_type="Domain-Name",
            reference=gti_external_reference("domain", entry.id),
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
                evidence = ioc_threat_evidence(
                    entry.attributes.gti_assessment if entry.attributes else None,
                    DELTA_THREAT_TYPES.get(rel_field),
                    item.attributes.name if item.attributes else None,
                    item.id,
                )
                rels.extend(rel_func(ioc_entry, item, evidence))

        return rels

    def _build_infrastructure(self, entry: IOCDeltaEntry) -> list[_STIXBase]:
        """Return the infrastructure observables of the entry, linked to the IOC observable.

        Enabled by indicator_infrastructure. The IOC observable is sent with them:
        OpenCTI also creates it from the indicator, with the same ID.
        """
        categories = set(getattr(self.config, "indicator_infrastructure", None) or [])
        rules = [
            rule
            for rule in INFRASTRUCTURE_RULES
            if rule.category in categories and rule.ioc_type == entry.type
        ]
        if not rules or entry.relationships is None:
            return []
        ioc_value = self._ioc_value(entry)
        ioc_observable = self._ioc_observable(entry) if ioc_value else None
        if ioc_value is None or ioc_observable is None:
            return []

        objects: list[_STIXBase] = []
        for rule in rules:
            for value in self._related_values(rule, entry, ioc_value):
                related = self._observable(rule.related_type, value)
                source, target = (
                    (ioc_observable, related)
                    if rule.ioc_is_source
                    else (related, ioc_observable)
                )
                relationship = Relationship(
                    type=RelationshipType(rule.relationship_type),
                    source=source,
                    target=target,
                    author=self.organization,
                    markings=[self.tlp_marking],
                    description=optional_reason(
                        "Stated by GTI: "
                        + rule.reason.format(ioc=ioc_value, related=value)
                    ),
                )
                objects.extend(
                    [related.to_stix2_object(), relationship.to_stix2_object()]
                )
        if objects:
            objects.insert(0, ioc_observable.to_stix2_object())
        return objects

    def _related_values(
        self, rule: InfrastructureRule, entry: IOCDeltaEntry, ioc_value: str
    ) -> list[str]:
        """Return the valid related values of a rule, deduplicated and capped."""
        data = getattr(entry.relationships, rule.field, None)
        values = (
            related_value(rule, ioc_value, item.id or "")
            for item in (data.data if data else [])
        )
        unique_values = list(dict.fromkeys(value for value in values if value))
        return unique_values[: self.config.indicator_infrastructure_limit]

    @staticmethod
    def _ioc_value(entry: IOCDeltaEntry) -> str | None:
        """Return the value identifying the IOC in relationship descriptions."""
        if entry.type == "url":
            return entry.attributes.url if entry.attributes else None
        return entry.id

    def _ioc_observable(self, entry: IOCDeltaEntry) -> Any | None:
        """Return the observable of the IOC itself, as created from its indicator."""
        attrs = entry.attributes
        if entry.type == "file":
            hashes = {
                algorithm: value
                for algorithm, value in (
                    (HashAlgorithm.SHA256, attrs.sha256 if attrs else None),
                    (HashAlgorithm.MD5, attrs.md5 if attrs else None),
                    (HashAlgorithm.SHA1, attrs.sha1 if attrs else None),
                )
                if value
            }
            if not hashes:
                return None
            return File(
                hashes=hashes, author=self.organization, markings=[self.tlp_marking]
            )
        if entry.type == "url":
            if not attrs or not attrs.url:
                return None
            return URL(
                value=attrs.url, author=self.organization, markings=[self.tlp_marking]
            )
        kind = "ip" if entry.type == "ip_address" else "domain"
        return self._observable(kind, entry.id)

    def _observable(self, kind: str, value: str) -> Any:
        """Return a domain, IP or file (SHA-256) observable."""
        common = {"author": self.organization, "markings": [self.tlp_marking]}
        if kind == "file":
            return File(hashes={HashAlgorithm.SHA256: value}, **common)
        if kind == "ip":
            if self._detect_ip_version(value) == "ipv4":
                return IPV4Address(value=value, **common)
            return IPV6Address(value=value, **common)
        return DomainName(value=value, **common)

    def _indicates(
        self, ioc_entry: Indicator, target: Any, evidence: str | None = None
    ) -> list[_STIXBase]:
        """Return the target and the 'indicates' relationship from the IOC to it.

        The description states that the IOC deltas feed lists the target, then the
        GTI evidence of the IOC supporting the link.
        """
        stix_target = target.to_stix2_object()
        relationship = Relationship(
            type=RelationshipType.INDICATES,
            source=ioc_entry,
            target=target,
            author=self.organization,
            markings=[self.tlp_marking],
            description=optional_reason(
                " ".join(
                    part
                    for part in (ioc_delta_association_reason(stix_target), evidence)
                    if part
                )
            ),
        )
        return [stix_target, relationship.to_stix2_object()]

    def _create_relation_malware_family(
        self,
        ioc_entry: Indicator,
        malware_data: IOCDeltaRelationshipItem,
        evidence: str | None = None,
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

        return self._indicates(ioc_entry, malware, evidence)

    def _create_relation_campaign(
        self,
        ioc_entry: Indicator,
        campaign_data: IOCDeltaRelationshipItem,
        evidence: str | None = None,
    ) -> list[_STIXBase]:
        if not campaign_data.attributes or not campaign_data.attributes.name:
            return []

        campaign_name = campaign_data.attributes.name

        campaign = Campaign(
            name=campaign_name,
            author=self.organization,
            markings=[self.tlp_marking],
        )

        return self._indicates(ioc_entry, campaign, evidence)

    def _create_relation_threat_actor(
        self,
        ioc_entry: Indicator,
        threat_actor_data: IOCDeltaRelationshipItem,
        evidence: str | None = None,
    ) -> list[_STIXBase]:
        if not threat_actor_data.attributes or not threat_actor_data.attributes.name:
            return []

        threat_actor_name = threat_actor_data.attributes.name

        intrusion_set = IntrusionSet(
            name=threat_actor_name.upper(),
            author=self.organization,
            markings=[self.tlp_marking],
        )

        return self._indicates(ioc_entry, intrusion_set, evidence)

    def _create_relation_software_toolkit(
        self,
        ioc_entry: Indicator,
        software_toolkit_data: IOCDeltaRelationshipItem,
        evidence: str | None = None,
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

        return self._indicates(ioc_entry, software_toolkit, evidence)

    def _create_relation_attack_technique(
        self,
        ioc_entry: Indicator,
        attack_technique_data: IOCDeltaRelationshipItem,
        evidence: str | None = None,
    ) -> list[_STIXBase]:
        if not attack_technique_data.id:
            return []

        attack_technique_id = attack_technique_data.id

        # The attack pattern ID only depends on the MITRE ID: it merges with the
        # MITRE ATT&CK technique, so it must never be named after its own ID.
        attack_technique_name = getattr(attack_technique_data.attributes, "name", None)
        if not attack_technique_name or not attack_technique_name.strip():
            # Counted, not logged: the IOC delta feed never carries technique names,
            # so the orchestrator logs one warning per package from this counter.
            self._skipped_attack_technique_count += 1
            return []

        attack_pattern = AttackPattern(
            name=attack_technique_name,
            mitre_id=attack_technique_id.upper(),
            author=self.organization,
            markings=[self.tlp_marking],
        )

        return self._indicates(ioc_entry, attack_pattern, evidence)
