import html
import re
from datetime import datetime, timezone

import stix2
from connectors_sdk.models import (
    URL,
    AttackPattern,
    AutonomousSystem,
    DomainName,
    EmailAddress,
    ExternalReference,
    File,
    Indicator,
    IntrusionSet,
    IPV4Address,
    IPV6Address,
    KillChainPhase,
    Malware,
    Organization,
    OrganizationAuthor,
    Relationship,
    Sighting,
    Text,
    TLPMarking,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType, TLPLevel
from pycti import OpenCTIConnectorHelper

from .utils import is_domain


class IndicatorConverterToStix:
    """Convert Flashpoint indicators into STIX/OpenCTI objects.

    This converter supports both regular indicator payloads and
    `extracted_config` payloads that may contain multiple IoCs.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_definition: str = "TLP:GREEN",
    ):
        """Initialize converter dependencies and default marking.

        Args:
            helper: OpenCTI connector helper used for logging and object context.
            tlp_definition: TLP definition for generated indicator-related objects.
        """
        self.helper = helper
        self.author = self._create_author()
        tlp_level_mapping = {
            "TLP:CLEAR": TLPLevel.CLEAR,
            "TLP:GREEN": TLPLevel.GREEN,
            "TLP:AMBER": TLPLevel.AMBER,
            "TLP:AMBER+STRICT": TLPLevel.AMBER_STRICT,
            "TLP:RED": TLPLevel.RED,
        }
        self.marking = TLPMarking(level=tlp_level_mapping[tlp_definition])

    def _create_author(self) -> OrganizationAuthor:
        """Build the Flashpoint author object.

        Returns:
            OrganizationAuthor: Author used on generated STIX objects.
        """
        return OrganizationAuthor(
            name="Flashpoint",
            description=(
                "Flashpoint is a data and intelligence company that empowers "
                "customers to take rapid, decisive action to stop threats and reduce risk."
            ),
        )

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        """Parse ISO datetime string to a datetime object.

        Args:
            value: Datetime string, potentially ending with `Z`.

        Returns:
            datetime | None: Parsed datetime or `None` when invalid.
        """
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    @staticmethod
    def _extract_ioc_type(indicator: dict) -> str | None:
        """Extract IoC type from indicator payload.

        Args:
            indicator: Indicator payload dictionary.

        Returns:
            str | None: IoC type from `type` field.
        """
        return indicator.get("type") or None

    @staticmethod
    def _extract_ioc_value(indicator: dict, ioc_type: str) -> str | None:
        """Extract IoC value from indicator payload.

        Args:
            indicator: Indicator payload dictionary.
            ioc_type: Previously resolved IoC type.

        Returns:
            str | None: IoC value from `value`, or hash fallback for file indicators.
        """
        raw_value = indicator.get("value")
        if raw_value:
            return raw_value

        if ioc_type.lower() == "file":
            hashes = indicator.get("hashes")
            if hashes:
                for algo in ["sha256", "sha1", "md5"]:
                    hash_value = hashes.get(algo)
                    if hash_value:
                        return hash_value

        return None

    @staticmethod
    def _extract_file_ioc(indicator: dict) -> tuple[str, str] | None:
        """Resolve file IoC STIX path and value.

        Args:
            indicator: Indicator payload dictionary.

        Returns:
            tuple[str, str] | None: `(stix_path, ioc_value)` for file indicators,
            or `None` if no usable value is found.
        """
        hashes = indicator.get("hashes")
        if hashes:
            for algo, stix_path in [
                ("sha256", "hashes.SHA-256"),
                ("sha1", "hashes.SHA-1"),
                ("md5", "hashes.MD5"),
            ]:
                hash_value = hashes.get(algo)
                if hash_value:
                    return stix_path, hash_value

        raw_ioc_value = indicator.get("value")
        if raw_ioc_value:
            normalized_value = raw_ioc_value.strip()
            lowered_value = normalized_value.lower()

            if lowered_value.startswith("md5:"):
                return "hashes.MD5", normalized_value.split(":", maxsplit=1)[1].strip()
            if lowered_value.startswith("sha1:"):
                return (
                    "hashes.SHA-1",
                    normalized_value.split(":", maxsplit=1)[1].strip(),
                )
            if lowered_value.startswith("sha256:"):
                return (
                    "hashes.SHA-256",
                    normalized_value.split(":", maxsplit=1)[1].strip(),
                )

            if re.fullmatch(r"[A-Fa-f0-9]{32}", normalized_value):
                return "hashes.MD5", normalized_value
            if re.fullmatch(r"[A-Fa-f0-9]{40}", normalized_value):
                return "hashes.SHA-1", normalized_value
            if re.fullmatch(r"[A-Fa-f0-9]{64}", normalized_value):
                return "hashes.SHA-256", normalized_value

            return "name", normalized_value

        return None

    @staticmethod
    def _resolve_score(indicator: dict) -> int:
        """Resolve OpenCTI score from indicator payload.

        Args:
            indicator: Indicator payload dictionary.

        Returns:
            int: Score in range 0-100.
        """
        score_tiers = {
            "informational": 60,
            "suspicious": 80,
            "malicious": 100,
        }

        nested_score = indicator.get("score")
        if nested_score:
            value = nested_score.get("value")
            if value:
                return score_tiers.get(value.lower(), 50)

        return 50

    @staticmethod
    def _normalize_labels(raw_tags: list | None) -> list[str]:
        """Normalize and deduplicate indicator labels.

        Args:
            raw_tags: Raw tags payload.

        Returns:
            list[str]: Deduplicated string labels.
        """
        if not raw_tags:
            return []

        return list(set(raw_tags))

    @staticmethod
    def _resolve_observable_definition(ioc_type: str) -> tuple[str, str, str] | None:
        """Map IoC type to STIX type/path and OpenCTI observable type.

        Args:
            ioc_type: Input IoC type.

        Returns:
            tuple[str, str, str] | None: `(stix_type, stix_path,
            opencti_main_observable_type)` mapping.
        """
        mapping = {
            "ipv4": ("ipv4-addr", "value", "IPv4-Addr"),
            "ipv4-addr": ("ipv4-addr", "value", "IPv4-Addr"),
            "ipv6": ("ipv6-addr", "value", "IPv6-Addr"),
            "ipv6-addr": ("ipv6-addr", "value", "IPv6-Addr"),
            "domain": ("domain-name", "value", "Domain-Name"),
            "domain-name": ("domain-name", "value", "Domain-Name"),
            "hostname": ("domain-name", "value", "Domain-Name"),
            "url": ("url", "value", "Url"),
            "email": ("email-addr", "value", "Email-Addr"),
            "email-addr": ("email-addr", "value", "Email-Addr"),
            "md5": ("file", "hashes.MD5", "StixFile"),
            "sha1": ("file", "hashes.SHA-1", "StixFile"),
            "sha256": ("file", "hashes.SHA-256", "StixFile"),
            "file": ("file", "name", "StixFile"),
            "file-md5": ("file", "hashes.MD5", "StixFile"),
            "file-sha1": ("file", "hashes.SHA-1", "StixFile"),
            "file-sha256": ("file", "hashes.SHA-256", "StixFile"),
            "file-name": ("file", "name", "StixFile"),
            "asn": ("autonomous-system", "number", "Autonomous-System"),
            "autonomous-system": ("autonomous-system", "number", "Autonomous-System"),
            "extracted_config": ("text", "value", "Text"),
            "text": ("text", "value", "Text"),
        }
        return mapping.get(ioc_type.lower())

    @staticmethod
    def _build_pattern(stix_type: str, stix_path: str, ioc_value: str) -> str | None:
        """Build a STIX pattern for a given observable value.

        Args:
            stix_type: STIX cyber observable type.
            stix_path: STIX object path.
            ioc_value: IoC value.

        Returns:
            str | None: STIX pattern string or `None` if value is invalid.
        """
        object_path = stix_path.split(".")
        value: str | int = ioc_value

        if stix_type == "text":
            escaped = ioc_value.replace("\\", "\\\\").replace("'", "\\'")
            return f"[text:value = '{escaped}']"

        if stix_type == "autonomous-system" and stix_path == "number":
            value = ioc_value.replace("AS", "")
            if value.isdigit():
                value = int(value)
            else:
                return None

        object_path_expr = stix2.ObjectPath(stix_type, object_path)
        return str(
            stix2.ObservationExpression(
                stix2.EqualityComparisonExpression(object_path_expr, value)
            )
        )

    def _create_observable(
        self,
        stix_type: str,
        stix_path: str,
        ioc_value: str,
        labels: list[str],
        score: int,
    ):
        """Create observable object matching the resolved STIX type/path.

        Args:
            stix_type: STIX observable type.
            stix_path: STIX path used in indicator pattern.
            ioc_value: Observable value.
            labels: Labels to attach to observables when supported.
            score: OpenCTI score.

        Returns:
            Any | None: SDK observable object, else `None`.
        """
        common_properties = {
            "labels": labels,
            "author": self.author,
            "markings": [self.marking],
            "score": score,
        }

        if stix_type == "ipv4-addr":
            return IPV4Address(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "ipv6-addr":
            return IPV6Address(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "domain-name":
            if not is_domain(ioc_value):
                return None
            return DomainName(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "url":
            return URL(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "email-addr":
            return EmailAddress(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "autonomous-system":
            number = ioc_value.replace("AS", "")
            if number.isdigit():
                return AutonomousSystem(
                    number=int(number),
                    **common_properties,
                )
            return None
        if stix_type == "file":
            if stix_path == "name":
                return File(
                    name=ioc_value,
                    **common_properties,
                )
            if stix_path.startswith("hashes."):
                algorithm = stix_path.split(".")[1]
                hash_mapping = {
                    "MD5": HashAlgorithm.MD5,
                    "SHA-1": HashAlgorithm.SHA1,
                    "SHA-256": HashAlgorithm.SHA256,
                }
                hash_algorithm = hash_mapping.get(algorithm)
                if hash_algorithm is None:
                    return None
                return File(hashes={hash_algorithm: ioc_value}, **common_properties)
        if stix_type == "text":
            return Text(
                value=ioc_value,
                **common_properties,
            )

        return None

    @staticmethod
    def _normalize_attack_pattern_id(value: str | None) -> str | None:
        """Normalize a MITRE ATT&CK external ID.

        Args:
            value: Raw external ID value.

        Returns:
            str | None: Normalized technique ID (e.g. `T1059.001`) or `None`.
        """
        if not value:
            return None

        normalized_value = value.strip().upper()
        if not normalized_value:
            return None

        match = re.search(r"T\d{4}(?:\.\d{3})?", normalized_value)
        if match is None:
            return None

        return match.group(0)

    @staticmethod
    def _strip_html(value: str) -> str:
        """Remove HTML tags and decode entities from a string."""
        return html.unescape(re.sub(r"<[^>]+>", "", value)).strip()

    @staticmethod
    def _normalize_kill_chain_phase_name(value: str | None) -> str | None:
        """Normalize a tactic string into a kill-chain phase name."""
        if not value:
            return None

        normalized_value = value.strip().lower()
        if not normalized_value:
            return None

        normalized_value = re.sub(r"[^a-z0-9]+", "-", normalized_value)
        normalized_value = re.sub(r"-+", "-", normalized_value).strip("-")
        return normalized_value or None

    @classmethod
    def _extract_attack_patterns(cls, indicator: dict) -> list[dict]:
        """Extract and normalize MITRE ATT&CK attack patterns from indicator."""
        mitre_attack_ids = indicator.get("mitre_attack_ids")
        if not mitre_attack_ids:
            return []

        attack_patterns = []
        seen_entries: set[tuple[str, str]] = set()

        for entry in mitre_attack_ids:
            mitre_id = None
            name = None
            description = None
            tactic = None
            tactics = []

            for attack_id_key in [
                "id",
                "mitre_id",
                "attack_id",
                "technique_id",
                "external_id",
            ]:
                mitre_id = cls._normalize_attack_pattern_id(entry.get(attack_id_key))
                if mitre_id is not None:
                    break

            for name_key in ["name", "technique", "technique_name", "title"]:
                raw_name = entry.get(name_key)
                if raw_name and raw_name.strip():
                    name = raw_name.strip()
                    break

            raw_description = entry.get("description")
            if raw_description and raw_description.strip():
                description = raw_description.strip()

            raw_tactic = entry.get("tactic")
            if raw_tactic and raw_tactic.strip():
                tactic = raw_tactic.strip()

            raw_tactics = entry.get("tactics")
            if raw_tactics:
                for raw_t in raw_tactics:
                    if raw_t and raw_t.strip():
                        tactics.append(raw_t.strip())

            if mitre_id is None and (name is None or not name.strip()):
                continue

            attack_pattern_name = name or mitre_id

            dedupe_key = (mitre_id or "", attack_pattern_name)
            if dedupe_key in seen_entries:
                continue
            seen_entries.add(dedupe_key)

            attack_patterns.append(
                {
                    "mitre_id": mitre_id,
                    "name": attack_pattern_name,
                    "description": description,
                    "tactic": tactic,
                    "tactics": tactics,
                }
            )

        return attack_patterns

    def _build_attack_pattern_objects(
        self,
        indicator: dict,
        octi_indicator: Indicator,
        labels: list[str],
    ) -> list:
        """Create attack-pattern entities and indicates relationships."""
        octi_objects = []

        for attack_pattern_data in self._extract_attack_patterns(indicator):
            kill_chain_phases = None
            tactics = attack_pattern_data.get("tactics") or []
            if not tactics:
                single_tactic = attack_pattern_data.get("tactic")
                if single_tactic:
                    tactics = [single_tactic]

            if tactics:
                kill_chain_phases = []
                for tactic_name in tactics:
                    phase_name = self._normalize_kill_chain_phase_name(tactic_name)
                    if phase_name is not None:
                        kill_chain_phases.append(
                            KillChainPhase(
                                chain_name="mitre-attack", phase_name=phase_name
                            )
                        )
                if not kill_chain_phases:
                    kill_chain_phases = None

            attack_pattern = AttackPattern(
                name=attack_pattern_data["name"],
                description=attack_pattern_data.get("description"),
                labels=labels,
                mitre_id=attack_pattern_data.get("mitre_id"),
                kill_chain_phases=kill_chain_phases,
                author=self.author,
                markings=[self.marking],
            )
            octi_objects.append(attack_pattern)

            octi_objects.append(
                Relationship(
                    type=RelationshipType.INDICATES,
                    source=octi_indicator,
                    target=attack_pattern,
                    author=self.author,
                    markings=[self.marking],
                )
            )

        return octi_objects

    @staticmethod
    def _extract_sightings(indicator: dict) -> list[dict]:
        """Extract normalized sightings from indicator payload."""
        extracted_sightings = list(indicator.get("sightings", []))
        seen_keys: set[tuple[str, str, str]] = set()

        latest_sighting = indicator.get("latest_sighting")
        if latest_sighting:
            extracted_sightings.append(latest_sighting)

        normalized_sightings = []
        for sighting in extracted_sightings:
            source = sighting.get("source")
            sighted_at = sighting.get("sighted_at")
            sighting_id = sighting.get("id")

            if not source or not source.strip():
                continue
            if not sighted_at or not sighted_at.strip():
                continue

            dedupe_key = (
                str(sighting_id or ""),
                source.strip(),
                sighted_at.strip(),
            )
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            normalized_sightings.append(sighting)

        return normalized_sightings

    @staticmethod
    def _collect_sighting_tags(indicator: dict) -> list[str]:
        """Collect all tags from sightings and latest_sighting."""
        all_tags: list[str] = []

        for sighting in indicator.get("sightings", []):
            all_tags.extend(sighting.get("tags", []))

        latest_sighting = indicator.get("latest_sighting")
        if latest_sighting:
            all_tags.extend(latest_sighting.get("tags", []))

        return all_tags

    @staticmethod
    def _extract_entities_from_tags(indicator: dict) -> tuple[list[str], list[str]]:
        """Extract actor and malware names from sighting tags.

        Returns:
            tuple: (actor_names, malware_names) deduplicated lists.
        """
        actor_names: set[str] = set()
        malware_names: set[str] = set()

        for tag in IndicatorConverterToStix._collect_sighting_tags(indicator):
            if tag.startswith("actor:"):
                name = tag[len("actor:") :].strip()
                if name:
                    actor_names.add(name)
            elif tag.startswith("malware:"):
                name = tag[len("malware:") :].strip()
                if name:
                    malware_names.add(name)

        return actor_names, malware_names

    def _build_tag_entities_objects(
        self,
        indicator: dict,
        octi_indicator: Indicator,
    ) -> list:
        """Create IntrusionSet / Malware entities and indicates relationships from tags."""
        octi_objects = []
        actor_names, malware_names = self._extract_entities_from_tags(indicator)

        raw_malware_description = indicator.get("malware_description")
        malware_description = None
        if raw_malware_description and raw_malware_description.strip():
            malware_description = self._strip_html(raw_malware_description) or None

        for name in actor_names:
            intrusion_set = IntrusionSet(
                name=name,
                author=self.author,
                markings=[self.marking],
            )
            octi_objects.append(intrusion_set)
            octi_objects.append(
                Relationship(
                    type=RelationshipType.INDICATES,
                    source=octi_indicator,
                    target=intrusion_set,
                    author=self.author,
                    markings=[self.marking],
                )
            )

        for name in malware_names:
            malware = Malware(
                name=name,
                is_family=True,
                description=malware_description,
                author=self.author,
                markings=[self.marking],
            )
            octi_objects.append(malware)
            octi_objects.append(
                Relationship(
                    type=RelationshipType.INDICATES,
                    source=octi_indicator,
                    target=malware,
                    author=self.author,
                    markings=[self.marking],
                )
            )

        return octi_objects

    def _build_sighting_objects(
        self, indicator: dict, octi_indicator: Indicator
    ) -> list:
        """Create source identities and STIX sightings for indicator payload."""
        octi_objects = []

        for raw_sighting in self._extract_sightings(indicator):
            source = raw_sighting["source"]
            sighted_at = self._parse_datetime(raw_sighting["sighted_at"])
            if sighted_at is None:
                continue

            organization = Organization(
                name=source,
                author=self.author,
                markings=[self.marking],
            )
            octi_objects.append(organization)

            sighting_description = raw_sighting.get("description") or None

            sighting = Sighting(
                sighting_of=octi_indicator,
                where_sighted=[organization],
                first_seen=sighted_at,
                last_seen=sighted_at,
                count=1,
                description=sighting_description,
                author=self.author,
                markings=[self.marking],
            )
            octi_objects.append(sighting)

        return octi_objects

    @staticmethod
    def _extract_ignite_url(indicator: dict) -> str | None:
        """Extract the Flashpoint Ignite URL from platform_urls."""
        platform_urls = indicator.get("platform_urls")
        if not platform_urls:
            return None
        ignite = platform_urls.get("ignite")
        return ignite.strip() if ignite else None

    @staticmethod
    def _extract_related_iocs(indicator: dict) -> list[dict]:
        """Extract related IoCs from all sightings.

        Returns:
            list[dict]: Deduplicated related IoC entries with type and value.
        """
        all_related: list[dict] = []
        seen: set[tuple[str, str]] = set()

        sources = list(indicator.get("sightings", []))
        latest = indicator.get("latest_sighting")
        if latest:
            sources.append(latest)

        for sighting in sources:
            for related_ioc in sighting.get("related_iocs", []):
                ioc_type = related_ioc.get("type")
                ioc_value = related_ioc.get("value")
                if (
                    not ioc_type
                    or not ioc_type.strip()
                    or not ioc_value
                    or not ioc_value.strip()
                ):
                    continue
                key = (ioc_type.strip().lower(), ioc_value.strip())
                if key in seen:
                    continue
                seen.add(key)
                all_related.append(
                    {"type": ioc_type.strip(), "value": ioc_value.strip()}
                )

        return all_related

    def _build_related_iocs_objects(
        self, indicator: dict, octi_indicator: Indicator
    ) -> list:
        """Create indicators, observables and relationships for related_iocs."""
        octi_objects = []
        parent_value = indicator.get("value")

        for related_ioc in self._extract_related_iocs(indicator):
            ioc_type = related_ioc["type"]
            ioc_value = related_ioc["value"]

            if ioc_value == parent_value:
                continue

            obs_def = self._resolve_observable_definition(ioc_type)
            if obs_def is None:
                continue
            stix_type, stix_path, opencti_type = obs_def

            pattern = self._build_pattern(stix_type, stix_path, ioc_value)
            if pattern is None:
                continue

            related_indicator = Indicator(
                name=ioc_value,
                pattern_type="stix",
                pattern=pattern,
                valid_from=octi_indicator.valid_from,
                author=self.author,
                markings=[self.marking],
                main_observable_type=opencti_type,
            )
            octi_objects.append(related_indicator)

            observable = self._create_observable(
                stix_type=stix_type,
                stix_path=stix_path,
                ioc_value=ioc_value,
                labels=[],
                score=50,
            )
            if observable is not None:
                octi_objects.append(observable)
                octi_objects.append(
                    Relationship(
                        type=RelationshipType.BASED_ON,
                        source=related_indicator,
                        target=observable,
                        author=self.author,
                        markings=[self.marking],
                    )
                )

            octi_objects.append(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=octi_indicator,
                    target=related_indicator,
                    author=self.author,
                    markings=[self.marking],
                )
            )

        return octi_objects

    def _build_external_references(self, indicator: dict) -> list[ExternalReference]:
        """Build external references from indicator payload."""
        external_references = []

        ignite_url = self._extract_ignite_url(indicator)
        if ignite_url:
            external_references.append(
                ExternalReference(
                    source_name="Flashpoint Ignite",
                    url=ignite_url,
                )
            )

        return external_references

    def _build_enrichment_objects(
        self, indicator: dict, octi_indicator: Indicator, labels: list[str]
    ) -> list:
        """Build attack patterns, sightings, tag entities and related IoCs."""
        octi_objects = []
        octi_objects.extend(
            self._build_attack_pattern_objects(
                indicator=indicator,
                octi_indicator=octi_indicator,
                labels=labels,
            )
        )
        # Sightings are disabled: the sighting sources from Flashpoint
        # (e.g. "flashpoint_extraction") are not real organizations.
        # Uncomment to enable later if needed.
        # octi_objects.extend(
        #     self._build_sighting_objects(
        #         indicator=indicator,
        #         octi_indicator=octi_indicator,
        #     )
        # )
        octi_objects.extend(
            self._build_tag_entities_objects(
                indicator=indicator,
                octi_indicator=octi_indicator,
            )
        )
        octi_objects.extend(
            self._build_related_iocs_objects(
                indicator=indicator,
                octi_indicator=octi_indicator,
            )
        )
        return octi_objects

    def convert_indicator_to_stix(self, indicator: dict) -> list:
        """Convert a Flashpoint indicator payload into STIX objects.

        Args:
            indicator: Raw Flashpoint indicator payload.

        Returns:
            list: Generated STIX objects. Returns an empty list when conversion
            is not possible.
        """
        ioc_type = self._extract_ioc_type(indicator)
        if ioc_type is None:
            return []

        forced_file_stix_path = None
        if ioc_type.lower() == "file":
            file_ioc = self._extract_file_ioc(indicator)
            if file_ioc is not None:
                forced_file_stix_path, ioc_value = file_ioc
            else:
                ioc_value = self._extract_ioc_value(indicator, ioc_type)
        else:
            ioc_value = self._extract_ioc_value(indicator, ioc_type)

        if ioc_value is None:
            return []

        observable_definition = self._resolve_observable_definition(ioc_type)
        if observable_definition is None:
            return []

        stix_type, stix_path, opencti_main_observable_type = observable_definition
        if stix_type == "domain-name" and not is_domain(ioc_value):
            self.helper.connector_logger.warning(
                "Skipping indicator with invalid domain value",
                {"ioc_value": ioc_value},
            )
            return []
        if stix_type == "file" and forced_file_stix_path:
            stix_path = forced_file_stix_path
        pattern = self._build_pattern(stix_type, stix_path, ioc_value)
        if pattern is None:
            return []

        created = self._parse_datetime(indicator.get("created_at"))
        modified = self._parse_datetime(indicator.get("modified_at"))
        first_seen = self._parse_datetime(indicator.get("first_seen_at"))
        last_seen = self._parse_datetime(indicator.get("last_seen_at"))
        valid_from = (
            first_seen or created or modified or last_seen or datetime.now(timezone.utc)
        )

        description = indicator.get("description") or ""
        labels = self._normalize_labels(self._collect_sighting_tags(indicator))
        score = self._resolve_score(indicator)

        octi_indicator = Indicator(
            name=ioc_value,
            description=description,
            pattern_type="stix",
            pattern=pattern,
            valid_from=valid_from,
            created=created,
            labels=labels,
            author=self.author,
            markings=[self.marking],
            external_references=self._build_external_references(indicator),
            main_observable_type=opencti_main_observable_type,
            score=score,
        )

        octi_objects = [octi_indicator]

        observable = self._create_observable(
            stix_type=stix_type,
            stix_path=stix_path,
            ioc_value=ioc_value,
            labels=labels,
            score=score,
        )
        if observable is not None:
            octi_objects.append(observable)
            octi_objects.append(
                Relationship(
                    type=RelationshipType.BASED_ON,
                    source=octi_indicator,
                    target=observable,
                    author=self.author,
                    markings=[self.marking],
                )
            )

        octi_objects.extend(
            self._build_enrichment_objects(indicator, octi_indicator, labels)
        )

        return octi_objects
