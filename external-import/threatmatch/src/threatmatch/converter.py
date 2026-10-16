import ipaddress
import re
from datetime import UTC, datetime
from typing import Any, Generator, Literal
from urllib.parse import urlparse, urlsplit

import pycti
import stix2
from bs4 import BeautifulSoup
from markdownify import markdownify
from pycti import OpenCTIConnectorHelper


class ConnectorWarning(Exception):
    """Custom warning for connector operations."""


class InvalidTlpLevelError(Exception):
    """Custom error for invalid TLP levels."""


class Converter:
    """
    Base class for all converters.

    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author_name: str,
        author_description: str,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
        threat_actor_to_intrusion_set: bool,
    ) -> None:
        self.helper = helper
        self.author = self._create_author(
            name=author_name, description=author_description
        )
        self.tlp_marking = self._create_tlp_marking(tlp_level=tlp_level)
        self.threat_actor_to_intrusion_set = threat_actor_to_intrusion_set

    @staticmethod
    def _create_author(name: str, description: str) -> stix2.Identity:
        return stix2.Identity(
            id=pycti.Identity.generate_id(name=name, identity_class="organization"),
            name=name,
            identity_class="organization",
            description=description,
        )

    @staticmethod
    def _create_tlp_marking(
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ) -> stix2.MarkingDefinition:
        match tlp_level:
            case "white" | "clear":
                return stix2.TLP_WHITE
            case "green":
                return stix2.TLP_GREEN
            case "amber":
                return stix2.TLP_AMBER
            case "amber+strict":
                return stix2.MarkingDefinition(
                    id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                    definition_type="statement",
                    definition={"statement": "custom"},
                    custom_properties={
                        "x_opencti_definition_type": "TLP",
                        "x_opencti_definition": "TLP:AMBER+STRICT",
                    },
                )
            case "red":
                return stix2.TLP_RED
            case _:  # default
                raise InvalidTlpLevelError(f"Invalid TLP level: {tlp_level}")

    def _handle_author(self, stix_object: dict[str, Any]) -> None:
        if "created_by_ref" not in stix_object:
            stix_object["created_by_ref"] = self.author.id

    def _handle_object_marking_refs(self, stix_object: dict[str, Any]) -> None:
        if "object_marking_refs" not in stix_object:
            stix_object["object_marking_refs"] = [self.tlp_marking.id]

    def _handle_threat_actor_as_intrusion_set(
        self, stix_object: dict[str, Any]
    ) -> None:
        if self.threat_actor_to_intrusion_set:
            if stix_object["type"] == "threat-actor":
                stix_object["type"] = "intrusion-set"
                stix_object["id"] = stix_object["id"].replace(
                    "threat-actor", "intrusion-set"
                )
            if stix_object["type"] == "relationship":
                stix_object["source_ref"] = stix_object["source_ref"].replace(
                    "threat-actor", "intrusion-set"
                )
                stix_object["target_ref"] = stix_object["target_ref"].replace(
                    "threat-actor", "intrusion-set"
                )

    def _handle_relationship(self, stix_object: dict[str, Any]) -> None:
        if stix_object.get("relationship_type") in {
            "associated_content",
            "associated-content",
        }:
            stix_object["relationship_type"] = "related-to"
            if stix_object.get("source_ref") and stix_object.get("target_ref"):
                stix_object["id"] = pycti.StixCoreRelationship.generate_id(
                    "related-to",
                    stix_object["source_ref"],
                    stix_object["target_ref"],
                )

    # ThreatMatch profiles reference their IOCs through `object_refs`, which OpenCTI
    # only supports on containers. They are converted into `indicates` relationships
    # so the indicators stay linked to the profile entity.
    INDICATABLE_TYPES = frozenset(
        {
            "threat-actor",
            "intrusion-set",
            "campaign",
            "malware",
            "tool",
            "attack-pattern",
        }
    )

    # ThreatMatch STIX descriptions append a plain-text summary footer of the form:
    # "Target geography: <...>. Language: <...>. Sectors: <...>."
    # while dumping all geography and language tags into the flat `labels` list.
    _DESCRIPTION_FOOTER_RE = re.compile(
        r"(?:(?<=</p>)|(?<=</ul>)|(?<=</ol>)|(?<=</table>)|^)\s*"
        r"(?P<footer>(?:(?:Target geography|Language|Sectors):\s*.+?)+)\s*$",
        re.DOTALL,
    )
    _FOOTER_FIELD_RE = re.compile(
        r"\s*(?P<key>Target geography|Language|Sectors):\s*"
        r"(?P<value>.+?)(?=\.\s+(?:Target geography|Language|Sectors):|\.?$)",
        re.DOTALL,
    )
    _COMPOUND_SECTORS = (
        "Aerospace, defence & security",
        "Energy, utilities & mining",
    )
    _IGNORED_LABELS = frozenset({"unknown", "global", "all"})
    _REGION_NAMES = frozenset(
        {
            "africa",
            "americas",
            "antarctica",
            "asia",
            "asia pacific",
            "australia-new-zealand",
            "caribbean",
            "central america",
            "central asia",
            "eastern africa",
            "eastern asia",
            "eastern europe",
            "europe",
            "latin america",
            "latin-america-caribbean",
            "melanesia",
            "micronesia",
            "middle africa",
            "middle east",
            "north africa",
            "north america",
            "northern africa",
            "northern america",
            "northern europe",
            "oceania",
            "polynesia",
            "south america",
            "south-eastern asia",
            "southeast asia",
            "southern africa",
            "southern asia",
            "southern europe",
            "sub-saharan africa",
            "western africa",
            "western asia",
            "western europe",
        }
    )

    def _create_object_ref_relationships(
        self, stix_object: dict[str, Any]
    ) -> list[dict[str, Any]]:
        if stix_object.get("type") not in self.INDICATABLE_TYPES:
            return []
        object_refs = stix_object.get("object_refs")
        if not isinstance(object_refs, list):
            return []

        target_ref = stix_object.get("id")
        if not target_ref:
            return []

        relationship_created = stix_object.get(
            "created", datetime.now(tz=UTC).isoformat(timespec="seconds")
        )
        relationship_modified = stix_object.get("modified", relationship_created)

        relationships = []
        for source_ref in object_refs:
            if not isinstance(source_ref, str) or not source_ref.startswith(
                "indicator--"
            ):
                continue
            relationships.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": pycti.StixCoreRelationship.generate_id(
                        "indicates", source_ref, target_ref
                    ),
                    "relationship_type": "indicates",
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                    "created": relationship_created,
                    "modified": relationship_modified,
                }
            )
        return relationships

    def _handle_object_refs(self, stix_object: dict[str, Any]) -> list[dict[str, Any]]:
        relationships = self._create_object_ref_relationships(stix_object)
        if "object_refs" in stix_object and stix_object["type"] not in [
            "report",
            "note",
            "opinion",
            "observed-data",
        ]:
            del stix_object["object_refs"]
        return relationships

    @classmethod
    def _split_sector_values(cls, raw_value: str) -> list[str]:
        text = raw_value.strip().rstrip(".")
        placeholders: dict[str, str] = {}
        for index, compound in enumerate(cls._COMPOUND_SECTORS):
            token = f"__SECTOR_{index}__"
            text = re.sub(re.escape(compound), token, text, flags=re.IGNORECASE)
            placeholders[token] = compound

        sectors: list[str] = []
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            for token, compound in placeholders.items():
                part = part.replace(token, compound)
            sectors.append(part)
        return sectors

    def _extract_description_footer_targets(
        self, stix_object: dict[str, Any]
    ) -> list[dict[str, Any]]:
        description = stix_object.get("description")
        if not isinstance(description, str) or not description:
            return []

        footer_match = self._DESCRIPTION_FOOTER_RE.search(description)
        if not footer_match:
            return []

        footer = footer_match.group("footer")
        geographies: list[str] = []
        languages: list[str] = []
        sectors: list[str] = []

        for field_match in self._FOOTER_FIELD_RE.finditer(footer):
            key = field_match.group("key")
            raw_value = field_match.group("value").strip().rstrip(".")
            if key == "Sectors":
                sectors.extend(self._split_sector_values(raw_value))
            else:
                values = [item.strip() for item in raw_value.split(",") if item.strip()]
                if key == "Target geography":
                    geographies.extend(values)
                elif key == "Language":
                    languages.extend(values)

        labels = stix_object.get("labels")
        if isinstance(labels, list):
            labels_to_strip = {
                value.lower() for value in (*geographies, *languages, *sectors)
            } | self._IGNORED_LABELS
            stix_object["labels"] = [
                label
                for label in labels
                if not isinstance(label, str)
                or label.strip().lower() not in labels_to_strip
            ]

        source_id = stix_object.get("id")
        if not source_id or stix_object.get("type") not in self.TTP_USER_TYPES:
            return []

        relationship_created = stix_object.get(
            "created", datetime.now(tz=UTC).isoformat(timespec="seconds")
        )
        relationship_modified = stix_object.get("modified", relationship_created)

        created_objects: list[dict[str, Any]] = []
        seen_locations: set[tuple[str, str]] = set()
        for geography in geographies:
            normalized = geography.strip()
            if not normalized or normalized.lower() in self._IGNORED_LABELS:
                continue
            is_region = normalized.lower() in self._REGION_NAMES
            location_type = "Region" if is_region else "Country"
            dedup_key = (normalized.lower(), location_type)
            if dedup_key in seen_locations:
                continue
            seen_locations.add(dedup_key)

            location_id = pycti.Location.generate_id(
                name=normalized, x_opencti_location_type=location_type
            )
            location_object: dict[str, Any] = {
                "type": "location",
                "spec_version": "2.1",
                "id": location_id,
                "name": normalized,
                "x_opencti_location_type": location_type,
            }
            if is_region:
                location_object["region"] = normalized
            else:
                location_object["country"] = normalized
            created_objects.append(location_object)
            created_objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": pycti.StixCoreRelationship.generate_id(
                        "targets", source_id, location_id
                    ),
                    "relationship_type": "targets",
                    "source_ref": source_id,
                    "target_ref": location_id,
                    "created": relationship_created,
                    "modified": relationship_modified,
                }
            )

        seen_sectors: set[str] = set()
        for sector in sectors:
            normalized = sector.strip()
            if not normalized or normalized.lower() in self._IGNORED_LABELS:
                continue
            dedup_key = normalized.lower()
            if dedup_key in seen_sectors:
                continue
            seen_sectors.add(dedup_key)

            sector_id = pycti.Identity.generate_id(
                name=normalized, identity_class="class"
            )
            created_objects.append(
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": sector_id,
                    "name": normalized,
                    "identity_class": "class",
                }
            )
            created_objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": pycti.StixCoreRelationship.generate_id(
                        "targets", source_id, sector_id
                    ),
                    "relationship_type": "targets",
                    "source_ref": source_id,
                    "target_ref": sector_id,
                    "created": relationship_created,
                    "modified": relationship_modified,
                }
            )

        return created_objects

    def _handle_description(self, stix_object: dict[str, Any]) -> list[dict[str, Any]]:
        description = stix_object.get("description")
        if not description:
            return []

        related_objects = self._extract_description_footer_targets(stix_object)
        soup = BeautifulSoup(description, "html.parser")
        stix_object["description"] = markdownify(
            str(soup), heading_style="ATX", bullets="-"
        ).strip()
        self._handle_external_references(stix_object, soup)
        return related_objects

    # ATT&CK technique labels in TM STIX look like "T1234 - Technique Name" or
    # "T1234.001 - Sub-technique Name". They are converted into attack-pattern
    # entities linked with `uses` (or `indicates` for indicators) so they
    # appear in OpenCTI's TTPs tab rather than flooding the label taxonomy.
    _ATTCK_LABEL_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)\s*-\s*(.+)$")
    _SIMPLE_INDICATOR_PATTERN_RE = re.compile(
        r"""^\[\s*(?P<field>[a-z][a-z0-9-]*:(?:[A-Za-z_][A-Za-z0-9_-]*|'[A-Za-z0-9_-]+')"""
        r"""(?:\.(?:[A-Za-z_][A-Za-z0-9_-]*|'[A-Za-z0-9_-]+'))*)\s*=\s*'(?P<value>[^'\\]*)'\s*\]$"""
    )
    TTP_USER_TYPES = frozenset(
        {"threat-actor", "intrusion-set", "malware", "tool", "campaign"}
    )
    # Indicators relate to ATT&CK techniques via `indicates` rather than `uses`.
    TTP_INDICATOR_TYPES = frozenset({"indicator"})

    def _create_attack_patterns(
        self, stix_object: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Convert ATT&CK technique labels into attack-patterns + relationships."""
        stix_object_type = stix_object.get("type")
        labels = stix_object.get("labels")
        if (
            stix_object_type not in self.TTP_USER_TYPES | self.TTP_INDICATOR_TYPES
            or not isinstance(labels, list)
            or not stix_object.get("id")
        ):
            return []

        ttp_relationship_type = (
            "indicates" if stix_object_type in self.TTP_INDICATOR_TYPES else "uses"
        )

        created_objects = []
        seen_techniques = set()
        remaining_labels = []
        for label in labels:
            match = (
                self._ATTCK_LABEL_RE.match(label.strip())
                if isinstance(label, str)
                else None
            )
            if not match:
                remaining_labels.append(label)
                continue
            technique_id, technique_name = match.group(1), match.group(2).strip()
            if technique_id in seen_techniques:
                continue
            seen_techniques.add(technique_id)

            # The ID is derived from x_mitre_id so it deduplicates with the
            # attack-patterns imported by the MITRE ATT&CK connector.
            attack_pattern_id = pycti.AttackPattern.generate_id(
                name=technique_name, x_mitre_id=technique_id
            )
            url_technique_id = technique_id.replace(".", "/")
            created_objects.append(
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": attack_pattern_id,
                    "name": technique_name,
                    "x_mitre_id": technique_id,
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": technique_id,
                            "url": f"https://attack.mitre.org/techniques/{url_technique_id}",
                        }
                    ],
                }
            )
            created_objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": pycti.StixCoreRelationship.generate_id(
                        ttp_relationship_type, stix_object["id"], attack_pattern_id
                    ),
                    "relationship_type": ttp_relationship_type,
                    "source_ref": stix_object["id"],
                    "target_ref": attack_pattern_id,
                    "created": stix_object.get(
                        "created", datetime.now(tz=UTC).isoformat(timespec="seconds")
                    ),
                    "modified": stix_object.get(
                        "modified",
                        stix_object.get(
                            "created",
                            datetime.now(tz=UTC).isoformat(timespec="seconds"),
                        ),
                    ),
                }
            )

        stix_object["labels"] = remaining_labels
        return created_objects

    def _handle_names_and_aliases(self, stix_object: dict[str, Any]) -> None:
        if isinstance(stix_object.get("name"), str):
            stix_object["name"] = stix_object["name"].strip()

        aliases = stix_object.get("aliases")
        if not isinstance(aliases, list):
            return
        name = stix_object.get("name")
        cleaned_aliases = []
        for alias in aliases:
            if not isinstance(alias, str):
                continue
            alias = alias.strip()
            if alias and alias != name:
                cleaned_aliases.append(alias)
        stix_object["aliases"] = list(dict.fromkeys(cleaned_aliases))

    def _handle_indicator_name(self, stix_object: dict[str, Any]) -> None:
        if stix_object.get("type") != "indicator":
            return
        if stix_object.get("pattern_type") != "stix":
            return

        pattern = stix_object.get("pattern")
        if not isinstance(pattern, str):
            return
        match = self._SIMPLE_INDICATOR_PATTERN_RE.fullmatch(pattern)
        if not match or not match.group("value"):
            return

        indicator_value = match.group("value")
        source_name = stix_object.get("name")
        source_name = source_name.strip() if isinstance(source_name, str) else ""
        description = stix_object.get("description")
        meaningful_description = (
            isinstance(description, str)
            and bool(description.strip())
            and description.strip() != indicator_value
        )
        if (
            source_name
            and source_name != indicator_value
            and not meaningful_description
        ):
            stix_object["description"] = source_name
        elif (
            source_name == indicator_value
            and isinstance(description, str)
            and description.strip() == indicator_value
        ):
            stix_object.pop("description")
        stix_object["name"] = indicator_value

    def create_observable(self, indicator: dict[str, Any]) -> dict[str, Any] | None:
        if (
            indicator.get("type") != "indicator"
            or indicator.get("pattern_type") != "stix"
        ):
            return None
        pattern = indicator.get("pattern")
        match = (
            self._SIMPLE_INDICATOR_PATTERN_RE.fullmatch(pattern)
            if isinstance(pattern, str)
            else None
        )
        if not match:
            return None

        field, value = match.group("field"), match.group("value")
        if not value:
            return None

        metadata = {
            "object_marking_refs": indicator.get("object_marking_refs", []),
            "custom_properties": {
                "x_opencti_created_by_ref": indicator.get(
                    "created_by_ref", self.author.id
                )
            },
        }
        if field == "file:hashes.'SHA-256'" and re.fullmatch(r"[0-9a-fA-F]{64}", value):
            observable = stix2.File(hashes={"SHA-256": value}, **metadata)
        elif field == "url:value":
            try:
                parsed = urlsplit(value)
                hostname = parsed.hostname
                parsed.port
            except ValueError:
                return None
            if (
                parsed.scheme not in {"http", "https"}
                or not hostname
                or parsed.username
                or any(character.isspace() for character in value)
            ):
                return None
            observable = stix2.URL(value=value, **metadata)
        elif field == "email-addr:value":
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
                return None
            observable = stix2.EmailAddress(value=value, **metadata)
        elif field == "domain-name:value":
            labels = value.split(".")
            if (
                len(value) > 253
                or len(labels) < 2
                or any(
                    not re.fullmatch(
                        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label
                    )
                    for label in labels
                )
            ):
                return None
            observable = stix2.DomainName(value=value, **metadata)
        elif field in {"ipv4-addr:value", "ipv6-addr:value"}:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return None
            if field == "ipv4-addr:value" and isinstance(
                address, ipaddress.IPv4Address
            ):
                observable = stix2.IPv4Address(value=value, **metadata)
            elif field == "ipv6-addr:value" and isinstance(
                address, ipaddress.IPv6Address
            ):
                observable = stix2.IPv6Address(value=value, **metadata)
            else:
                return None
        else:
            return None

        return dict(observable)

    def _handle_goals_labels(self, stix_object: dict[str, Any]) -> None:
        """Remove labels only when they exactly duplicate structured goals."""
        labels = stix_object.get("labels")
        if not isinstance(labels, list):
            return
        goals = set(stix_object.get("goals") or [])
        stix_object["labels"] = [label for label in labels if label not in goals]

    def _handle_labels(self, stix_object: dict[str, Any]) -> None:
        labels = stix_object.get("labels")
        if not isinstance(labels, list):
            return
        stix_object["labels"] = list(
            dict.fromkeys(
                label.strip()
                for label in labels
                if isinstance(label, str)
                and label.strip()
                and label.strip().lower() not in self._IGNORED_LABELS
            )
        )

    def _handle_external_references(
        self, stix_object: dict[str, Any], soup: BeautifulSoup
    ) -> None:
        external_references = stix_object.get("external_references", [])
        existing_urls = {
            external_reference.get("url")
            for external_reference in external_references
            if isinstance(external_reference, dict)
        }
        for link in soup.find_all("a", href=True):
            url = link.get("href", "").strip()
            if not url or url in existing_urls:
                continue
            hostname = urlparse(url).hostname
            source_name = hostname if hostname else "ThreatMatch"
            external_references.append({"source_name": source_name, "url": url})
            existing_urls.add(url)
        if external_references:
            stix_object["external_references"] = external_references

    def _inherit_source_metadata(
        self, source_object: dict[str, Any], derived_object: dict[str, Any]
    ) -> None:
        if "created_by_ref" in source_object and "created_by_ref" not in derived_object:
            derived_object["created_by_ref"] = source_object["created_by_ref"]
        if (
            "object_marking_refs" in source_object
            and "object_marking_refs" not in derived_object
        ):
            derived_object["object_marking_refs"] = source_object["object_marking_refs"]

    def process(
        self, stix_object: dict[str, Any]
    ) -> Generator[dict[str, Any], None, None]:
        try:
            if "error" in stix_object:
                raise ConnectorWarning()
            self._handle_author(stix_object)
            self._handle_object_marking_refs(stix_object)
            self._handle_threat_actor_as_intrusion_set(stix_object)
            self._handle_relationship(stix_object)
            related_objects = self._handle_object_refs(stix_object)
            self._handle_indicator_name(stix_object)
            related_objects += self._handle_description(stix_object)
            self._handle_names_and_aliases(stix_object)
            related_objects += self._create_attack_patterns(stix_object)
            self._handle_goals_labels(stix_object)
            self._handle_labels(stix_object)
            yield stix_object
            for related_object in related_objects:
                self._inherit_source_metadata(stix_object, related_object)
                self._handle_author(related_object)
                self._handle_object_marking_refs(related_object)
                self._handle_threat_actor_as_intrusion_set(related_object)
                self._handle_relationship(related_object)
                yield related_object
        except Exception as e:
            self.helper.connector_logger.warning(
                "An error occurred while processing an entity, skipping...",
                {"error": str(e), "stix_object": stix_object},
            )
