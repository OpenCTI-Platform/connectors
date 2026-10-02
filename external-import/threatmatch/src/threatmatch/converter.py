import re
from datetime import UTC, datetime
from typing import Any, Generator, Literal
from urllib.parse import urlparse

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

    def _handle_description(self, stix_object: dict[str, Any]) -> None:
        description = stix_object.get("description")
        if not description:
            return

        soup = BeautifulSoup(description, "html.parser")
        stix_object["description"] = markdownify(
            str(soup), heading_style="ATX", bullets="-"
        ).strip()
        self._handle_external_references(stix_object, soup)

    # ATT&CK technique labels in TM STIX look like "T1234 - Technique Name" or
    # "T1234.001 - Sub-technique Name". They are converted into attack-pattern
    # entities linked with `uses` (or `indicates` for indicators) so they
    # appear in OpenCTI's TTPs tab rather than flooding the label taxonomy.
    _ATTCK_LABEL_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)\s*-\s*(.+)$")
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
                if isinstance(label, str) and label.strip()
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
            self._handle_description(stix_object)
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
