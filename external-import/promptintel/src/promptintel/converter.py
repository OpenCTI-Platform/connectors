import re
from datetime import datetime, timezone

import stix2
from pycti import (
    CustomObservableAIPrompt,
    Identity,
    Indicator,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    StixSightingRelationship,
)

from .settings import ConnectorSettings

SEVERITY_SCORE_MAP = {
    "critical": 85,
    "high": 65,
    "medium": 45,
    "low": 25,
}

# Regex for a single capitalized name part: "Marco", "Jean-Pierre", "O'Brien"
_NAME_PART_RE = re.compile(r"^[A-Z][a-zA-Z'-]{1,30}$")

# Lowercase particles allowed between first and last name
_NAME_PARTICLES = frozenset(
    {"de", "del", "della", "di", "du", "van", "von", "le", "la", "el", "al", "bin"}
)


def _looks_like_individual(name: str) -> bool:
    """Return True only when *name* very clearly looks like a person's name.

    The check is deliberately restrictive: when in doubt it returns False so
    that the caller falls back to ``identity_class="organization"``.

    Accepted patterns (all words must be purely alphabetic / hyphen / apostrophe):
      - ``Firstname Lastname``  (2 capitalized words)
      - ``Firstname particle Lastname``  (3 words, middle is a known particle)
      - ``Firstname Middle Lastname``  (3 capitalized words)
    """
    parts = name.split()
    if len(parts) == 2:
        return all(_NAME_PART_RE.match(p) for p in parts)
    if len(parts) == 3:
        first_ok = _NAME_PART_RE.match(parts[0]) is not None
        last_ok = _NAME_PART_RE.match(parts[2]) is not None
        middle_ok = parts[1].lower() in _NAME_PARTICLES or (
            _NAME_PART_RE.match(parts[1]) is not None
        )
        return first_ok and middle_ok and last_ok
    return False


class PromptIntelConverter:
    """Converts PromptIntel API data into STIX 2.1 objects."""

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.config = config
        self.promptintel_identity = self._create_promptintel_identity()
        self.tlp_marking = self._create_tlp_marking(
            config.promptintel.tlp_level.lower()
        )
        self._author_cache: dict[str, stix2.Identity] = {}

    @staticmethod
    def _create_promptintel_identity() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id("PromptIntel", "organization"),
            name="PromptIntel",
            identity_class="organization",
            description=(
                "PromptIntel - A collaborative threat intelligence platform for "
                "tracking and defending against adversarial AI prompts. Indicators "
                "of Prompt Compromise (IoPC) registry."
            ),
            external_references=[
                stix2.ExternalReference(
                    source_name="PromptIntel",
                    url="https://promptintel.novahunting.ai",
                    description="PromptIntel platform",
                )
            ],
        )

    @staticmethod
    def _create_tlp_marking(level: str) -> stix2.MarkingDefinition:
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping.get(level, stix2.TLP_WHITE)

    def _get_or_create_author(self, author_name: str) -> stix2.Identity:
        """Get a cached author Identity or create a new one.

        Uses strict pattern matching to decide ``individual`` vs
        ``organization``.  Only names that clearly look like
        "Firstname Lastname" are classified as individuals; everything
        else defaults to organization.
        """
        if author_name in self._author_cache:
            return self._author_cache[author_name]
        identity_class = (
            "individual" if _looks_like_individual(author_name) else "organization"
        )
        identity = stix2.Identity(
            id=Identity.generate_id(author_name, identity_class),
            name=author_name,
            identity_class=identity_class,
            created_by_ref=self.promptintel_identity.id,
        )
        self._author_cache[author_name] = identity
        return identity

    @staticmethod
    def _calculate_score(severity: str | None, average_score: float | None) -> int:
        """Compute a 0-100 score from severity level and community rating."""
        base = SEVERITY_SCORE_MAP.get((severity or "").lower(), 35)
        bonus = int((average_score or 0) * 3)
        return min(100, base + bonus)

    @staticmethod
    def _escape_stix_pattern_value(value: str) -> str:
        """Escape a string for use inside a STIX pattern single-quoted literal."""
        return value.replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        """Parse an ISO-8601 timestamp string into a timezone-aware datetime.

        The PromptIntel API returns timestamps with the ``+00:00`` suffix which
        the stix2 library cannot parse directly.  Converting to a proper
        ``datetime`` object avoids that limitation.
        """
        if not value:
            return None
        return datetime.fromisoformat(value).astimezone(timezone.utc)

    def _build_external_references(
        self, reference_urls: list[str] | None, prompt_id: str
    ) -> list[stix2.ExternalReference]:
        refs = [
            stix2.ExternalReference(
                source_name="PromptIntel",
                url=f"https://promptintel.novahunting.ai/prompt/{prompt_id}",
                description="PromptIntel prompt page",
            )
        ]
        for url in reference_urls or []:
            refs.append(
                stix2.ExternalReference(
                    source_name="PromptIntel Reference",
                    url=url,
                )
            )
        return refs

    def convert_prompt(self, prompt_data: dict) -> list:
        """Convert a single PromptIntel prompt into a list of STIX objects.

        For each prompt this creates:
        - Author Identity (individual)
        - AI-Prompt observable (SCO)
        - Indicator with pattern_type "stix" (SDO)
        - Relationship: indicator --based-on--> observable
        - [If nova_rule] Indicator with pattern_type "nova"
        - [If nova_rule] Sighting of nova indicator at PromptIntel
        """
        objects: list = []

        author_name = prompt_data.get("author") or "Unknown"
        author_identity = self._get_or_create_author(author_name)
        objects.append(author_identity)

        score = self._calculate_score(
            prompt_data.get("severity"),
            prompt_data.get("average_score", 0),
        )

        labels = []
        for cat in prompt_data.get("categories") or []:
            labels.append(cat)
        for threat in prompt_data.get("threats") or []:
            labels.append(threat)
        for tag in prompt_data.get("tags") or []:
            labels.append(tag)

        ext_refs = self._build_external_references(
            prompt_data.get("reference_urls"),
            prompt_data.get("id", ""),
        )
        ext_refs_dicts = [
            {"source_name": r.source_name, "url": r.url}
            | (
                {"description": r.description}
                if hasattr(r, "description") and r.description
                else {}
            )
            for r in ext_refs
        ]

        title = prompt_data.get("title", "")
        impact_desc = prompt_data.get("impact_description", "")
        observable_desc = impact_desc if impact_desc else title
        indicator_desc = impact_desc if impact_desc else ""
        created_at = self._parse_datetime(prompt_data.get("created_at"))
        prompt_text = prompt_data.get("prompt", "")

        # --- AI-Prompt Observable (SCO) ---
        observable = CustomObservableAIPrompt(
            value=prompt_text,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_description": observable_desc,
                "x_opencti_labels": labels,
                "x_opencti_external_references": ext_refs_dicts,
                "created_by_ref": author_identity.id,
            },
        )
        objects.append(observable)

        # --- STIX Indicator (SDO) ---
        escaped_value = self._escape_stix_pattern_value(prompt_text)
        stix_pattern = f"[ai-prompt:value = '{escaped_value}']"

        indicator = stix2.Indicator(
            id=Indicator.generate_id(stix_pattern),
            name=title,
            description=indicator_desc,
            pattern=stix_pattern,
            pattern_type="stix",
            valid_from=created_at,
            labels=labels,
            created_by_ref=author_identity.id,
            external_references=ext_refs,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_main_observable_type": "AI-Prompt",
            },
            allow_custom=True,
        )
        objects.append(indicator)

        # --- Relationship: indicator --based-on--> observable ---
        rel_based_on = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on", indicator.id, observable.id
            ),
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=observable.id,
            created_by_ref=author_identity.id,
            object_marking_refs=[self.tlp_marking.id],
            allow_custom=True,
        )
        objects.append(rel_based_on)

        # --- Nova Rule handling ---
        nova_rule = prompt_data.get("nova_rule")
        if nova_rule:
            nova_indicator = stix2.Indicator(
                id=Indicator.generate_id(nova_rule),
                name=f"{title} (Nova Rule)",
                description=indicator_desc,
                pattern=nova_rule,
                pattern_type="nova",
                valid_from=created_at,
                labels=labels,
                created_by_ref=author_identity.id,
                external_references=ext_refs,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_score": score,
                    "x_opencti_main_observable_type": "AI-Prompt",
                },
                allow_custom=True,
            )
            objects.append(nova_indicator)

            sighting = stix2.Sighting(
                id=StixSightingRelationship.generate_id(
                    nova_indicator.id,
                    self.promptintel_identity.id,
                    created_at,
                    created_at,
                ),
                sighting_of_ref=nova_indicator.id,
                where_sighted_refs=[self.promptintel_identity.id],
                first_seen=created_at,
                last_seen=created_at,
                created_by_ref=author_identity.id,
                object_marking_refs=[self.tlp_marking.id],
                allow_custom=True,
            )
            objects.append(sighting)

        return objects
