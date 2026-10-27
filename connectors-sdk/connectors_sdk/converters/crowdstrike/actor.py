"""CrowdStrikeActorConverter."""

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser

from connectors_sdk.converters.base import AbstractConverter
from connectors_sdk.converters.crowdstrike.location import (
    CrowdStrikeLocationConverter,
)
from connectors_sdk.converters.crowdstrike.models import (
    CrowdStrikeActor,
    CrowdStrikeActorInput,
    CrowdStrikeEntity,
    CrowdStrikeThreat,
)
from connectors_sdk.converters.crowdstrike.sector import CrowdStrikeSectorConverter
from connectors_sdk.converters.exceptions import ConversionError
from connectors_sdk.models import (
    AttackPattern,
    BaseAuthorEntity,
    BaseIdentifiedEntity,
    BaseIdentifiedObject,
    ExternalReference,
    IntrusionSet,
    Malware,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import AttackMotivation, RelationshipType
from pydantic import ValidationError

CROWDSTRIKE_MOTIVATIONS = {
    "criminal": "personal-gain",
    "destruction": "dominance",
    "espionage": "organizational-gain",
    "hacktivist": "ideology",
    "state-sponsored": "geopolitical",
}


class _TextExtractor(HTMLParser):
    """Collect the text of an HTML fragment."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _strip_html(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    return "".join(parser.parts).strip()


def _entities(objects: Iterable[BaseIdentifiedObject]) -> list[BaseIdentifiedEntity]:
    """Narrow sub-converter output to entities that can be relationship ends."""
    return [obj for obj in objects if isinstance(obj, BaseIdentifiedEntity)]


class CrowdStrikeActorConverter(AbstractConverter[CrowdStrikeActorInput]):
    """Convert a CrowdStrike actor into an intrusion set and the entities it relates to.

    Locations and sectors are delegated to ``CrowdStrikeLocationConverter`` and
    ``CrowdStrikeSectorConverter``. Unlike the connector, objects carry no
    ``confidence``: SDK models do not support it.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor
        >>> converter = CrowdStrikeActorConverter(
        ...     author=OrganizationAuthor(name="CrowdStrike"), markings=[]
        ... )
        >>> actor = CrowdStrikeActorInput.model_validate(
        ...     {"actor": {"id": 1, "name": "FANCY BEAR"}}
        ... )
        >>> [obj.name for obj in converter.transform(actor)]
        ['FANCY BEAR']

    """

    def __init__(
        self,
        author: BaseAuthorEntity,
        markings: list[TLPMarking],
        source_name: str = "CrowdStrike",
    ) -> None:
        """Initialize the converter and its sub-converters.

        Args:
            author: The author referenced by every produced object.
            markings: The markings referenced by every produced object.
            source_name: The source name of the actor external reference.
        """
        super().__init__(author=author, markings=markings)
        self.source_name = source_name
        self.location_converter = CrowdStrikeLocationConverter(
            author=author, markings=markings
        )
        self.sector_converter = CrowdStrikeSectorConverter(
            author=author, markings=markings
        )

    def transform(self, input: CrowdStrikeActorInput) -> list[BaseIdentifiedObject]:
        """Convert an actor.

        Args:
            input: The actor and its MITRE ATT&CK identifiers.

        Returns:
            The intrusion set, its origin and target locations, targeted sectors,
            attack patterns and malware, and the relationships between them.

        Raises:
            ConversionError: If a value of the actor is rejected by the models.
        """
        try:
            return self._convert(input)
        except ValidationError as err:
            raise ConversionError(f"Cannot convert actor {input.actor.name}") from err

    def _convert(self, input: CrowdStrikeActorInput) -> list[BaseIdentifiedObject]:
        actor = input.actor
        first_seen, last_seen = self._activity_dates(actor)
        intrusion_set = self._intrusion_set(actor, first_seen, last_seen)

        origins = self._locations(actor.origins)
        targeted_locations = self._locations(actor.target_countries)
        sectors = _entities(
            obj
            for entity in actor.target_industries or []
            for obj in self.sector_converter.transform(entity)
        )
        attack_patterns = self._attack_patterns(input.mitre_attack_ids)
        used_malware = self._malware(actor.uses_threats)
        developed_malware = self._malware(actor.develops_threats)
        all_malware = list({m.id: m for m in used_malware + developed_malware}.values())

        def relate(
            relationship_type: RelationshipType,
            targets: list[BaseIdentifiedEntity],
            dated: bool = False,
        ) -> list[Relationship]:
            return [
                Relationship(
                    type=relationship_type,
                    source=intrusion_set,
                    target=target,
                    start_time=first_seen if dated else None,
                    stop_time=last_seen if dated else None,
                    author=self.author,
                    markings=self.markings,
                )
                for target in targets
            ]

        return [
            intrusion_set,
            *origins,
            *relate(RelationshipType.ORIGINATES_FROM, origins),
            *targeted_locations,
            *relate(RelationshipType.TARGETS, targeted_locations, dated=True),
            *sectors,
            *relate(RelationshipType.TARGETS, sectors, dated=True),
            *attack_patterns,
            *relate(RelationshipType.USES, list(attack_patterns), dated=True),
            *all_malware,
            *relate(RelationshipType.USES, list(used_malware), dated=True),
            *[
                Relationship(
                    type=RelationshipType.AUTHORED_BY,
                    source=malware,
                    target=intrusion_set,
                    author=self.author,
                    markings=self.markings,
                )
                for malware in developed_malware
            ],
        ]

    def _intrusion_set(
        self,
        actor: CrowdStrikeActor,
        first_seen: datetime | None,
        last_seen: datetime | None,
    ) -> IntrusionSet:
        motivations = self._motivations(actor)
        return IntrusionSet(
            name=actor.name,
            description=self._description(actor),
            aliases=self._aliases(actor),
            first_seen=first_seen,
            last_seen=last_seen,
            primary_motivation=motivations[0] if motivations else None,
            secondary_motivations=motivations[1:] or None,
            labels=self._labels(actor),
            external_references=(
                [
                    ExternalReference(
                        source_name=self.source_name,
                        external_id=str(actor.id),
                        url=actor.url,
                    )
                ]
                if actor.url
                else None
            ),
            author=self.author,
            markings=self.markings,
        )

    def _locations(
        self, entities: list[CrowdStrikeEntity] | None
    ) -> list[BaseIdentifiedEntity]:
        return _entities(
            obj
            for entity in entities or []
            for obj in self.location_converter.transform(entity)
        )

    def _attack_patterns(self, mitre_attack_ids: list[str]) -> list[AttackPattern]:
        """Build one attack pattern per technique of ``<actor>_<tactic>_<technique>`` ids."""
        technique_ids = dict.fromkeys(
            parts[2]
            for parts in (mitre_id.split("_") for mitre_id in mitre_attack_ids)
            if len(parts) >= 3 and parts[2].startswith("T")
        )
        return [
            AttackPattern(
                name=technique_id,
                mitre_id=technique_id,
                author=self.author,
                markings=self.markings,
            )
            for technique_id in technique_ids
        ]

    def _malware(self, threats: list[CrowdStrikeThreat] | None) -> list[Malware]:
        family_names = dict.fromkeys(
            threat.family_name for threat in threats or [] if threat.family_name
        )
        return [
            Malware(
                name=name, is_family=True, author=self.author, markings=self.markings
            )
            for name in family_names
        ]

    @staticmethod
    def _activity_dates(
        actor: CrowdStrikeActor,
    ) -> tuple[datetime | None, datetime | None]:
        """Return first and last seen, the first never later than the last."""
        first_seen, last_seen = (
            datetime.fromtimestamp(ts, tz=timezone.utc) if ts and ts > 0 else None
            for ts in (actor.first_activity_date, actor.last_activity_date)
        )
        if first_seen is not None and last_seen is not None:
            if first_seen == last_seen:
                last_seen += timedelta(seconds=1)
            elif first_seen > last_seen:
                first_seen, last_seen = last_seen, first_seen
        return first_seen, last_seen

    @staticmethod
    def _description(actor: CrowdStrikeActor) -> str | None:
        if actor.description:
            return actor.description
        if actor.rich_text_description:
            return _strip_html(actor.rich_text_description)
        return actor.short_description or None

    @staticmethod
    def _aliases(actor: CrowdStrikeActor) -> list[str]:
        """Return the compact name and the ``known_as`` names, without the name itself."""
        aliases = dict.fromkeys(
            [
                actor.name.replace(" ", ""),
                *(alias.strip() for alias in (actor.known_as or "").split(",")),
            ]
        )
        return [alias for alias in aliases if alias and alias != actor.name]

    @staticmethod
    def _motivations(actor: CrowdStrikeActor) -> list[AttackMotivation]:
        """Map CrowdStrike motivations to STIX ones, dropping unknown values."""
        return [
            AttackMotivation(CROWDSTRIKE_MOTIVATIONS[value])
            for value in (
                (motivation.value or "").strip().lower()
                for motivation in actor.motivations or []
            )
            if value in CROWDSTRIKE_MOTIVATIONS
        ]

    @staticmethod
    def _labels(actor: CrowdStrikeActor) -> list[str] | None:
        """Return the raw motivation values and the actor type, deduplicated."""
        labels = dict.fromkeys(
            [
                *(
                    (motivation.value or motivation.slug or "").strip()
                    for motivation in actor.motivations or []
                ),
                (actor.actor_type or "").strip(),
            ]
        )
        return [label for label in labels if label] or None
