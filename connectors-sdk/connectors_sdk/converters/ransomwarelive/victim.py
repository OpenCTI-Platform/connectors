"""RansomwareLiveVictimConverter."""

import re
from urllib.parse import urlsplit

from connectors_sdk.converters.base import AbstractConverter
from connectors_sdk.converters.exceptions import ConversionError
from connectors_sdk.converters.ransomwarelive.models import (
    RansomwareLiveGroup,
    RansomwareLiveVictim,
    RansomwareLiveVictimInput,
)
from connectors_sdk.models import (
    BaseAuthorEntity,
    BaseIdentifiedEntity,
    BaseIdentifiedObject,
    Country,
    DomainName,
    ExternalReference,
    Individual,
    IntrusionSet,
    Organization,
    Relationship,
    Report,
    Sector,
    TLPMarking,
)
from connectors_sdk.models.enums import AttackResourceLevel, RelationshipType
from pydantic import ValidationError

RANSOMWARELIVE_SOURCE_NAME = "ransomware.live"
LOCKBIT_GROUPS = frozenset({"lockbit2", "lockbit3"})
NO_DESCRIPTION = "No description available"
UNKNOWN_SECTOR = "Not Found"
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.IGNORECASE
)


class RansomwareLiveVictimConverter(AbstractConverter[RansomwareLiveVictimInput]):
    """Convert a Ransomware.live victim publication into a report and its graph.

    The report references the victim, the intrusion set of the group and, when
    the publication has them, the victim's sector, domain name and country.
    Threat actors, campaigns, leak-site domains and TTPs are not produced.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor, TLPMarking
        >>> converter = RansomwareLiveVictimConverter(
        ...     author=OrganizationAuthor(name="Ransomware.Live"),
        ...     markings=[TLPMarking(level="clear")],
        ... )
        >>> converter.include_leak_post_references
        False

    """

    def __init__(
        self,
        author: BaseAuthorEntity,
        markings: list[TLPMarking],
        include_leak_site_references: bool = False,
        include_leak_post_references: bool = False,
    ) -> None:
        """Initialize the converter.

        Args:
            author: The author referenced by every produced object.
            markings: The markings referenced by every produced object.
            include_leak_site_references: Add the group's leak-site URLs to the
                intrusion set external references.
            include_leak_post_references: Add the victim's leak post URL to the
                report external references.
        """
        super().__init__(author=author, markings=markings)
        self.include_leak_site_references = include_leak_site_references
        self.include_leak_post_references = include_leak_post_references

    def transform(self, input: RansomwareLiveVictimInput) -> list[BaseIdentifiedObject]:
        """Convert a victim publication.

        Args:
            input: The victim publication and its group entry.

        Returns:
            The victim, the intrusion set, the optional sector, domain name and
            country, the relationships between them, and the report.

        Raises:
            ConversionError: If a value of the publication is rejected by the models.
        """
        try:
            return self._convert(input.victim, input.group)
        except ValidationError as err:
            raise ConversionError(
                f"Cannot convert victim {input.victim.victim}"
            ) from err

    def _convert(
        self, item: RansomwareLiveVictim, group: RansomwareLiveGroup | None
    ) -> list[BaseIdentifiedObject]:
        victim = self._victim(item.victim)
        intrusion_set = self._intrusion_set(item.group, group)
        objects: list[BaseIdentifiedEntity] = [
            victim,
            intrusion_set,
            self._relationship(RelationshipType.TARGETS, intrusion_set, victim, item),
        ]

        if item.activity and item.activity != UNKNOWN_SECTOR:
            sector = Sector(
                name=item.activity, author=self.author, markings=self.markings
            )
            objects += [
                sector,
                self._relationship(RelationshipType.PART_OF, victim, sector),
                self._relationship(
                    RelationshipType.TARGETS, intrusion_set, sector, item
                ),
            ]

        domain_name = self._domain_name(item)
        if domain_name:
            domain = DomainName(
                value=domain_name, author=self.author, markings=self.markings
            )
            objects += [
                domain,
                self._relationship(RelationshipType.BELONGS_TO, domain, victim),
            ]

        if item.country:
            country = Country(
                name=item.country, author=self.author, markings=self.markings
            )
            objects += [
                country,
                self._relationship(
                    RelationshipType.TARGETS, intrusion_set, country, item
                ),
                self._relationship(RelationshipType.LOCATED_AT, victim, country),
            ]

        report = Report(
            name=f"{item.group} has published a new victim: {item.victim}",
            publication_date=item.attackdate,
            created=item.discovered,
            description=item.description,
            report_types=["Ransomware-report"],
            objects=list(objects),
            external_references=self._victim_references(item) or None,
            author=self.author,
            markings=self.markings,
        )
        return [*objects, report]

    def _victim(self, name: str) -> Organization | Individual:
        """Return an organization, or an individual for names of 2 characters or less."""
        if len(name) > 2:
            return Organization(name=name, author=self.author, markings=self.markings)
        return Individual(name=f"{name}:<)", author=self.author, markings=self.markings)

    def _intrusion_set(
        self, group_name: str, group: RansomwareLiveGroup | None
    ) -> IntrusionSet:
        name = "lockbit" if group_name in LOCKBIT_GROUPS else group_name
        if len(name.strip()) < 2:
            name += " "  # The STIX id cannot be generated from shorter names.
        description = NO_DESCRIPTION
        if (
            group
            and group.description
            and group.description.strip()
            not in {
                "",
                "null",
            }
        ):
            description = group.description
        aliases = (
            [group.altname.strip()]
            if group and group.altname and group.altname.strip()
            else None
        )
        return IntrusionSet(
            name=name,
            description=description,
            aliases=aliases,
            labels=["ransomware"],
            resource_level=AttackResourceLevel.ORGANIZATION,
            external_references=self._group_references(group) or None,
            author=self.author,
            markings=self.markings,
        )

    def _group_references(
        self, group: RansomwareLiveGroup | None
    ) -> list[ExternalReference]:
        if group is None:
            return []
        urls: dict[str, str] = {}
        if group.url:
            urls[group.url] = "ransomware.live group profile page"
        if self.include_leak_site_references:
            for location in group.locations:
                if location.slug and location.slug not in urls:
                    urls[location.slug] = f"Leak site: {location.title or 'Leak site'}"
        return [
            ExternalReference(
                source_name=RANSOMWARELIVE_SOURCE_NAME, url=url, description=description
            )
            for url, description in urls.items()
        ]

    def _victim_references(self, item: RansomwareLiveVictim) -> list[ExternalReference]:
        fields = {"screenshot": item.screenshot, "website": item.website}
        if self.include_leak_post_references:
            fields["post_url"] = item.post_url
        return [
            ExternalReference(
                source_name=RANSOMWARELIVE_SOURCE_NAME,
                url=url,
                description=f"This is the {field} for the ransomware campaign.",
            )
            for field, url in fields.items()
            if url
        ]

    @staticmethod
    def _domain_name(item: RansomwareLiveVictim) -> str | None:
        """Return the victim domain: the victim name if it is one, else the ``domain`` field host.

        Unlike the connector, the registered domain is not extracted from
        sub-domains (no public suffix list in the SDK).
        """
        if DOMAIN_PATTERN.match(item.victim):
            return item.victim
        candidate = (item.domain or "").replace("​", "").strip()
        if not candidate:
            return None
        if DOMAIN_PATTERN.match(candidate):
            return candidate
        host = urlsplit(candidate if "//" in candidate else f"//{candidate}").hostname
        return host if host and DOMAIN_PATTERN.match(host) else None

    def _relationship(
        self,
        relationship_type: RelationshipType,
        source: BaseIdentifiedEntity,
        target: BaseIdentifiedEntity,
        dated_by: RansomwareLiveVictim | None = None,
    ) -> Relationship:
        """Build a relationship, dated by the attack when ``dated_by`` is given."""
        return Relationship(
            type=relationship_type,
            source=source,
            target=target,
            start_time=dated_by.attackdate if dated_by else None,
            created=dated_by.discovered if dated_by else None,
            author=self.author,
            markings=self.markings,
        )
