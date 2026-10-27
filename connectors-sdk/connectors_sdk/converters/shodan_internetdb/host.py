"""ShodanInternetDbHostConverter."""

from connectors_sdk.converters.base import AbstractConverter
from connectors_sdk.converters.shodan_internetdb.models import (
    ShodanInternetDbHostInput,
    ShodanInternetDbResult,
)
from connectors_sdk.models import (
    BaseIdentifiedObject,
    DomainName,
    IPV4Address,
    Note,
    Reference,
    Relationship,
    Vulnerability,
)
from connectors_sdk.models.enums import RelationshipType


class ShodanInternetDbHostConverter(AbstractConverter[ShodanInternetDbHostInput]):
    """Convert a Shodan InternetDB result into objects enriching an IPv4 observable.

    Unlike the connector, the ``related-to`` relationships have no start and
    stop times and the note has no creation date: both made the ids change on
    every run.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor, TLPMarking
        >>> converter = ShodanInternetDbHostConverter(
        ...     author=OrganizationAuthor(name="Shodan"),
        ...     markings=[TLPMarking(level="clear")],
        ... )
        >>> result = ShodanInternetDbResult(
        ...     cpes=[], hostnames=[], ip="1.1.1.1", ports=[], tags=[], vulns=[]
        ... )
        >>> objects = converter.transform(
        ...     ShodanInternetDbHostInput(observable_value="1.1.1.1", result=result)
        ... )
        >>> [type(obj).__name__ for obj in objects]
        ['Note']

    """

    def transform(self, input: ShodanInternetDbHostInput) -> list[BaseIdentifiedObject]:
        """Convert an InternetDB result for one IPv4 observable.

        Args:
            input: The observable value and its InternetDB result.

        Returns:
            The hostnames, the vulnerabilities and their relationships, the
            observable carrying the tags as labels (only when there are tags)
            and the note.
        """
        result = input.result
        # The id of an IPv4 observable only depends on its value.
        observable = Reference(id=IPV4Address(value=input.observable_value).id)

        objects: list[BaseIdentifiedObject] = [
            DomainName(
                value=hostname,
                resolves_to=[observable],
                author=self.author,
                markings=self.markings,
            )
            for hostname in result.hostnames
        ]
        for name in result.vulns:
            vulnerability = Vulnerability(
                name=name, author=self.author, markings=self.markings
            )
            objects.append(vulnerability)
            objects.append(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=observable,
                    target=vulnerability,
                    author=self.author,
                    markings=self.markings,
                )
            )
        if result.tags:
            objects.append(
                IPV4Address(
                    value=input.observable_value,
                    labels=result.tags,
                    author=self.author,
                    markings=self.markings,
                )
            )
        objects.append(
            Note(
                abstract=f"Shodan InternetDB enrichment of {input.observable_value}",
                content=self._note_content(result),
                objects=[observable],
                author=self.author,
                markings=self.markings,
            )
        )
        return objects

    @staticmethod
    def _note_content(result: ShodanInternetDbResult) -> str:
        def format_list(values: list[str] | list[int]) -> str:
            return "".join(f"\n- {value}" for value in values) or "n/a"

        return (
            "```\n"
            "Shodan InternetDB:\n"
            "------------------\n"
            f"Hostnames: {format_list(result.hostnames)}\n"
            "------------------\n"
            f"Software: {format_list(result.cpes)}\n"
            "------------------\n"
            f"Vulnerabilities: {format_list(result.vulns)}\n"
            "------------------\n"
            f"Ports: {format_list(result.ports)}\n"
            "------------------\n"
            "```\n"
        )
