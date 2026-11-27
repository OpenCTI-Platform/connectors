"""EXAMPLE processor -- enrich IPv4 addresses with their reputation.

`IPv4Processor` below is an example, not a processor to keep as it is. The
API it calls (`TemplateClient.get_ip_reputation`) does not exist. The file
shows the usual shape of an enrichment processor: copy it, then rewrite it
for your own source.

What is an enrichment processor?
    A processor enriches the entity types listed in `handled_entity_types`.
    For each message, `InternalEnrichmentConnector` (from `connectors-sdk`)
    first checks the connector scope and the entity TLP. Then it picks the
    processor that handles the entity, and calls:
        1. `collect()`: fetch data about the entity from the external source;
        2. `transform()`: convert this data to STIX objects.
    Finally, it sends these objects to OpenCTI, with the objects of the
    message.

    So a processor only fetches and converts data. It never checks the scope
    or the TLP, never sends a bundle, and never handles playbooks: the
    connector does it.

    A processor is created once and handles many messages. Keep the data of
    a message in local variables, never in instance attributes (`self.xxx`):
    they would leak to the next message.

TODO:
    - [ ] Copy this file for each group of entity types to enrich, then
        delete this example.
    - [ ] Add your processors to `connector/enrichment_processors/__init__.py`
        and `src/main.py`, and their entity types to the `scope` default in
        `connector/settings.py`.
"""

from connector.settings import ConnectorSettings
from connectors_sdk import ApiNotFoundError, BaseEnrichmentProcessor, EnrichmentMessage
from connectors_sdk.models import (
    AutonomousSystem,
    BaseIdentifiedObject,
    ExternalReference,
    IPV4Address,
    OrganizationAuthor,
    Reference,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import TLPLevel
from template_client import IPReputation, TemplateClient


# `[ConnectorSettings]` tells the type checker the type of `self.settings`.
class IPv4Processor(BaseEnrichmentProcessor[ConnectorSettings]):
    """EXAMPLE processor -- enrich an IPv4 address from a reputation API.

    Attributes:
        handled_entity_types: The OpenCTI entity types this processor enriches.
        settings: The connector settings. `InternalEnrichmentConnector` sets
            them before calling `post_init()`.
    """

    handled_entity_types = frozenset({"IPv4-Addr"})

    def post_init(self) -> None:
        """Create the API client, the author and the marking.

        `InternalEnrichmentConnector` calls this method once, when the
        connector starts, after it sets `self.settings`. Objects created here
        are shared by all the messages, so they are not created again for
        each entity.
        """
        self.client = TemplateClient(
            base_url=str(self.settings.template.api_base_url),
            api_key=self.settings.template.api_key.get_secret_value(),
        )
        self.author = OrganizationAuthor(name="Template Connector")
        # The TLP of the data the source provides. It is only applied to the
        # objects the connector creates, never to the enriched entity.
        self.tlp_marking = TLPMarking(level=TLPLevel.CLEAR)

    def collect(self, message: EnrichmentMessage) -> IPReputation | None:
        """Fetch the reputation of the IP address from the external API.

        `message.stix_entity` is the entity to enrich, as a STIX object. Read
        its STIX properties as attributes (e.g. `message.stix_entity.value`).
        No STIX conversion happens here.

        Args:
            message: The enrichment message.

        Returns:
            The reputation of the IP, or `None` if the source does not know it.

        Raises:
            ApiClientError: If the API call fails. The connector logs the error
                and puts the work in error.
        """
        try:
            return self.client.get_ip_reputation(message.stix_entity.value)
        except ApiNotFoundError:
            # Not an error: the source has no data about this IP
            self.logger.info(
                "IP address not found in the source",
                meta=message.to_log_metadata(),
            )
            return None

    def transform(
        self, data: IPReputation | None, message: EnrichmentMessage
    ) -> list[BaseIdentifiedObject]:
        """Convert the reputation of the IP address to STIX objects.

        No network call happens here. This example shows the two ways to
        enrich an entity:

        - Change the entity itself: return a new version of it, built with the
          same values as the entity (here, the same IP address), so that it
          gets the same id. In the bundle, it replaces the entity received,
          and OpenCTI adds its new properties (score, labels...) to the entity.
          We recommend not setting an author or a marking on it, and setting
          them on the new objects only: OpenCTI can replace the author of the
          entity, and adds the marking to the entity, which changes who can
          see it.
        - Link new objects to the entity: use `Reference(id=message.stix_entity.id)`
          as the source or the target of a relationship. A `Reference` only
          points to the entity: it never changes it, and it is never sent.

        Never return `message.stix_objects`: the connector already sends them
        with the objects returned here.

        Args:
            data: The reputation returned by `collect()`.
            message: The enrichment message.

        Returns:
            The STIX objects to send, with the author and the marking (other
            objects refer to them). An empty list when there is nothing to send.
        """
        if data is None:
            return []

        enriched_ip = IPV4Address(
            value=message.stix_entity.value,  # same value, so same id
            score=data.score,
            labels=data.tags or None,
            external_references=(
                [ExternalReference(source_name="Template", url=data.permalink)]
                if data.permalink
                else None
            ),
        )
        stix_objects: list[BaseIdentifiedObject] = [
            self.author,
            self.tlp_marking,
            enriched_ip,
        ]

        if self.settings.template.create_autonomous_system and data.asn is not None:
            autonomous_system = AutonomousSystem(
                number=data.asn,
                name=data.as_name,
                author=self.author,
                markings=[self.tlp_marking],
            )
            relationship = Relationship(
                type="belongs-to",
                source=Reference(id=message.stix_entity.id),
                target=autonomous_system,
                author=self.author,
                markings=[self.tlp_marking],
            )
            stix_objects += [autonomous_system, relationship]

        return stix_objects
