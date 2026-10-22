import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import pycountry
import requests
from connectors_sdk import ApiClientError, BaseEnrichmentProcessor, EnrichmentMessage
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import (
    AdministrativeArea,
    AutonomousSystem,
    BaseIdentifiedEntity,
    City,
    Country,
    ExternalReference,
    Infrastructure,
    IPV4Address,
    IPV6Address,
    Note,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import InfrastructureType, RelationshipType
from pydantic import IPvAnyAddress, ValidationError
from spur_client import IPContext, SpurClient, TagMetadata
from spur_client.models import Tunnel

RISK_SCORE_STEP = 5
# Risks that point to malicious activity. An anonymization service alone (TUNNEL)
# or a location mismatch (GEO_MISMATCH) does not make an IP malicious.
OFFENSIVE_RISKS = frozenset(
    {"AD_FRAUD", "CALLBACK_PROXY", "LOGIN_BRUTEFORCE", "WEB_SCRAPING"}
)
# Entry and exit nodes linked to a tunnel infrastructure, per enrichment
MAX_TUNNEL_NODES = 50
SPUR_CONTEXT_URL = "https://spur.us/context/{ip}"
# City and state that Spur returns for anycast IPs (with the "ZZ" country code)
ANYCAST = "anycast"
# Readable titles of the Spur tag metrics, in display order
TAG_METRICS = {
    "distinctIPs": "Distinct IPs",
    "distinctASNs": "Distinct ASNs",
    "distinctISPs": "Distinct ISPs",
    "distinctCountries": "Distinct countries",
    "averageDeviceCount": "Average device count",
    "churnRate": "Churn rate",
}


def build_author() -> OrganizationAuthor:
    """Spur author, shared with the Spur external-import connector (same name, same id)."""
    return OrganizationAuthor(
        name="Spur",
        description=(
            "Spur provides anonymous infrastructure intelligence, identifying VPNs, "
            "proxies, and residential exit nodes."
        ),
    )


def _label(field: str, value: str | bool) -> str:
    """Build a Spur label, e.g. `spur-risk:geo_mismatch`."""
    return f"spur-{field}:{str(value).lower()}"


def _unique(values: Iterable[str | None]) -> list[str]:
    """Remove empty values and duplicates, keeping the order."""
    return list(dict.fromkeys(value for value in values if value))


def _service_tags(ip_context: IPContext) -> list[str]:
    """Return the service tags seen on the IP: tunnel operators, client proxies, AI operator."""
    return _unique(
        [
            *(tunnel.operator for tunnel in ip_context.tunnels),
            *(ip_context.client.proxies if ip_context.client else []),
            ip_context.ai.operator if ip_context.ai else None,
        ]
    )


def _canonical_tag(tag: str, tag_metadata: dict[str, TagMetadata]) -> str:
    """Return the tag that `tag` is an alias of, or `tag` itself."""
    metadata = tag_metadata.get(tag)
    return metadata.alias_of if metadata and metadata.alias_of else tag


@dataclass(frozen=True)
class SpurData:
    """What `collect()` fetched from Spur for one IP.

    Attributes:
        ip_context: The IP Context object.
        tag_metadata: The Tag Metadata objects by service tag, including the
            canonical tags of aliases. Empty when `fetch_tag_metadata` is disabled.
    """

    ip_context: IPContext
    tag_metadata: dict[str, TagMetadata] = field(default_factory=dict)


class SpurIPProcessor(BaseEnrichmentProcessor):
    """Enrich an IPv4 or IPv6 address with one call to the Spur Context API."""

    entity_types = frozenset({"IPv4-Addr", "IPv6-Addr"})

    def post_init(self) -> None:
        """Build the API client, the author and the marking once."""
        spur_config = self.settings.spur
        self.client = SpurClient(
            base_url=str(spur_config.api_base_url),
            api_key=spur_config.api_key.get_secret_value(),
        )
        self.author = build_author()
        self.tlp_marking = TLPMarking(level=spur_config.tlp_level)
        self.default_score = spur_config.default_score
        self.fetch_tag_metadata = spur_config.fetch_tag_metadata

    def collect(self, message: EnrichmentMessage) -> SpurData | None:
        """Fetch the Spur IP context, `None` when the IP cannot be queried.

        With `fetch_tag_metadata`, also fetch the metadata of the services seen
        on the IP (cached by the client).
        """
        value = message.stix_entity["value"]
        ip = self._single_ip(value)
        if ip is None:
            self.logger.warning(
                "Skipping a network, Spur only accepts a single IP address",
                meta={"entity_id": message.entity_id, "value": value},
            )
            return None
        try:
            ip_context = self.client.get_ip_context(ip)
        except (ApiClientError, requests.RequestException) as err:
            raise DataRetrievalError(
                f"Failed to fetch the Spur IP context of {ip}: {err}"
            ) from err
        except ValidationError as err:
            raise DataRetrievalError(
                f"Spur returned an invalid IP context for {ip}: {err}"
            ) from err
        if ip_context is None:
            self.logger.warning(
                "Spur rejected the IP address (private or reserved IP?)",
                meta={"entity_id": message.entity_id, "ip": ip},
            )
            return None
        tag_metadata = (
            self._collect_tag_metadata(ip_context) if self.fetch_tag_metadata else {}
        )
        return SpurData(ip_context=ip_context, tag_metadata=tag_metadata)

    def _collect_tag_metadata(self, ip_context: IPContext) -> dict[str, TagMetadata]:
        """Fetch the metadata of each service tag, and of the canonical tag of aliases.

        A tag whose metadata cannot be fetched is skipped and logged: its
        infrastructure is still created, from the IP context only.
        """
        tag_metadata: dict[str, TagMetadata] = {}
        for tag in _service_tags(ip_context):
            metadata = self._fetch_tag_metadata(tag)
            if metadata is None:
                continue
            tag_metadata[tag] = metadata
            canonical_tag = metadata.alias_of
            if canonical_tag and canonical_tag not in tag_metadata:
                canonical_metadata = self._fetch_tag_metadata(canonical_tag)
                if canonical_metadata is not None:
                    tag_metadata[canonical_tag] = canonical_metadata
        return tag_metadata

    def _fetch_tag_metadata(self, tag: str) -> TagMetadata | None:
        """Fetch the metadata of a tag, `None` (logged) when it is unknown or fails."""
        try:
            metadata = self.client.get_tag_metadata(tag)
        except (ApiClientError, requests.RequestException, ValidationError) as err:
            self.logger.warning(
                "Failed to fetch the Spur tag metadata, skipping it",
                meta={"tag": tag, "error": str(err)},
            )
            return None
        if metadata is None:
            self.logger.info("Spur has no metadata for this tag", meta={"tag": tag})
        return metadata

    @staticmethod
    def _single_ip(value: str) -> str | None:
        """Return the IP address of the value, `None` for a network or an invalid value.

        OpenCTI accepts a CIDR as IP value: a `/32` (or `/128`) is a single IP.
        """
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if network.num_addresses != 1:
            return None
        return str(network.network_address)

    def transform(self, data: SpurData | None, message: EnrichmentMessage) -> list[Any]:
        """Convert the Spur data into connectors-sdk models.

        Returns:
            The author, the marking, the enriched IP (merged by the connector into the
            IP received) and the related objects, or `[]` when there is no IP context.
        """
        if data is None:
            return []
        ip_context = data.ip_context
        ip = self._build_ip(ip_context, message)
        objects: list[Any] = [
            self.author,
            self.tlp_marking,
            message.enriched_entity(ip),
        ]
        objects.extend(self._build_autonomous_system(ip_context, ip))
        objects.extend(self._build_locations(ip_context, ip))
        objects.extend(self._build_infrastructures(ip_context, data.tag_metadata, ip))
        objects.extend(self._build_note(ip_context, ip))
        return objects

    def _build_ip(
        self, ip_context: IPContext, message: EnrichmentMessage
    ) -> IPV4Address | IPV6Address:
        """Rebuild the enriched IP with the Spur labels, score and external reference.

        The connector merges it into the IP received: the labels and the external
        reference are added to the existing ones, the score replaces the existing one,
        and the author and the markings of the IP received are kept. The value is
        kept as is, so that relationships built from this model point to the IP
        received.
        """
        ip_class = (
            IPV6Address if message.entity_type.lower() == "ipv6-addr" else IPV4Address
        )
        return ip_class(
            value=message.stix_entity["value"],
            labels=self._build_labels(ip_context) or None,
            score=self._compute_score(ip_context),
            external_references=[
                ExternalReference(
                    source_name="Spur",
                    description="Spur IP context",
                    url=SPUR_CONTEXT_URL.format(ip=ip_context.ip),
                )
            ],
        )

    @staticmethod
    def _build_labels(ip_context: IPContext) -> list[str]:
        """Build the Spur labels of the enriched IP.

        Only values from a closed list become labels. Service tags (tunnel
        operators, client proxies, AI operators) are an open catalog of thousands
        of values: they become infrastructures instead.
        """
        labels = []
        for tunnel in ip_context.tunnels:
            if tunnel.type:
                labels.append(_label("tunnel-type", tunnel.type))
            if tunnel.anonymous is not None:
                labels.append(_label("tunnel-anonymous", tunnel.anonymous))
        labels.extend(_label("risk", risk) for risk in ip_context.risks)
        labels.extend(_label("service", service) for service in ip_context.services)
        if ip_context.infrastructure:
            labels.append(_label("infrastructure", ip_context.infrastructure))
        if client := ip_context.client:
            labels.extend(_label("behavior", behavior) for behavior in client.behaviors)
            labels.extend(
                _label("client-type", client_type) for client_type in client.types
            )
        if ai := ip_context.ai:
            labels.extend(_label("ai-type", ai_type) for ai_type in ai.types)
        return _unique(labels)

    def _compute_score(self, ip_context: IPContext) -> int | None:
        """Score an IP with offensive risks: `default_score + 5 x offensive risks`.

        An IP without offensive risk (e.g. a consumer VPN exit, flagged `TUNNEL`
        only) keeps its current score.
        """
        offensive_risks = [risk for risk in ip_context.risks if risk in OFFENSIVE_RISKS]
        if not offensive_risks:
            return None
        return min(100, self.default_score + RISK_SCORE_STEP * len(offensive_risks))

    def _relationship(
        self,
        relationship_type: RelationshipType,
        source: BaseIdentifiedEntity,
        target: BaseIdentifiedEntity,
        description: str | None = None,
    ) -> Relationship:
        return Relationship(
            type=relationship_type,
            source=source,
            target=target,
            description=description,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _build_autonomous_system(
        self, ip_context: IPContext, ip: IPV4Address | IPV6Address
    ) -> list[Any]:
        """Build the autonomous system of the IP and its `belongs-to` relationship."""
        as_info = ip_context.autonomous_system
        if as_info is None or as_info.number is None:
            return []
        autonomous_system = AutonomousSystem(
            number=as_info.number,
            name=as_info.organization or None,
            author=self.author,
            markings=[self.tlp_marking],
        )
        return [
            autonomous_system,
            self._relationship(RelationshipType.BELONGS_TO, ip, autonomous_system),
        ]

    def _build_locations(
        self, ip_context: IPContext, ip: IPV4Address | IPV6Address
    ) -> list[Any]:
        """Build the locations of the IP, chained by `located-at` relationships.

        The IP is located at its most precise location (city, then state, then
        country), and each location at the next less precise one.

        Anycast IPs have no real location: Spur returns `Anycast` as city and
        state, and `ZZ` as country. Those values, like any country code that is
        not ISO 3166, are skipped.
        """
        location = ip_context.location
        if location is None:
            return []
        country = (
            pycountry.countries.get(alpha_2=location.country)
            if location.country
            else None
        )
        candidates: list[
            tuple[type[City | AdministrativeArea | Country], str | None]
        ] = [
            (City, location.city),
            (AdministrativeArea, location.state),
            (Country, country.name if country else None),
        ]

        objects: list[Any] = []
        source: BaseIdentifiedEntity = ip
        for location_class, name in candidates:
            if not name or name.lower() == ANYCAST:
                continue
            target = location_class(
                name=name, author=self.author, markings=[self.tlp_marking]
            )
            objects.append(target)
            objects.append(
                self._relationship(RelationshipType.LOCATED_AT, source, target)
            )
            source = target
        return objects

    def _build_infrastructures(
        self,
        ip_context: IPContext,
        tag_metadata: dict[str, TagMetadata],
        ip: IPV4Address | IPV6Address,
    ) -> list[Any]:
        """Build the services the IP belongs to or is used by.

        - Tunnel operator: anonymization infrastructure that `consists-of` the IP
          and the tunnel entry and exit nodes.
        - Client proxy: anonymization infrastructure `related-to` the IP. The
          clients behind the IP use it, but the IP is not necessarily part of it.
        - AI operator: infrastructure that `consists-of` the IP.

        A service seen several times (e.g. as tunnel operator and client proxy) is
        built once, with the strongest relationship.
        """
        objects: list[Any] = []
        names: set[str] = set()

        # Tunnels are grouped by service: two operator tags of the same service
        # (an alias and its canonical tag) give one infrastructure with all nodes.
        tunnels_by_service: dict[str, tuple[str, list[Tunnel]]] = {}
        for tunnel in ip_context.tunnels:
            if tunnel.operator:
                service = _canonical_tag(tunnel.operator, tag_metadata)
                _, service_tunnels = tunnels_by_service.setdefault(
                    service, (tunnel.operator, [])
                )
                service_tunnels.append(tunnel)
        for operator, tunnels in tunnels_by_service.values():
            infrastructure, extra_objects = self._build_infrastructure(
                operator,
                tag_metadata,
                infrastructure_types=[InfrastructureType.ANONYMIZATION],
                anonymous=any(tunnel.anonymous for tunnel in tunnels),
                fallback_description=(
                    f"Services seen by Spur on {ip_context.ip}: "
                    f"{', '.join(ip_context.services)}"
                    if ip_context.services
                    else None
                ),
            )
            objects.append(infrastructure)
            objects.extend(extra_objects)
            objects.append(
                self._relationship(RelationshipType.CONSISTS_OF, infrastructure, ip)
            )
            objects.extend(
                self._build_tunnel_nodes(infrastructure, tunnels, ip_context.ip)
            )
            names.add(infrastructure.name)

        proxies = ip_context.client.proxies if ip_context.client else []
        for proxy in _unique(proxies):
            infrastructure, extra_objects = self._build_infrastructure(
                proxy,
                tag_metadata,
                infrastructure_types=[InfrastructureType.ANONYMIZATION],
            )
            if infrastructure.name in names:
                continue
            objects.append(infrastructure)
            objects.extend(extra_objects)
            objects.append(
                self._relationship(RelationshipType.RELATED_TO, infrastructure, ip)
            )
            names.add(infrastructure.name)

        ai_operator = ip_context.ai.operator if ip_context.ai else None
        if ai_operator:
            infrastructure, extra_objects = self._build_infrastructure(
                ai_operator, tag_metadata
            )
            if infrastructure.name not in names:
                objects.append(infrastructure)
                objects.extend(extra_objects)
                objects.append(
                    self._relationship(RelationshipType.CONSISTS_OF, infrastructure, ip)
                )
        return objects

    def _build_infrastructure(
        self,
        tag: str,
        tag_metadata: dict[str, TagMetadata],
        infrastructure_types: list[InfrastructureType] | None = None,
        anonymous: bool = False,
        fallback_description: str | None = None,
    ) -> tuple[Infrastructure, list[Any]]:
        """Build the infrastructure of a service tag, described by its metadata if fetched.

        The infrastructure is named after the canonical Spur tag (the tag itself,
        or the tag it is an alias of). This name must never change, as the
        infrastructure id only depends on it: the readable name and the other tags
        go to `aliases`.

        Returns:
            The infrastructure, and the note holding the service metrics, if any.
        """
        canonical_tag = _canonical_tag(tag, tag_metadata)
        metadata = tag_metadata.get(canonical_tag, tag_metadata.get(tag))
        if metadata is None:
            infrastructure = Infrastructure(
                name=tag,
                description=fallback_description,
                infrastructure_types=infrastructure_types,
                labels=[_label("infra", "anonymous")] if anonymous else None,
                author=self.author,
                markings=[self.tlp_marking],
            )
            return infrastructure, []

        labels = [_label("category", category) for category in metadata.categories]
        if anonymous or metadata.is_anonymous:
            labels.append(_label("infra", "anonymous"))
        if metadata.is_no_log:
            labels.append(_label("infra", "no-log"))
        aliases = [
            alias
            for alias in _unique(
                [tag, metadata.name, *metadata.aliases, *metadata.all_tags]
            )
            if alias != canonical_tag
        ]
        infrastructure = Infrastructure(
            name=canonical_tag,
            description=self._describe_service(metadata),
            aliases=aliases or None,
            infrastructure_types=infrastructure_types,
            labels=_unique(labels) or None,
            external_references=(
                [
                    ExternalReference(
                        source_name=metadata.name or canonical_tag,
                        description="Service website",
                        url=metadata.website,
                    )
                ]
                if metadata.website
                else None
            ),
            author=self.author,
            markings=[self.tlp_marking],
        )
        return infrastructure, self._build_metrics_note(metadata, infrastructure)

    @staticmethod
    def _describe_service(metadata: TagMetadata) -> str:
        """Describe a service from its Spur metadata: Spur's text, then its properties."""
        properties = [
            ("Categories", metadata.categories),
            ("Protocols", metadata.protocols),
            ("Platforms", metadata.platforms),
            ("Targeting types", metadata.targeting_types),
            ("Anonymous", metadata.is_anonymous),
            ("No-log policy", metadata.is_no_log),
            ("Callback proxy", metadata.is_callback_proxy),
            ("Enterprise", metadata.is_enterprise),
            ("Inactive", metadata.is_inactive),
            ("Tracked by Spur", metadata.is_tracked),
            ("White-label versions", metadata.allows_white_label),
            ("Local network access", metadata.allows_local_network_access),
            ("Crypto payment", metadata.allows_crypto),
            ("Free access", metadata.allows_free_access),
            ("Torrents", metadata.allows_torrents),
            ("Observation max age (days)", metadata.max_age_days),
            ("Resold by", metadata.resold_by),
            (
                "Resells",
                [
                    (
                        f"{resell.tag} ({', '.join(resell.products)})"
                        if resell.products
                        else resell.tag
                    )
                    for resell in metadata.resells
                    if resell.tag
                ],
            ),
        ]
        lines = []
        for title, value in properties:
            if value is None or value == []:
                continue
            if isinstance(value, list):
                value = ", ".join(value)
            elif isinstance(value, bool):
                value = "yes" if value else "no"
            lines.append(f"- **{title}**: {value}")
        return "\n\n".join(
            part for part in (metadata.description, "\n".join(lines)) if part
        )

    def _build_metrics_note(
        self, metadata: TagMetadata, infrastructure: Infrastructure
    ) -> list[Any]:
        """Build a note with the metrics of a service, attached to its infrastructure.

        The note has no creation date: the same metrics give the same note, and
        new metrics give a new one. Decimals are rounded so that tiny variations
        do not create a new note.
        """
        metrics = metadata.metrics
        known_keys = [key for key in TAG_METRICS if key in metrics]
        other_keys = sorted(key for key in metrics if key not in TAG_METRICS)
        lines = [
            f"- **{TAG_METRICS.get(key, key)}**: "
            f"{round(metrics[key], 4) if isinstance(metrics[key], float) else metrics[key]}"
            for key in [*known_keys, *other_keys]
            if metrics[key] is not None
        ]
        if not lines:
            return []
        return [
            Note(
                abstract=f"Spur metrics for {infrastructure.name}",
                content="\n".join(lines),
                objects=[infrastructure],
                author=self.author,
                markings=[self.tlp_marking],
            )
        ]

    def _build_tunnel_nodes(
        self,
        infrastructure: Infrastructure,
        tunnels: list[Tunnel],
        enriched_ip: IPvAnyAddress,
    ) -> list[Any]:
        """Build the entry and exit nodes that a tunnel infrastructure `consists-of`.

        The relationship description tells the role of the node. The enriched IP
        itself is skipped (already linked), and at most `MAX_TUNNEL_NODES` nodes
        are linked per enrichment.
        """
        roles_by_node: dict[str, list[str]] = {}
        for tunnel in tunnels:
            for role, values in (("entry", tunnel.entries), ("exit", tunnel.exits)):
                for value in values:
                    roles = roles_by_node.setdefault(value, [])
                    if role not in roles:
                        roles.append(role)

        objects: list[Any] = []
        linked_nodes = 0
        for value, roles in roles_by_node.items():
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                self.logger.warning(
                    "Skipping an invalid tunnel node IP",
                    meta={"infrastructure": infrastructure.name, "value": value},
                )
                continue
            if address == enriched_ip:
                continue
            if linked_nodes == MAX_TUNNEL_NODES:
                self.logger.info(
                    "Tunnel node limit reached, skipping the remaining nodes",
                    meta={
                        "infrastructure": infrastructure.name,
                        "limit": MAX_TUNNEL_NODES,
                        "nodes": len(roles_by_node),
                    },
                )
                break
            node_class = IPV6Address if address.version == 6 else IPV4Address
            node = node_class(
                value=str(address), author=self.author, markings=[self.tlp_marking]
            )
            objects.append(node)
            objects.append(
                self._relationship(
                    RelationshipType.CONSISTS_OF,
                    infrastructure,
                    node,
                    description=f"{' and '.join(roles).capitalize()} node",
                )
            )
            linked_nodes += 1
        return objects

    def _build_note(
        self, ip_context: IPContext, ip: IPV4Address | IPV6Address
    ) -> list[Any]:
        """Build a note with the context that has no better place in OpenCTI.

        The note has no creation date, so that the same content gives the same
        note on every enrichment.
        """
        lines = []
        if ip_context.organization:
            lines.append(f"- **Organization**: {ip_context.organization}")
        if client := ip_context.client:
            for title, value in (
                ("Client count", client.count),
                ("Client countries", client.countries),
                ("Client spread", client.spread),
            ):
                if value is not None:
                    lines.append(f"- **{title}**: {value}")
            if concentration := client.concentration:
                place = ", ".join(
                    _unique(
                        [concentration.city, concentration.state, concentration.country]
                    )
                )
                for title, value in (
                    ("Client concentration", place),
                    ("Concentration density", concentration.density),
                    ("Concentration skew (km)", concentration.skew),
                    ("Concentration geohash", concentration.geohash),
                ):
                    if value not in (None, ""):
                        lines.append(f"- **{title}**: {value}")
        if not lines:
            return []
        return [
            Note(
                abstract=f"Spur IP context for {ip.value}",
                content="\n".join(lines),
                objects=[ip],
                author=self.author,
                markings=[self.tlp_marking],
            )
        ]
