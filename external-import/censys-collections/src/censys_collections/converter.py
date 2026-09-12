"""Convert Censys collection hits into connectors-sdk / OpenCTI objects."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

import stix2
from censys_platform import (
    Certificate,
    Collection,
    Host,
    SearchQueryHit,
    Threat,
    Vuln,
    Webproperty,
)
from connectors_sdk.models import (
    BaseObject,
    DomainName,
    ExternalReference,
    IPV4Address,
    IPV6Address,
    Malware,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    ThreatActorGroup,
    Vulnerability,
    X509Certificate,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType, TLPLevel
from pycti import Grouping as PyctiGrouping

_TLP_LEVEL_MAP: dict[str, TLPLevel] = {
    "TLP:CLEAR": TLPLevel.CLEAR,
    "TLP:GREEN": TLPLevel.GREEN,
    "TLP:AMBER": TLPLevel.AMBER,
    "TLP:AMBER+STRICT": TLPLevel.AMBER_STRICT,
    "TLP:RED": TLPLevel.RED,
}

# Censys collection web-UI base URL used for external references.
_COLLECTION_URL_BASE = "https://app.censys.io/collections"

# STIX 2.1 grouping-context-ov value used for every Grouping this connector creates.
_GROUPING_CONTEXT = "suspicious-activity"


class Converter:
    """Transform Censys collection hits into a list of OpenCTI SDK objects."""

    def __init__(
        self,
        tlp_level: str,
        score: int,
        auto_indicator_by_score: bool = False,
        indicator_score_threshold: int = 50,
    ) -> None:
        self.author = OrganizationAuthor(name="Censys Collection")  # type: ignore[call-arg]
        self.marking = TLPMarking(level=_TLP_LEVEL_MAP.get(tlp_level, TLPLevel.AMBER))
        self.score = score
        self.auto_indicator_by_score = auto_indicator_by_score
        self.indicator_score_threshold = indicator_score_threshold
        self._common_props: dict = {
            "author": self.author,
            "markings": [self.marking],
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def bootstrap_objects(self) -> list[BaseObject]:
        """Return the shared author identity and TLP marking used by every object.

        These must be included in at least one bundle per run so OpenCTI
        actually creates the Identity/Marking-definition that other objects'
        ``created_by_ref`` / ``object_marking_refs`` point to.
        """
        return [self.author, self.marking]

    def build_grouping(
        self, collection: Collection, objects: list[Any]
    ) -> stix2.v21.Grouping | None:
        """Build a STIX Grouping bundling every object generated for *collection*.

        This lets an analyst open the Grouping in OpenCTI and see every
        observable/indicator/entity that came from the same Censys collection.
        Returns ``None`` if there are no objects to group.
        """
        object_refs = [obj.id for obj in objects if hasattr(obj, "id")]
        if not object_refs:
            return None

        ext_ref = self._collection_external_reference(collection)
        return stix2.v21.Grouping(
            id=PyctiGrouping.generate_id(
                name=collection.id,
                context=_GROUPING_CONTEXT,
            ),
            name=f"Censys Collection: {collection.name}",
            description=collection.description or None,
            context=_GROUPING_CONTEXT,
            object_refs=object_refs,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
            external_references=[ext_ref.to_stix2_object()],
            allow_custom=True,
        )

    def from_hit(
        self, hit: SearchQueryHit, collection: Collection
    ) -> list[BaseObject]:
        """Return all OpenCTI objects derived from a single collection hit."""
        objects: list[BaseObject] = []
        if hit.host_v1 is not None:
            objects.extend(self._from_host(hit.host_v1.resource, collection))
        if hit.certificate_v1 is not None:
            objects.extend(
                self._from_certificate(hit.certificate_v1.resource, collection)
            )
        if hit.webproperty_v1 is not None:
            objects.extend(
                self._from_webproperty(hit.webproperty_v1.resource, collection)
            )
        return objects

    # ------------------------------------------------------------------
    # Per-asset converters
    # ------------------------------------------------------------------

    def _from_host(
        self, host: Host, collection: Collection
    ) -> Generator[BaseObject, None, None]:
        ip = host.ip
        if not ip:
            return

        ext_ref = self._collection_external_reference(collection)
        score = self._resolve_score(host)
        observable: IPV4Address | IPV6Address
        if ":" in ip:
            observable = IPV6Address(
                value=ip,
                create_indicator=self._should_create_indicator(score),
                score=score,
                external_references=[ext_ref],
                **self._common_props,
            )
        else:
            observable = IPV4Address(
                value=ip,
                create_indicator=self._should_create_indicator(score),
                score=score,
                external_references=[ext_ref],
                **self._common_props,
            )
        yield observable

        # Gather threats and vulnerabilities across all services.
        seen_malware: set[str] = set()
        seen_actors: set[str] = set()
        seen_vulns: set[str] = set()

        for service in (host.services if isinstance(host.services, list) else []):
            yield from self._threats_to_objects(
                observable, service.threats, seen_malware, seen_actors
            )
            yield from self._vulns_to_objects(observable, service.vulns, seen_vulns)

    def _from_certificate(
        self, cert: Certificate, collection: Collection
    ) -> Generator[BaseObject, None, None]:
        hashes: dict[HashAlgorithm, str] = {}
        if cert.fingerprint_sha256:
            hashes[HashAlgorithm.SHA256] = cert.fingerprint_sha256
        if cert.fingerprint_sha1:
            hashes[HashAlgorithm.SHA1] = cert.fingerprint_sha1
        if cert.fingerprint_md5:
            hashes[HashAlgorithm.MD5] = cert.fingerprint_md5

        if not hashes:
            return

        # Extract parsed metadata when available.
        issuer_dn: str | None = None
        subject_dn: str | None = None
        serial_number: str | None = None
        validity_not_before: datetime | None = None
        validity_not_after: datetime | None = None

        if cert.parsed:
            issuer_dn = cert.parsed.issuer_dn
            subject_dn = cert.parsed.subject_dn
            serial_number = cert.parsed.serial_number
            if cert.parsed.validity_period:
                validity_not_before = _parse_rfc3339(
                    cert.parsed.validity_period.not_before
                )
                validity_not_after = _parse_rfc3339(
                    cert.parsed.validity_period.not_after
                )

        ext_ref = self._collection_external_reference(collection)
        observable = X509Certificate(
            hashes=hashes,
            issuer=issuer_dn,
            subject=subject_dn,
            serial_number=serial_number,
            validity_not_before=validity_not_before,
            validity_not_after=validity_not_after,
            create_indicator=self._should_create_indicator(self.score),
            score=self.score,
            external_references=[ext_ref],
            **self._common_props,
        )
        yield observable

    def _from_webproperty(
        self, webproperty: Webproperty, collection: Collection
    ) -> Generator[BaseObject, None, None]:
        hostname = webproperty.hostname
        if not hostname:
            return

        ext_ref = self._collection_external_reference(collection)
        observable = DomainName(
            value=hostname,
            create_indicator=self._should_create_indicator(self.score),
            score=self.score,
            external_references=[ext_ref],
            **self._common_props,
        )
        yield observable

        seen_malware: set[str] = set()
        seen_actors: set[str] = set()
        seen_vulns: set[str] = set()

        yield from self._threats_to_objects(
            observable,
            webproperty.threats,
            seen_malware,
            seen_actors,
        )
        yield from self._vulns_to_objects(observable, webproperty.vulns, seen_vulns)

    # ------------------------------------------------------------------
    # Threat & vulnerability helpers
    # ------------------------------------------------------------------

    def _threats_to_objects(
        self,
        observable: IPV4Address | IPV6Address | DomainName | X509Certificate,
        threats: object,
        seen_malware: set[str],
        seen_actors: set[str],
    ) -> Generator[BaseObject, None, None]:
        if not isinstance(threats, list):
            return
        for threat in threats:
            if not isinstance(threat, Threat):
                continue
            yield from self._malware_objects(observable, threat, seen_malware)
            yield from self._actor_objects(observable, threat, seen_actors)

    def _malware_objects(
        self,
        observable: IPV4Address | IPV6Address | DomainName | X509Certificate,
        threat: Threat,
        seen: set[str],
    ) -> Generator[BaseObject, None, None]:
        if threat.malware is None:
            return
        name = threat.malware.primary_name
        if not name or name in seen:
            return
        seen.add(name)

        aliases = [
            n
            for n in (threat.malware.all_names or [])
            if isinstance(n, str) and n != name
        ]

        malware = Malware(
            name=name,
            is_family=True,
            aliases=aliases or None,
            **self._common_props,
        )
        yield malware
        yield Relationship(
            source=observable,
            target=malware,
            type=RelationshipType.RELATED_TO,
            **self._common_props,
        )

    def _actor_objects(
        self,
        observable: IPV4Address | IPV6Address | DomainName | X509Certificate,
        threat: Threat,
        seen: set[str],
    ) -> Generator[BaseObject, None, None]:
        actors = threat.actors if isinstance(threat.actors, list) else []
        for actor in actors:
            name = actor.primary_name
            if not name or name in seen:
                continue
            seen.add(name)

            aliases = [
                n
                for n in (actor.all_names or [])
                if isinstance(n, str) and n != name
            ]

            actor_obj = ThreatActorGroup(
                name=name,
                aliases=aliases or None,
                **self._common_props,
            )
            yield actor_obj
            yield Relationship(
                source=observable,
                target=actor_obj,
                type=RelationshipType.ATTRIBUTED_TO,
                **self._common_props,
            )

    def _vulns_to_objects(
        self,
        observable: IPV4Address | IPV6Address | DomainName | X509Certificate,
        vulns: object,
        seen: set[str],
    ) -> Generator[BaseObject, None, None]:
        if not isinstance(vulns, list):
            return
        for vuln in vulns:
            if not isinstance(vuln, Vuln):
                continue
            name = vuln.id or vuln.name
            if not name or name in seen:
                continue
            seen.add(name)

            vulnerability = Vulnerability(
                name=name,
                **self._common_props,
            )
            yield vulnerability
            yield Relationship(
                source=observable,
                target=vulnerability,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _resolve_score(self, host: Host) -> int:
        """Return the Censys reputation score for *host*, or the configured fallback.

        Censys reports a host's ``reputation.score`` on a 0-100 scale
        (higher = riskier), matching OpenCTI's own score range. When Censys
        doesn't provide one, fall back to the connector-configured default
        score.
        """
        if host.reputation is not None and host.reputation.score is not None:
            return max(0, min(100, round(host.reputation.score)))
        return self.score

    def _should_create_indicator(self, score: int) -> bool:
        """Return whether an indicator should be auto-created for *score*.

        When ``auto_indicator_by_score`` is disabled (default), an indicator
        is always created, preserving prior behavior. When enabled, an
        indicator is only created if *score* meets or exceeds
        ``indicator_score_threshold``.
        """
        if not self.auto_indicator_by_score:
            return True
        return score >= self.indicator_score_threshold

    @staticmethod
    def _collection_external_reference(collection: Collection) -> ExternalReference:
        return ExternalReference(
            source_name="Censys Collections",
            description=f"Censys collection: {collection.name}",
            url=f"{_COLLECTION_URL_BASE}/{collection.id}",
            external_id=collection.id,
        )


def _parse_rfc3339(value: str | None) -> datetime | None:
    """Parse an RFC-3339 string to a timezone-aware datetime, or return None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None
