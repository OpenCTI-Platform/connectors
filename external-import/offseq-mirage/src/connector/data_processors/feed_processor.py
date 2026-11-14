"""Fetch the Mirage Feed bundle and import its indicators, with the ATT&CK
techniques and CVEs they point to, under the OffSeq author and the configured
TLP marking."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Generator

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    AttackPattern,
    BaseIdentifiedObject,
    ExternalReference,
    Indicator,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    Vulnerability,
)
from mirage_client import MirageFeedClient
from mirage_client.models import (
    MirageAttackPattern,
    MirageIndicator,
    MirageRelationship,
    MirageVulnerability,
)

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState

OBSERVABLE_TYPES = {
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "url": "Url",
    "domain-name": "Domain-Name",
    "file": "StixFile",
}


class MirageFeedProcessor(BaseDataProcessor):
    settings: ConnectorSettings
    state: ConnectorState

    work_name = "OffSeq Mirage Feed import"

    def post_init(self) -> None:
        cfg = self.settings.offseq_mirage
        self.client = MirageFeedClient(str(cfg.feed_url))
        self.author = OrganizationAuthor(
            name="OffSeq",
            description="Operator of the Mirage honeypot network. The Mirage Feed lists "
            "addresses seen by at least 3 sensors in 2 networks within 7 days, "
            "excluding research scanners and VPN/Tor exits.",
            contact_information="abuse@offseq.com",
        )
        self.tlp_marking = TLPMarking(level=cfg.tlp_level)

    def collect(self) -> dict[str, Any]:
        self.logger.info(
            "Fetching Mirage Feed bundle",
            meta={"url": str(self.settings.offseq_mirage.feed_url)},
        )
        return self.client.get_bundle()

    def transform(
        self, bundle: dict[str, Any]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        bundle_id = bundle.get("id")
        if bundle_id and bundle_id == self.state.last_bundle_id:
            self.logger.info(
                "Feed unchanged since last run", meta={"bundle": bundle_id}
            )
            return

        by_type: dict[str, list[dict]] = defaultdict(list)
        for obj in bundle.get("objects", []):
            by_type[obj.get("type")].append(obj)

        targets: dict[str, BaseIdentifiedObject] = {}
        links: dict[str, list[MirageRelationship]] = defaultdict(list)
        if self.settings.offseq_mirage.import_relationships:
            targets = self._targets(by_type)
            for raw in by_type["relationship"]:
                rel = MirageRelationship.model_validate(raw)
                if rel.target_ref in targets:
                    links[rel.source_ref].append(rel)

        batch_size = self.settings.offseq_mirage.batch_size
        raw_indicators = by_type["indicator"]
        imported = skipped = 0
        for start in range(0, len(raw_indicators), batch_size):
            objects: list[BaseIdentifiedObject] = [self.author, self.tlp_marking]
            used: dict[str, BaseIdentifiedObject] = {}
            for raw in raw_indicators[start : start + batch_size]:
                try:
                    source = MirageIndicator.model_validate(raw)
                    indicator = self._indicator(source)
                except ValueError as err:
                    self.logger.warning(
                        "Skipping indicator",
                        meta={"id": raw.get("id"), "error": str(err)},
                    )
                    skipped += 1
                    continue
                objects.append(indicator)
                imported += 1
                for rel in links.get(source.id, []):
                    target = targets[rel.target_ref]
                    used[rel.target_ref] = target
                    objects.append(
                        Relationship(
                            type=rel.relationship_type,
                            source=indicator,
                            target=target,
                            author=self.author,
                            markings=[self.tlp_marking],
                        )
                    )
            objects[2:2] = used.values()
            yield objects

        self.state.last_bundle_id = bundle_id
        self.logger.info(
            "Mirage Feed imported",
            meta={"bundle": bundle_id, "indicators": imported, "skipped": skipped},
        )

    def _indicator(self, source: MirageIndicator) -> Indicator:
        prefix = source.pattern.removeprefix("[").split(":", 1)[0]
        observable_type = OBSERVABLE_TYPES.get(prefix)
        if observable_type is None:
            raise ValueError(f"unsupported pattern {source.pattern[:40]!r}")
        return Indicator(
            name=source.name,
            description=source.description,
            pattern=source.pattern,
            pattern_type=source.pattern_type,
            main_observable_type=observable_type,
            indicator_types=source.indicator_types or None,
            labels=source.labels or None,
            score=source.confidence,
            created=source.created,
            valid_from=source.valid_from,
            valid_until=source.valid_until,
            author=self.author,
            markings=[self.tlp_marking],
            create_observables=self.settings.offseq_mirage.create_observables,
        )

    def _targets(
        self, by_type: dict[str, list[dict]]
    ) -> dict[str, BaseIdentifiedObject]:
        targets: dict[str, BaseIdentifiedObject] = {}
        for raw in by_type["attack-pattern"]:
            ap = MirageAttackPattern.model_validate(raw)
            mitre = next(
                (r for r in ap.external_references if r.source_name == "mitre-attack"),
                None,
            )
            targets[ap.id] = AttackPattern(
                name=ap.name,
                mitre_id=mitre.external_id if mitre else None,
                external_references=(
                    [
                        ExternalReference(
                            source_name="mitre-attack",
                            external_id=mitre.external_id,
                            url=mitre.url,
                        )
                    ]
                    if mitre
                    else None
                ),
                author=self.author,
                markings=[self.tlp_marking],
            )
        for raw in by_type["vulnerability"]:
            vuln = MirageVulnerability.model_validate(raw)
            targets[vuln.id] = Vulnerability(
                name=vuln.name,
                is_cisa_kev="cisa-kev" in vuln.labels or None,
                author=self.author,
                markings=[self.tlp_marking],
            )
        return targets
