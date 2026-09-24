"""One processor per HoneyLabs collection: fetch its STIX indicators from the
TAXII server since the last checkpoint and hand them to OpenCTI as SDK
objects, with the HoneyLabs author, the configured TLP marking, the
evidence link as an external reference, and the observables behind them."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Generator

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    BaseIdentifiedObject,
    ExternalReference,
    Indicator,
    KillChainPhase,
    OrganizationAuthor,
    TLPMarking,
)

from honeylabs_client import HoneyLabsTaxiiClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState
    from honeylabs_client.models import TaxiiIndicator

# Alias of the collection -> name of its checkpoint field on ConnectorState.
STATE_FIELDS = {
    "attackers": "attackers_added_after",
    "exploiters": "exploiters_added_after",
    "cve-probers": "cve_probers_added_after",
    "malware-infrastructure": "malware_infrastructure_added_after",
}

OBSERVABLE_TYPES = {
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "url": "Url",
    "domain-name": "Domain-Name",
}


class IndicatorConversionError(Exception):
    pass


class IndicatorsProcessor(BaseDataProcessor):
    settings: ConnectorSettings
    state: ConnectorState

    def __init__(self, collection: str) -> None:
        if collection not in STATE_FIELDS:
            raise ValueError(
                f"unknown HoneyLabs collection {collection!r}; one of {sorted(STATE_FIELDS)}"
            )
        self.collection = collection
        self.work_name = f"HoneyLabs {collection} import"

    def post_init(self) -> None:
        cfg = self.settings.honeylabs
        self.client = HoneyLabsTaxiiClient(
            api_root=cfg.api_root,
            api_key=cfg.api_key.get_secret_value(),
            logger=self.logger,
        )
        self.author = OrganizationAuthor(
            name="HoneyLabs",
            description="Threat intelligence from HoneyLabs' own internet-facing honeypot sensors. "
            "Every indicator links to the captured evidence at honeylabs.net.",
        )
        self.tlp_marking = TLPMarking(level=cfg.tlp_level)

    # -- checkpoint -------------------------------------------------------
    def _checkpoint(self) -> datetime | None:
        return getattr(self.state, STATE_FIELDS[self.collection])

    def _set_checkpoint(self, value: datetime) -> None:
        setattr(self.state, STATE_FIELDS[self.collection], value)

    # -- collect / transform ----------------------------------------------
    def collect(self) -> Generator[list[TaxiiIndicator], None, None]:
        since = self._checkpoint() or self.settings.honeylabs.import_since
        self.logger.info(
            "Fetching HoneyLabs collection",
            {"collection": self.collection, "added_after": since.isoformat()},
        )
        yield from self.client.iter_objects(
            self.collection, since, self.settings.honeylabs.page_size
        )

    def transform(
        self, pages: Generator[list[TaxiiIndicator], None, None]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        newest = self._checkpoint()
        total = 0
        for page in pages:
            objects: list[BaseIdentifiedObject] = [self.author, self.tlp_marking]
            for raw in page:
                try:
                    objects.append(self._convert(raw))
                except IndicatorConversionError as exc:
                    self.logger.warning(
                        "Skipping indicator", {"id": raw.id, "error": str(exc)}
                    )
                    continue
                if newest is None or raw.modified > newest:
                    newest = raw.modified
            total += len(objects) - 2
            if newest is not None:
                self._set_checkpoint(newest)
            yield objects
        self.logger.info(
            "HoneyLabs collection imported",
            {"collection": self.collection, "indicators": total},
        )

    # -- conversion -------------------------------------------------------
    def _convert(self, raw: TaxiiIndicator) -> Indicator:
        observable_type = None
        for prefix, octi_type in OBSERVABLE_TYPES.items():
            if raw.pattern.startswith(f"[{prefix}:"):
                observable_type = octi_type
                break
        if observable_type is None:
            raise IndicatorConversionError(f"unsupported pattern {raw.pattern[:40]!r}")
        return Indicator(
            name=raw.name,
            description=raw.description,
            pattern=raw.pattern,
            pattern_type=raw.pattern_type,
            main_observable_type=observable_type,
            indicator_types=raw.indicator_types or None,
            valid_from=raw.valid_from,
            valid_until=raw.valid_until,
            score=raw.confidence,
            labels=raw.labels or None,
            kill_chain_phases=[
                KillChainPhase(chain_name=k.kill_chain_name, phase_name=k.phase_name)
                for k in raw.kill_chain_phases
            ]
            or None,
            external_references=[
                ExternalReference(
                    source_name=r.source_name, url=r.url, description=r.description
                )
                for r in raw.external_references
                if r.url
            ]
            or None,
            created=raw.created,
            author=self.author,
            markings=[self.tlp_marking],
            create_observables=self.settings.honeylabs.create_observables,
        )
