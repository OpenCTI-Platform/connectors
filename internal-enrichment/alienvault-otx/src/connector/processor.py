from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from connector.observable_note import ObservableNote
from connector.settings import ConnectorSettings
from connector.summary_note import NOTE_TITLE, render_summary
from connectors_sdk import BaseEnrichmentProcessor, EnrichmentMessage
from connectors_sdk.models import (
    URL,
    DomainName,
    ExternalReference,
    IPV4Address,
    OrganizationAuthor,
    TLPMarking,
)
from otx_client import OTX_HOSTNAME_SECTION, OTX_SECTIONS, OtxClient, OtxGeneral

OTX_INDICATOR_PAGE_URL = "https://otx.alienvault.com/indicator/{path}/{value}"


@dataclass(frozen=True)
class _ObservableType:
    """How an observable type is looked up in OTX and rebuilt.

    Attributes:
        section: OTX API section (`IPv4`, `domain` or `url`).
        page_path: Path of the indicator page on the OTX website (`ip`, `domain` or `url`).
        model: The connectors-sdk model of the observable.
        fallback: OTX API section and website page path queried when `section` knows
            no pulse of the indicator, `None` when there is none.
    """

    section: str
    page_path: str
    model: type[IPV4Address] | type[DomainName] | type[URL]
    fallback: tuple[str, str] | None = None


# Keyed by the lowercase entity type: the SDK matches entity types case-insensitively,
# and OpenCTI sends `IPv4-Addr` where STIX says `ipv4-addr`
OBSERVABLE_TYPES = {
    "ipv4-addr": _ObservableType(OTX_SECTIONS["IPv4-Addr"], "ip", IPV4Address),
    # OTX files subdomains under `hostname`: `domain` answers 200 with no pulse for them
    "domain-name": _ObservableType(
        OTX_SECTIONS["Domain-Name"],
        "domain",
        DomainName,
        fallback=(OTX_HOSTNAME_SECTION, "hostname"),
    ),
    "url": _ObservableType(OTX_SECTIONS["Url"], "url", URL),
}


@dataclass(frozen=True)
class OtxLookup:
    """The answer of OTX to the lookup of an entity.

    Attributes:
        section: OTX API section that answered (`IPv4`, `domain`, `hostname` or `url`).
        page_path: Path of the indicator page on the OTX website of the section that
            answered (`ip`, `domain`, `hostname` or `url`).
        general: The `general` section that answered.
    """

    section: str
    page_path: str
    general: OtxGeneral


class AlienVaultOtxProcessor(BaseEnrichmentProcessor[ConnectorSettings]):
    """Enrich IPv4 addresses, domain names and URLs with AlienVault OTX.

    One call to the OTX `general` endpoint tells whether OTX knows the indicator: it
    does when at least one pulse contains it. A known indicator is rebuilt with an
    external reference to its OTX page, and a summary note is attached to it. The
    country sightings are added by the next sub-issue of epic #8537.
    """

    handled_entity_types = frozenset({"IPv4-Addr", "Domain-Name", "Url"})

    def post_init(self) -> None:
        """Build the API client, the author and the marking once."""
        otx_config = self.settings.alienvault_otx
        self.client = OtxClient(str(otx_config.api_base_url), otx_config.api_key)
        # Same name and class as the AlienVault external-import connector: same id
        self.author = OrganizationAuthor(name="AlienVault")
        self.tlp_marking = TLPMarking(level="clear")

    @staticmethod
    def _observable_type(message: EnrichmentMessage) -> _ObservableType:
        return OBSERVABLE_TYPES[message.enrichment_entity.entity_type.lower()]

    def collect(self, message: EnrichmentMessage) -> OtxLookup | None:
        """Fetch the OTX `general` section of the entity.

        A domain name that its `domain` section does not know (no pulse) is looked up
        again in the `hostname` section. No second call is made when the first one
        returned nothing (HTTP 400 or 404).

        Returns:
            The `general` section, with the OTX section and the page it belongs to,
            `None` when OTX has no such indicator or rejects its value. `OtxClient`
            raises `DataRetrievalError` on any other failure, the fallback call
            included.
        """
        observable_type = self._observable_type(message)
        self.logger.debug(
            "Fetching the OTX general section",
            meta={**message.to_log_metadata(), "section": observable_type.section},
        )
        value = message.stix_entity.value
        general = self.client.get_general(observable_type.section, value)
        if general is None:
            return None
        lookup = OtxLookup(observable_type.section, observable_type.page_path, general)
        if general.pulse_info.is_known or observable_type.fallback is None:
            return lookup
        fallback_section, fallback_page_path = observable_type.fallback
        self.logger.debug(
            "Domain unknown to OTX, looking it up as a hostname",
            meta={**message.to_log_metadata(), "section": fallback_section},
        )
        fallback_general = self.client.get_general(fallback_section, value)
        if fallback_general is None:
            return lookup
        return OtxLookup(fallback_section, fallback_page_path, fallback_general)

    def transform(
        self, data: OtxLookup | None, message: EnrichmentMessage
    ) -> list[Any]:
        """Convert the OTX data into connectors-sdk models.

        An indicator is known to OTX when at least one pulse contains it: otherwise
        nothing is sent. The note is built from the `general` section already fetched:
        no network call is made here.

        Returns:
            The author, the marking, the observable rebuilt with an OTX external
            reference and the summary note attached to it, or `[]` when OTX does not
            know the indicator.
        """
        if data is None or not data.general.pulse_info.is_known:
            return []
        observable_type = self._observable_type(message)
        value = message.stix_entity.value
        # The value is kept as is, so that the model has the id of the entity received:
        # it replaces it in the bundle and OpenCTI merges it with the entity it holds.
        # No author and no marking are set, to leave those of the entity untouched.
        observable = observable_type.model(
            value=value,
            external_references=[
                ExternalReference(
                    source_name="AlienVault OTX",
                    url=OTX_INDICATOR_PAGE_URL.format(
                        path=data.page_path, value=quote(value, safe="")
                    ),
                )
            ],
        )
        # `created` is never set: the id of the note is built from its abstract, its
        # content and the id of the observable, so the same OTX data on the same
        # observable gives the same note, and two observables never share one
        note = ObservableNote(
            abstract=NOTE_TITLE,
            content=render_summary(data.section, data.general),
            objects=[observable],
            author=self.author,
            markings=[self.tlp_marking],
        )
        return [self.author, self.tlp_marking, observable, note]
