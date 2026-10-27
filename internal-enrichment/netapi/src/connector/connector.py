"""NetAPI internal-enrichment connector.

Checks domain names, hostnames and URLs (by their host) against the NetAPI
compromised feed, the hosts that public threat feeds report for
malware or phishing, and adds the position of a listed domain in the NetAPI
Top 1M. The lookups are free and need no account; CONNECTOR_MAX_TLP gates
what may leave the platform.
"""

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

import idna
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connectors_sdk.models import Reference, TLPMarking
from netapi_client import NetAPIClient
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import OpenCTIConnectorHelper

TLP_LEVELS = (
    "TLP:CLEAR",
    "TLP:WHITE",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
)
TLP_IDS = {
    PyctiMarkingDefinition.generate_id("TLP", level): level for level in TLP_LEVELS
}


# a URL scheme without an authority (mailto:, urn:, data: ...); "host:8080/path" is not one
HOSTLESS_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:(?![0-9]|//)")


class EnrichmentSkipped(Exception):
    """The observable is handed back untouched; the message says why."""


class NetAPIConnector:
    """Enrich an observable in place with its NetAPI feed listing.

    A listed observable gets the label `netapi-compromised` (while listed now),
    an external reference, optionally a score, and one note with the details:
    first and last seen, the reporting feed, the registrar and the Top 1M rank.
    A value that was never listed is left as it is.

    The original bundle (`stix_objects`) is always part of what is sent, and a
    playbook gets it back unchanged when the entity is skipped or the enrichment
    fails, so playbooks never stall.
    """

    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        client: NetAPIClient | None = None,
    ) -> None:
        self.config = config
        self.helper = helper
        settings = config.netapi
        self.client = client or NetAPIClient(
            base_url=str(settings.api_base_url),
            api_token=(
                settings.api_token.get_secret_value() if settings.api_token else None
            ),
            timeout=settings.timeout,
        )
        self.converter = ConverterToStix(author=ConverterToStix.make_author())

    def _send_bundle(self, stix_objects: list[dict[str, Any]], update: bool = False):
        bundle = self.helper.stix2_create_bundle(list(stix_objects))
        return self.helper.send_stix2_bundle(
            bundle, update=update, cleanup_inconsistent_bundle=True
        )

    def _entity_in_scope(self, data: dict[str, Any]) -> bool:
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        return data["entity_id"].split("--")[0].lower() in scopes

    @staticmethod
    def source_markings(data: dict[str, Any]) -> tuple[list[str], list[str]]:
        """The TLP values and the marking ids of the observable.

        Both representations are read: the resolved `objectMarking` of the
        OpenCTI entity and the `object_marking_refs` of the STIX entity, whose
        definitions are looked up among the well-known TLP ids and the marking
        definitions bundled with it. A marking that cannot be read is refused
        rather than treated as no marking.
        """
        stix_entity = data["stix_entity"]
        bundled = {
            obj.get("id"): obj
            for obj in data.get("stix_objects") or []
            if isinstance(obj, dict) and obj.get("type") == "marking-definition"
        }
        tlps: list[str] = []
        refs: list[str] = []
        for marking in data["enrichment_entity"].get("objectMarking") or []:
            kind = marking.get("definition_type")
            definition = marking.get("definition")
            if not kind or not definition:
                raise EnrichmentSkipped(
                    "A marking of the observable cannot be read: not sent to NetAPI"
                )
            if str(kind).upper() == "TLP":
                tlps.append(definition)
            refs.append(
                marking.get("standard_id")
                or PyctiMarkingDefinition.generate_id(kind, definition)
            )
        for ref in stix_entity.get("object_marking_refs") or []:
            if ref in TLP_IDS:
                tlps.append(TLP_IDS[ref])
            elif ref in bundled:
                definition = bundled[ref]
                kind = definition.get("x_opencti_definition_type") or definition.get(
                    "definition_type"
                )
                if str(kind).upper() == "TLP":
                    tlps.append(
                        definition.get("x_opencti_definition") or definition.get("name")
                    )
            elif ref not in refs:
                raise EnrichmentSkipped(
                    f"Marking {ref} of the observable cannot be resolved: "
                    "not sent to NetAPI"
                )
            refs.append(ref)
        return tlps, list(dict.fromkeys(refs))

    def _check_tlp(self, tlps: list[str]) -> None:
        """Refuse an observable whose TLP is above CONNECTOR_MAX_TLP."""
        max_tlp = f"TLP:{self.config.connector.max_tlp.upper()}"
        for tlp in tlps:
            if not isinstance(tlp, str) or not self.helper.check_max_tlp(tlp, max_tlp):
                raise EnrichmentSkipped(
                    f"Observable is {tlp}, above the maximum "
                    f"{max_tlp}: not sent to NetAPI"
                )

    @staticmethod
    def lookup_value(stix_entity: dict[str, Any]) -> str:
        """The host to look up: a URL is checked by its host, names in punycode."""
        value = str(stix_entity.get("value") or "").strip()
        stix_type = str(stix_entity.get("type") or "")
        if stix_type == "url":
            if "://" in value or value.startswith("//"):
                parsed = urlparse(value)
            elif HOSTLESS_SCHEME.match(value):
                # mailto:, urn:, data: ... carry no host to look up
                raise EnrichmentSkipped("The URL has no host to look up")
            else:
                parsed = urlparse("//" + value)
            host = parsed.hostname or ""
        else:
            host = value.lower()
        host = host.strip().rstrip(".")
        if not host:
            raise EnrichmentSkipped("The observable has no host to look up")

        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise EnrichmentSkipped("IP address: the NetAPI feed holds domains only")

        try:
            # a Unicode name goes through IDNA2008 with UTS 46 mapping, so that it and
            # its A-label look up the same entry (the built-in IDNA 2003 codec maps
            # "ß" to "ss"); an ASCII name keeps the built-in label checks
            if host.isascii():
                host = host.encode("idna").decode("ascii")
            else:
                host = idna.encode(host, uts46=True).decode("ascii")
        except (idna.IDNAError, UnicodeError) as err:
            raise EnrichmentSkipped(
                "The observable value is not a valid host name"
            ) from err
        if "." not in host or len(host) > 253:
            raise EnrichmentSkipped("The observable value is not a valid host name")
        return host

    def _forward(self, data: dict[str, Any], message: str) -> str:
        """Inside a playbook, hand the bundle back untouched; return the status."""
        if not data.get("event_type"):
            self._send_bundle(data["stix_objects"])
        return message

    def _enrich(self, data: dict[str, Any]) -> str:
        if not self._entity_in_scope(data):
            raise EnrichmentSkipped("Entity type not in scope")

        tlps, marking_refs = self.source_markings(data)
        self._check_tlp(tlps)
        stix_entity = data["stix_entity"]
        value = self.lookup_value(stix_entity)

        self.helper.connector_logger.info(
            "Checking the observable against the NetAPI feed",
            {"type": stix_entity.get("type"), "value": value},
        )
        check = self.client.compromised_check(value)
        if not check.get("listed_ever"):
            return self._forward(
                data, "Not in the NetAPI compromised feed, now or in the past"
            )

        rank = None
        if check.get("type") == "domain" and self.config.netapi.include_rank:
            rank = self.client.domain_rank(value)

        settings = self.config.netapi
        score = (
            settings.score
            if settings.update_score and check.get("listed_now")
            else None
        )
        enriched = self.converter.enrich_observable(stix_entity, check, score)

        tlp = TLPMarking(level=settings.tlp_level)
        note_markings = [tlp] + [
            Reference(id=ref) for ref in marking_refs if ref != tlp.id
        ]
        note = self.converter.build_note(
            stix_entity["id"],
            value,
            check,
            rank,
            markings=note_markings,
            observed_at=data["enrichment_entity"].get("created_at"),
        )
        objects = [
            enriched if obj.get("id") == enriched["id"] else obj
            for obj in data["stix_objects"]
        ]
        if enriched not in objects:
            objects.append(enriched)
        objects += [
            self.converter.author.to_stix2_object(),
            tlp.to_stix2_object(),
            note.to_stix2_object(),
        ]
        self._send_bundle(objects, update=True)

        status = self.converter.status_line(check)
        self.helper.connector_logger.info(
            "Observable enriched", {"value": value, "status": status}
        )
        return f"NetAPI: {status}; observable updated and note attached"

    def process_message(self, data: dict[str, Any]) -> str:
        """Enrich the entity of an OpenCTI enrichment request or playbook step."""
        try:
            return self._enrich(data)
        except EnrichmentSkipped as skipped:
            self.helper.connector_logger.warning(
                "Observable skipped",
                {"entity_id": data.get("entity_id"), "reason": str(skipped)},
            )
            return self._forward(data, str(skipped))
        except Exception as err:
            self.helper.connector_logger.error(
                "Enrichment failed",
                {"entity_id": data.get("entity_id"), "error": str(err)},
            )
            if not data.get("event_type"):
                self._send_bundle(data["stix_objects"])
            raise

    def run(self) -> None:
        """Listen for enrichment requests."""
        self.helper.listen(message_callback=self.process_message)
