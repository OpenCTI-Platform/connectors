"""NetAPI internal-enrichment connector.

Checks domain names, hostnames, URLs (by their host) and IPv4 addresses against
the NetAPI compromised feed, the hosts that public threat feeds report for
malware or phishing, and adds the position of a listed domain in the NetAPI
Top 1M. The lookups are free and need no account; CONNECTOR_MAX_TLP gates
what may leave the platform.
"""

import ipaddress
from typing import Any
from urllib.parse import urlparse

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connectors_sdk.models import Reference, TLPMarking
from netapi_client import NetAPIClient
from pycti import OpenCTIConnectorHelper


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

    def _check_tlp(self, opencti_entity: dict[str, Any]) -> None:
        """Refuse an observable whose TLP is above CONNECTOR_MAX_TLP."""
        max_tlp = f"TLP:{self.config.connector.max_tlp.upper()}"
        for marking in opencti_entity.get("objectMarking") or []:
            if marking.get("definition_type") != "TLP":
                continue
            if not self.helper.check_max_tlp(marking["definition"], max_tlp):
                raise EnrichmentSkipped(
                    f"Observable is {marking['definition']}, above the maximum "
                    f"{max_tlp}: not sent to NetAPI"
                )

    @staticmethod
    def lookup_value(stix_entity: dict[str, Any]) -> str:
        """The host to look up: a URL is checked by its host, names in punycode."""
        value = str(stix_entity.get("value") or "").strip()
        stix_type = str(stix_entity.get("type") or "")
        if stix_type == "url":
            parsed = urlparse(value if "://" in value else "//" + value)
            host = parsed.hostname or ""
        else:
            host = value.lower()
        host = host.strip().rstrip(".")
        if not host:
            raise EnrichmentSkipped("The observable has no host to look up")

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None:
            if address.version != 4:
                raise EnrichmentSkipped("IPv6 address: the NetAPI feed holds IPv4 only")
            if not address.is_global:
                raise EnrichmentSkipped("Private or reserved address: not looked up")
            return str(address)

        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as err:
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

        self._check_tlp(data["enrichment_entity"])
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
            Reference(id=ref)
            for ref in stix_entity.get("object_marking_refs") or []
            if ref != tlp.id
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
