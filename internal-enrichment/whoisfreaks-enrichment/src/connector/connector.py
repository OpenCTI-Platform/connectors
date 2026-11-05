"""WhoisFreaks internal enrichment connector."""

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from whoisfreaks_client import WhoisFreaksClient


class ObservableTLPTooHighError(ValueError):
    """The observable's TLP is above `max_tlp`: it must not leave OpenCTI."""


class WhoisFreaksConnector:
    """Enrich Domain-Name observables with WhoisFreaks WHOIS data.

    Each observable is looked up with one API request. The connector sends back the
    observable with labels and an external reference, together with its registrar,
    name servers, registrant organization and contact e-mail addresses, and a note
    holding the full WHOIS report.

    The original bundle (`stix_objects`) is always part of what is sent, and a playbook
    gets it back unchanged when the entity is skipped or the enrichment fails, so
    playbooks never stall.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        settings = config.whoisfreaks
        self.client = WhoisFreaksClient(
            api_key=settings.api_key.get_secret_value(),
            base_url=str(settings.api_base_url),
            timeout=settings.timeout,
        )
        self.converter = ConverterToStix(tlp_level=settings.tlp_level)

    def _entity_in_scope(self, data: dict) -> bool:
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        return data["entity_id"].split("--")[0].lower() in scopes

    def _check_tlp(self, opencti_entity: dict) -> None:
        """Refuse an observable whose TLP is above `max_tlp`."""
        max_tlp = f"TLP:{self.config.connector.max_tlp.upper()}"
        for marking in opencti_entity.get("objectMarking") or []:
            if marking.get("definition_type") != "TLP":
                continue
            if not self.helper.check_max_tlp(marking["definition"], max_tlp):
                raise ObservableTLPTooHighError(
                    f"Observable is {marking['definition']}, above the maximum "
                    f"{max_tlp}: not sent to WhoisFreaks"
                )

    def _send_bundle(self, stix_objects: list) -> int:
        bundle = self.helper.stix2_create_bundle(stix_objects)
        return len(
            self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
        )

    def process_message(self, data: dict) -> str:
        """Enrich the entity of an OpenCTI enrichment request or playbook step."""
        stix_objects = data["stix_objects"]
        from_playbook = not data.get("event_type")
        try:
            return self._enrich(data, stix_objects, from_playbook)
        except Exception:
            if from_playbook:
                self._send_bundle(stix_objects)
            raise

    def _enrich(self, data: dict, stix_objects: list, from_playbook: bool) -> str:
        stix_entity = data["stix_entity"]

        if not self._entity_in_scope(data):
            if from_playbook:
                self._send_bundle(stix_objects)
                return "Entity type not in scope: original bundle sent back"
            return "Entity type not in scope: nothing to do"

        try:
            self._check_tlp(data["enrichment_entity"])
        except ObservableTLPTooHighError as err:
            # An expected case, not a failure: report it and end the work normally.
            self.helper.connector_logger.warning(
                "Observable TLP is above the maximum: not sent to WhoisFreaks",
                {"entity_id": data["entity_id"]},
            )
            if from_playbook:
                self._send_bundle(stix_objects)
            return str(err)

        domain = stix_entity["value"]
        self.helper.connector_logger.info(
            "Enriching observable", {"type": stix_entity["type"], "value": domain}
        )
        record = self.client.lookup(domain)

        settings = self.config.whoisfreaks
        new_objects = self.converter.build(
            record,
            stix_entity,
            create_labels=settings.create_labels,
            create_relationships=settings.create_relationships,
            create_note=settings.create_note,
        )
        # In the JSON-delivered enrichment message, `stix_entity` is a separate
        # object from its copy in `stix_objects`; replace that copy so the labels
        # and external reference added to it survive (a no-op when they are already
        # the same object, as in a playbook step).
        bundle_objects = [
            stix_entity if obj.get("id") == stix_entity["id"] else obj
            for obj in stix_objects
        ]
        bundles = self._send_bundle(bundle_objects + new_objects)
        self.helper.connector_logger.info(
            "Observable enriched",
            {
                "value": domain,
                "objects": len(new_objects),
                "registered": record.is_registered,
            },
        )
        return (
            f"Sent {bundles} bundle(s) with {len(new_objects)} new objects for {domain}"
        )

    def run(self) -> None:
        """Listen for enrichment requests."""
        self.helper.listen(message_callback=self.process_message)
