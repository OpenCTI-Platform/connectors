"""IPGeolocation.io internal enrichment connector."""

import ipaddress

from connector.converter_to_stix import ConverterToStix
from connector.risk_scorer import RiskScorer
from connector.settings import ConnectorSettings
from ipgeolocation_client import IPGeolocationClient
from pycti import OpenCTIConnectorHelper


class ObservableTLPTooHighError(ValueError):
    """The observable's TLP is above `max_tlp_level`: it must not leave OpenCTI."""


class IPGeolocationConnector:
    """Enrich IPv4 and IPv6 observables with IPGeolocation.io.

    Each observable is looked up with one API request. The connector sends back the
    observable with a score, labels and an external reference, together with its country,
    city, autonomous system, organizations, hostname, an indicator for risky addresses
    and a note holding the full enrichment report.

    The original bundle (`stix_objects`) is always part of what is sent, and a playbook
    gets it back unchanged when the entity is skipped or the enrichment fails, so
    playbooks never stall.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        settings = config.ipgeolocation
        include = tuple(
            module
            for module, enabled in (
                ("security", settings.include_security),
                ("abuse", settings.include_abuse),
                ("hostname", settings.include_hostname),
            )
            if enabled
        )
        self.client = IPGeolocationClient(
            api_key=settings.api_key.get_secret_value(),
            base_url=str(settings.api_base_url),
            timeout=settings.timeout,
            include=include,
        )
        self.converter = ConverterToStix(tlp_level=settings.tlp_level)
        self.scorer = RiskScorer()

    def _entity_in_scope(self, data: dict) -> bool:
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        return data["entity_id"].split("--")[0].lower() in scopes

    def _check_tlp(self, opencti_entity: dict) -> None:
        """Refuse an observable whose TLP is above `max_tlp_level`."""
        max_tlp = "TLP:" + self.config.ipgeolocation.max_tlp_level.upper()
        for marking in opencti_entity.get("objectMarking") or []:
            if marking.get("definition_type") != "TLP":
                continue
            if not self.helper.check_max_tlp(marking["definition"], max_tlp):
                raise ObservableTLPTooHighError(
                    f"Observable is {marking['definition']}, above the maximum "
                    f"{max_tlp}: not sent to IPGeolocation.io"
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
                "Observable TLP is above the maximum: not sent to IPGeolocation.io",
                {"entity_id": data["entity_id"]},
            )
            if from_playbook:
                self._send_bundle(stix_objects)
            return str(err)

        ip = stix_entity["value"]
        if not ipaddress.ip_address(ip).is_global:
            self.helper.connector_logger.info(
                "Private or reserved address: not sent to IPGeolocation.io",
                {"value": ip},
            )
            if from_playbook:
                self._send_bundle(stix_objects)
            return "Private or reserved address: skipped"

        self.helper.connector_logger.info(
            "Enriching observable", {"type": stix_entity["type"], "value": ip}
        )
        intel = self.client.lookup(ip)
        risk = self.scorer.assess(intel) if intel.has_security else None

        settings = self.config.ipgeolocation
        new_objects = self.converter.build(
            intel,
            risk,
            stix_entity,
            create_labels=settings.create_labels,
            create_relationships=settings.create_relationships,
            create_indicator=settings.create_indicator,
            indicator_threshold=settings.indicator_threshold,
            create_note=settings.create_note,
        )
        bundles = self._send_bundle(stix_objects + new_objects)
        self.helper.connector_logger.info(
            "Observable enriched",
            {
                "value": ip,
                "objects": len(new_objects),
                "risk": risk.risk_level if risk else None,
            },
        )
        return f"Sent {bundles} bundle(s) with {len(new_objects)} new objects for {ip}"

    def run(self) -> None:
        """Listen for enrichment requests."""
        self.helper.listen(message_callback=self.process_message)
