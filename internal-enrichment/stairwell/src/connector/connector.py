from __future__ import annotations

from typing import Any

from connector.enricher import Dispatcher
from connector.settings import ConnectorSettings
from connector.stairwell import StairwellClient
from pycti import OpenCTIConnectorHelper


class StairwellConnector:
    """Internal-enrichment connector: enriches observables with Stairwell intel.

    Triggered by OpenCTI (manual enrichment or, when `CONNECTOR_AUTO=true`,
    on newly-created in-scope observables). Playbook-compatible: an
    enriched entity is sent back as a STIX bundle, and an entity type outside
    the connector's scope gets its playbook bundle back unchanged.
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper

        s = config.stairwell
        self.client = StairwellClient(
            api_token=s.api_token,
            base_url=str(s.api_base_url),
            organization_id=s.organization_id or None,
            user_id=s.user_id or None,
        )
        self.dispatcher = Dispatcher(
            helper,
            self.client,
            s.default_tlp,
            variant_limit=s.variant_limit,
            resolutions_limit=s.resolutions_limit,
            sightings_limit=s.sightings_limit,
            opencti_base_url=str(config.opencti.url).rstrip("/"),
            max_tlp=s.max_tlp_level,
        )

    def process_message(self, data: dict[str, Any]) -> str:
        stix_entity = data.get("stix_entity") or {}
        entity_id = stix_entity.get("id") or data.get("entity_id")
        if not entity_id:
            return "No entity_id in enrichment message"

        # pycti resolves the entity before calling back (and fails the message
        # if it cannot). The max-TLP gate in Dispatcher.dispatch checks every
        # TLP marking on it before any enricher calls Stairwell.
        observable = data.get("enrichment_entity")
        if not observable:
            return f"Observable {entity_id} not found"

        if not self.dispatcher.supports(observable):
            if not data.get("event_type"):
                # A playbook step must hand its bundle on even when this
                # connector has nothing to add, so return it unchanged.
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(data.get("stix_objects") or [])
                )
                return "Entity type not in scope; playbook bundle returned unchanged"
            raise ValueError(
                f"Failed to process observable, {observable.get('entity_type')} "
                "is not a supported entity type."
            )

        try:
            return self.dispatcher.dispatch(observable)
        except Exception as err:  # noqa: BLE001
            self.helper.connector_logger.error(
                "[CONNECTOR] Stairwell enrichment failed",
                {"entity_id": entity_id, "error": str(err)},
            )
            raise

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
