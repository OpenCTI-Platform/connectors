from __future__ import annotations

from typing import Any

from pycti import OpenCTIConnectorHelper

from connector.enricher import Dispatcher
from connector.settings import ConnectorSettings
from connector.stairwell import StairwellClient


class StairwellConnector:
    """Internal-enrichment connector: enriches observables with Stairwell intel.

    Triggered by OpenCTI (manual enrichment or, when `CONNECTOR_AUTO=true`,
    on newly-created in-scope observables). Playbook-compatible: every call
    returns after sending a STIX bundle back to OpenCTI.
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper

        s = config.stairwell
        self.max_tlp = s.max_tlp_level
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
        )

    def _check_max_tlp(self, data: dict[str, Any]) -> None:
        """Refuse to enrich an observable whose TLP exceeds `max_tlp_level`."""
        entity = data.get("enrichment_entity") or {}
        tlp = "TLP:CLEAR"
        for marking in entity.get("objectMarking") or []:
            if marking.get("definition_type") == "TLP":
                tlp = marking.get("definition")
        if not self.helper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "[CONNECTOR] Observable TLP is greater than the connector's "
                "max TLP; skipping enrichment."
            )

    def process_message(self, data: dict[str, Any]) -> str:
        stix_entity = data.get("stix_entity") or {}
        entity_id = stix_entity.get("id") or data.get("entity_id")
        if not entity_id:
            return "No entity_id in enrichment message"

        self._check_max_tlp(data)

        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if not observable:
            return f"Observable {entity_id} not found"

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
