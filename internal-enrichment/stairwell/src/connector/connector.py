from __future__ import annotations

import json
from typing import Any

from connector.enricher import Dispatcher
from connector.settings import ConnectorSettings
from connector.stairwell import StairwellClient
from pycti import OpenCTIConnectorHelper


class _PlaybookBundles:
    """The helper the enrichers send through, with playbook bookkeeping.

    A playbook step must hand on the bundle it received plus whatever it adds.
    While a playbook message is processed, every bundle an enricher sends gets
    the incoming objects merged in (the enricher's version of an object wins),
    and `sent` records whether anything went out. Every other attribute is the
    real helper's.
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        self._helper = helper
        self.incoming: list[dict[str, Any]] | None = None
        self.sent = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._helper, name)

    def begin(self, incoming: list[dict[str, Any]] | None) -> None:
        self.incoming = incoming
        self.sent = False

    def send_stix2_bundle(self, bundle: str, **kwargs: Any) -> Any:
        if self.incoming:
            payload = json.loads(bundle)
            ids = {o.get("id") for o in payload.get("objects", [])}
            payload["objects"].extend(
                o for o in self.incoming if o.get("id") not in ids
            )
            bundle = json.dumps(payload)
        result = self._helper.send_stix2_bundle(bundle, **kwargs)
        self.sent = True
        return result

    def send_incoming(self) -> None:
        """Hand the incoming playbook bundle on unchanged."""
        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle(self.incoming or [])
        )
        self.sent = True


class StairwellConnector:
    """Internal-enrichment connector: enriches observables with Stairwell intel.

    Triggered by OpenCTI (manual enrichment or, when `CONNECTOR_AUTO=true`,
    on newly-created in-scope observables). Playbook-compatible: in a playbook
    the bundle sent back always carries the objects the step received, with
    the enrichment added when there is one, so the playbook continues on an
    out-of-scope entity, a refused TLP, no Stairwell data, or an error.
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper
        self.bundles = _PlaybookBundles(helper)

        s = config.stairwell
        self.client = StairwellClient(
            api_token=s.api_token.get_secret_value(),
            base_url=str(s.api_base_url),
            organization_id=s.organization_id or None,
            user_id=s.user_id or None,
        )
        self.dispatcher = Dispatcher(
            self.bundles,
            self.client,
            s.default_tlp,
            variant_limit=s.variant_limit,
            resolutions_limit=s.resolutions_limit,
            sightings_limit=s.sightings_limit,
            opencti_base_url=str(config.opencti.url).rstrip("/"),
            max_tlp=s.max_tlp_level,
        )

    def _in_scope(self, observable: dict[str, Any]) -> bool:
        """Supported by an enricher and listed in the configured CONNECTOR_SCOPE."""
        scope = {t.strip().lower() for t in self.config.connector.scope}
        entity_type = (observable.get("entity_type") or "").lower()
        return entity_type in scope and self.dispatcher.supports(observable)

    def process_message(self, data: dict[str, Any]) -> str:
        playbook = not data.get("event_type")
        self.bundles.begin(data.get("stix_objects") or [] if playbook else None)

        stix_entity = data.get("stix_entity") or {}
        entity_id = stix_entity.get("id") or data.get("entity_id")
        # pycti resolves the entity before calling back (and fails the message
        # if it cannot). The max-TLP gate in Dispatcher.dispatch checks every
        # TLP marking on it before any enricher calls Stairwell.
        observable = data.get("enrichment_entity")
        if not entity_id or not observable:
            if playbook:
                self.bundles.send_incoming()
            return "No resolvable entity in enrichment message"

        if not self._in_scope(observable):
            if playbook:
                self.bundles.send_incoming()
                return "Entity type not in scope; playbook bundle returned unchanged"
            raise ValueError(
                f"Failed to process observable, {observable.get('entity_type')} "
                "is not a supported entity type."
            )

        try:
            message = self.dispatcher.dispatch(observable)
        except Exception as err:  # noqa: BLE001
            self.helper.connector_logger.error(
                "[CONNECTOR] Stairwell enrichment failed",
                {"entity_id": entity_id, "error": str(err)},
            )
            if not playbook:
                raise
            if not self.bundles.sent:
                self.bundles.send_incoming()
            return f"Stairwell enrichment failed: {err}"

        if playbook and not self.bundles.sent:
            self.bundles.send_incoming()
        return message

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
