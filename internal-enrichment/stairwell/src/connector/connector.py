from __future__ import annotations

import json
from typing import Any

from connector.enricher import Dispatcher, stix_marking_tlps
from connector.settings import ConnectorSettings
from connector.stairwell import StairwellClient
from pycti import OpenCTIConnectorHelper


def _is_union_list(key: str) -> bool:
    return key in ("labels", "external_references") or key.endswith("_refs")


def _merge_object(incoming: dict[str, Any], ours: dict[str, Any]) -> dict[str, Any]:
    """`ours` applied on top of `incoming`, keeping what `ours` leaves out.

    Enrichers send partial objects, so a field they omit keeps its incoming
    value. Dicts present in both (hashes) merge key by key, and labels,
    external references, and `*_refs` lists (markings) are unioned in order,
    and the higher `x_opencti_score` is kept; for any other field the
    enricher's value wins.
    """
    merged = dict(incoming)
    for key, value in ours.items():
        previous = merged.get(key)
        if key == "x_opencti_score" and previous is None:
            # OpenCTI may hold the incoming score in its STIX extension.
            previous = OpenCTIConnectorHelper.get_attribute_in_extension(
                "score", incoming
            )
        if key == "x_opencti_score" and isinstance(previous, int):
            # Scores only ever go up (see stairwell.score.monotonic_score).
            merged[key] = max(previous, value) if isinstance(value, int) else previous
        elif isinstance(previous, dict) and isinstance(value, dict):
            merged[key] = {**previous, **value}
        elif (
            _is_union_list(key)
            and isinstance(previous, list)
            and isinstance(value, list)
        ):
            combined = list(previous)
            seen = {json.dumps(v, sort_keys=True) for v in previous}
            for item in value:
                marker = json.dumps(item, sort_keys=True)
                if marker not in seen:
                    seen.add(marker)
                    combined.append(item)
            merged[key] = combined
        else:
            merged[key] = value
    return merged


class _PlaybookBundles:
    """The helper the enrichers send through, with playbook bookkeeping.

    A playbook step must hand on the bundle it received plus whatever it adds.
    While a playbook message is processed, every bundle an enricher sends gets
    the incoming objects merged in (an object in both is merged with
    `_merge_object`), and `sent` records whether anything went out. Every other attribute is the
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
        # Enrichment refreshes existing observables, so it must overwrite
        # their score and description (pycti's default is not to).
        kwargs.setdefault("update", True)
        kwargs.pop("cleanup_inconsistent_bundle", None)
        if self.incoming:
            payload = json.loads(bundle)
            ours = {o.get("id"): o for o in payload.get("objects", [])}
            objects = []
            for obj in self.incoming:
                mine = ours.pop(obj.get("id"), None)
                objects.append(obj if mine is None else _merge_object(obj, mine))
            objects.extend(ours.values())
            payload["objects"] = objects
            bundle = json.dumps(payload)
        result = self._helper.send_stix2_bundle(
            bundle, cleanup_inconsistent_bundle=True, **kwargs
        )
        self.sent = True
        return result

    def send_incoming(self) -> None:
        """Hand the incoming playbook bundle on unchanged."""
        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle(self.incoming or []),
            cleanup_inconsistent_bundle=True,
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
            max_tlp=config.connector.max_tlp.value,
        )

    def _in_scope(self, observable: dict[str, Any]) -> bool:
        """Supported by an enricher and listed in the configured CONNECTOR_SCOPE."""
        scope = {t.strip().lower() for t in self.config.connector.scope}
        entity_type = (observable.get("entity_type") or "").lower()
        return entity_type in scope and self.dispatcher.supports(observable)

    def process_message(self, data: dict[str, Any]) -> str:
        playbook = not data.get("event_type")
        self.bundles.begin(data["stix_objects"] if playbook else None)

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

        # In a playbook the step's input may carry markings the stored entity
        # does not (an earlier step can raise its TLP); both are gated.
        input_tlps = (
            stix_marking_tlps(
                stix_entity,
                data["stix_objects"],
                lookup=lambda ref: self.helper.api.marking_definition.read(id=ref),
            )
            if playbook
            else []
        )
        try:
            message = self.dispatcher.dispatch(observable, extra_tlps=input_tlps)
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
