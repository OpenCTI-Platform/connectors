# -*- coding: utf-8 -*-
"""OpenCTI enrichment connector for OSINT Industries.

Operational note: to be used only for lawful, authorised investigations
(GDPR legal basis / legal request / proper investigative framework).
"""

from __future__ import annotations

import traceback

from connectors_sdk.models import TLPMarking
from pycti import OpenCTIConnectorHelper

from .client_api import OsintIndustriesClient
from .converter_to_stix import ConverterToStix
from .settings import ConnectorSettings


class MaxTlpExceededError(Exception):
    """Raised when an observable's TLP is above the configured maximum."""


class OsintIndustriesConnector:
    SCOPES = ["Email-Addr", "Phone-Number", "User-Account", "Cryptocurrency-Wallet"]

    def __init__(self, config: ConnectorSettings | None = None):
        self.config = config or ConnectorSettings()
        self.helper = OpenCTIConnectorHelper(
            config=self.config.to_helper_config(),
            playbook_compatible=True,
        )

        api_key = self.config.osint_industries.api_key.get_secret_value()
        base_url = str(self.config.osint_industries.base_url)
        tlp_level = self.config.osint_industries.tlp_level
        # Premium mode: queries additional modules; consumes more API credits.
        self.premium = self.config.osint_industries.premium

        self.tlp = TLPMarking(level=tlp_level)
        self.client = OsintIndustriesClient(self.helper, api_key, base_url)
        author = ConverterToStix.make_author()
        self.converter = ConverterToStix(author=author, tlp=self.tlp)

    def _check_tlp_allowed(self, observable: dict) -> None:
        """Reject observables the connector is not allowed to enrich.

        Every TLP marking carried by the observable must be within the
        configured maximum: an entity marked both TLP:GREEN and TLP:RED is
        treated as TLP:RED. Unmarked observables are allowed, which is what
        `check_max_tlp` does for a `None` TLP.

        :raises MaxTlpExceededError: when the observable's value must never
            be sent to the OSINT Industries API.
        """
        max_tlp = self.config.osint_industries.max_tlp
        refused = [
            marking.get("definition")
            for marking in observable.get("objectMarking") or []
            if marking.get("definition_type") == "TLP"
            and not OpenCTIConnectorHelper.check_max_tlp(
                marking.get("definition"), max_tlp
            )
        ]
        if refused:
            raise MaxTlpExceededError(
                "Observable marked %s exceeds the configured maximum TLP %s."
                % (refused, max_tlp)
            )

    def _extract_value(self, observable: dict) -> str | None:
        otype = observable.get("entity_type")
        if otype in ("Email-Addr", "Url", "Cryptocurrency-Wallet", "Phone-Number"):
            return observable.get("observable_value") or observable.get("value")
        if otype == "User-Account":
            return observable.get("account_login") or observable.get("observable_value")
        return observable.get("observable_value")

    def _send_bundle(self, stix_objects: list) -> None:
        """Serialize and send a bundle to the platform."""
        # `stix2_create_bundle` mutates the list it receives, so hand it a copy
        # and never the caller's `data["stix_objects"]`.
        bundle = self.helper.stix2_create_bundle(list(stix_objects))
        self.helper.send_stix2_bundle(
            bundle,
            update=True,
            cleanup_inconsistent_bundle=True,
        )

    @staticmethod
    def _is_playbook_context(data: dict) -> bool:
        """Return True when the connector was triggered by a playbook.

        The platform omits `event_type` for playbook triggers; a manual or
        automatic enrichment request always carries one.
        """
        return not bool(data.get("event_type"))

    @staticmethod
    def _former_bundle(data: dict) -> list:
        """Return the original bundle the platform sent with the trigger.

        Reading it is what makes every "no enrichment" path able to hand the
        untouched bundle back to the playbook.
        """
        return data["stix_objects"] if "stix_objects" in data else []

    def _forward_original_bundle(self, data: dict, message: str) -> str:
        """Return the incoming bundle untouched so the playbook can continue.

        Any path that produces no enrichment — TLP above the maximum,
        unsupported entity, empty API result, error — must still hand the
        original bundle back, otherwise the playbook stops at this step.
        Outside a playbook run there is nothing to forward.
        """
        original_stix_objects = self._former_bundle(data)
        if self._is_playbook_context(data) and original_stix_objects:
            self._send_bundle(original_stix_objects)
        return message

    def _process_message(self, data: dict) -> str:
        observable = data["enrichment_entity"]
        entity_type = observable.get("entity_type")

        # Gate before anything else: a selector above the configured max TLP
        # must never leave the platform towards a third-party paid API.
        self._check_tlp_allowed(observable)

        selector_type = self.client.selector_type_for(entity_type)
        if selector_type is None:
            return self._forward_original_bundle(
                data, "Unsupported type: %s" % entity_type
            )

        value = self._extract_value(observable)
        if not value:
            return self._forward_original_bundle(
                data, "No usable value on the observable."
            )

        self.helper.connector_logger.info(
            "OSINT Industries enrichment",
            meta={"type": selector_type, "value": value},
        )

        payload = self.client.query(selector_type, value, premium=self.premium)
        if payload is None:
            return self._forward_original_bundle(
                data, "OSINT Industries request failed (see logs)."
            )
        if payload in ([], {}):
            return self._forward_original_bundle(
                data, "No OSINT Industries result for this selector."
            )

        stix_objects = self.converter.process(observable, payload)
        if not stix_objects:
            return self._forward_original_bundle(data, "No STIX object generated.")

        # Enriched objects are appended to the original bundle so the playbook
        # keeps the entities it already carried.
        self._send_bundle(self._former_bundle(data) + stix_objects)
        return "Bundle sent: %d objects." % len(stix_objects)

    def _safe_forward_original_bundle(self, data: dict, message: str) -> str:
        """Forward the original bundle, never letting the forward itself fail."""
        try:
            return self._forward_original_bundle(data, message)
        except Exception:
            # Forwarding is best effort: it must not mask the original
            # outcome nor break the listener loop.
            self.helper.connector_logger.error(
                "Could not forward the original bundle",
                meta={"trace": traceback.format_exc()},
            )
            return message

    def _process_callback(self, data: dict) -> str:
        try:
            return self._process_message(data)
        except MaxTlpExceededError as err:
            self.helper.connector_logger.warning(
                "Skipping enrichment: observable TLP exceeds the configured max TLP",
                meta={"reason": str(err)},
            )
            return self._safe_forward_original_bundle(
                data, "Observable TLP is greater than OSINT_INDUSTRIES_MAX_TLP."
            )
        except Exception:
            self.helper.connector_logger.error(
                "Error during enrichment",
                meta={"trace": traceback.format_exc()},
            )
            return self._safe_forward_original_bundle(
                data, "Internal error (see logs)."
            )

    def run(self) -> None:
        self.helper.connector_logger.info("Starting the OSINT Industries connector.")
        self.helper.listen(message_callback=self._process_callback)
