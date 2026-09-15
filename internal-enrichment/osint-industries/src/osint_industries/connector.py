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


class OsintIndustriesConnector:
    SCOPES = ["Email-Addr", "Phone-Number", "User-Account", "Cryptocurrency-Wallet"]

    def __init__(self, config: ConnectorSettings | None = None):
        self.config = config or ConnectorSettings()
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())

        api_key = self.config.osint_industries.api_key.get_secret_value()
        base_url = str(self.config.osint_industries.base_url)
        tlp_level = self.config.osint_industries.tlp_level
        # Premium mode: queries additional modules; consumes more API credits.
        self.premium = self.config.osint_industries.premium

        self.tlp = TLPMarking(level=tlp_level)
        self.client = OsintIndustriesClient(self.helper, api_key, base_url)
        author = ConverterToStix.make_author()
        self.converter = ConverterToStix(author=author, tlp=self.tlp)

    def _extract_value(self, observable: dict) -> str | None:
        otype = observable.get("entity_type")
        if otype in ("Email-Addr", "Url", "Cryptocurrency-Wallet", "Phone-Number"):
            return observable.get("observable_value") or observable.get("value")
        if otype == "User-Account":
            return observable.get("account_login") or observable.get("observable_value")
        return observable.get("observable_value")

    def _process_message(self, data: dict) -> str:
        observable = data["enrichment_entity"]
        entity_type = observable.get("entity_type")

        selector_type = self.client.selector_type_for(entity_type)
        if selector_type is None:
            return "Unsupported type: %s" % entity_type

        value = self._extract_value(observable)
        if not value:
            return "No usable value on the observable."

        self.helper.connector_logger.info(
            "OSINT Industries enrichment",
            meta={"type": selector_type, "value": value},
        )

        payload = self.client.query(selector_type, value, premium=self.premium)
        if payload is None:
            return "OSINT Industries request failed (see logs)."
        if payload in ([], {}):
            return "No OSINT Industries result for this selector."

        stix_objects = self.converter.process(observable, payload)
        if not stix_objects:
            return "No STIX object generated."

        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle, update=True)
        return "Bundle sent: %d objects." % len(stix_objects)

    def _process_callback(self, data: dict) -> str:
        try:
            return self._process_message(data)
        except Exception:
            self.helper.connector_logger.error(
                "Error during enrichment",
                meta={"trace": traceback.format_exc()},
            )
            return "Internal error (see logs)."

    def run(self) -> None:
        self.helper.connector_logger.info("Starting the OSINT Industries connector.")
        self.helper.listen(message_callback=self._process_callback)
