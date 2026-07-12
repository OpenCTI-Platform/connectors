# -*- coding: utf-8 -*-
"""OpenCTI internal-enrichment connector for XposedOrNot.

Enriches Email-Addr observables with data-breach exposure. Works without any
API key via the free community API; an optional key switches to the Plus API.

Privacy note: the observable's email address (personal information) is sent
over TLS to xposedornot.com. Gate what may leave the platform with
XPOSEDORNOT_MAX_TLP, and use the results only within lawful, authorised
investigations.
"""

from __future__ import annotations

import os
import re
import traceback
from copy import deepcopy

import stix2
import yaml
from connectors_sdk.models import TLPMarking
from pycti import OpenCTIConnectorHelper, get_config_variable

from .client_api import XposedOrNotClient
from .converter_to_stix import ConverterToStix

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(value: str) -> bool:
    return bool(value) and len(value) <= 254 and bool(EMAIL_RE.match(value))


def observable_tlp(observable: dict) -> str | None:
    """Extract the TLP marking definition of the observable, if any."""
    for marking in observable.get("objectMarking") or []:
        if str(marking.get("definition_type", "")).upper() == "TLP":
            return marking.get("definition")
    return None


class XposedOrNotConnector:
    SCOPES = ["Email-Addr"]

    def __init__(self):
        config = self._load_config()
        self.helper = OpenCTIConnectorHelper(config)

        api_key = get_config_variable(
            "XPOSEDORNOT_API_KEY", ["xposedornot", "api_key"], config
        )
        base_url = get_config_variable(
            "XPOSEDORNOT_BASE_URL", ["xposedornot", "base_url"], config
        )
        self.max_tlp = (
            get_config_variable(
                "XPOSEDORNOT_MAX_TLP", ["xposedornot", "max_tlp"], config
            )
            or "TLP:AMBER"
        )
        tlp_level = (
            get_config_variable(
                "XPOSEDORNOT_TLP_LEVEL", ["xposedornot", "tlp_level"], config
            )
            or "amber"
        )

        self.tlp = TLPMarking(level=tlp_level)
        self.client = XposedOrNotClient(self.helper, api_key, base_url)
        self.converter = ConverterToStix(
            author=ConverterToStix.make_author(), tlp=self.tlp
        )

    @staticmethod
    def _load_config() -> dict:
        config_file = os.path.join(os.path.dirname(__file__), "..", "..", "config.yml")
        if os.path.isfile(config_file):
            with open(config_file, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
        return {}

    def _process_message(self, data: dict) -> str:
        observable = data["enrichment_entity"]
        entity_type = observable.get("entity_type")
        if entity_type not in self.SCOPES:
            return "Unsupported type: %s" % entity_type

        tlp = observable_tlp(observable)
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            return (
                "TLP of the observable (%s) is higher than what the connector is"
                " allowed to enrich (%s); skipping." % (tlp or "none", self.max_tlp)
            )

        email = (
            str(observable.get("observable_value") or observable.get("value") or "")
            .strip()
            .lower()
        )
        if not is_valid_email(email):
            return "The observable value is not a valid email address."

        result = self.client.lookup(email)
        if result is None:
            return "XposedOrNot request failed (see logs)."
        if not result:
            return "No known breach exposure for this email address (XposedOrNot)."

        breaches = result.get("breaches") or []

        # Update the source observable in place: score, labels, external reference.
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        enriched_entity = deepcopy(stix_entity)
        if result.get("risk_score") is not None:
            enriched_entity["x_opencti_score"] = result["risk_score"]
        labels = enriched_entity.get("labels") or []
        for label in ["data-breach"] + (
            ["plaintext-password-exposure"]
            if self.converter.has_plaintext_exposure(breaches)
            else []
        ):
            if label not in labels:
                labels.append(label)
        enriched_entity["labels"] = labels
        external_references = enriched_entity.get("external_references") or []
        if not any(
            ref.get("source_name") == "XposedOrNot" for ref in external_references
        ):
            external_references.append(
                stix2.ExternalReference(
                    source_name="XposedOrNot",
                    url="https://xposedornot.com",
                    description="XposedOrNot breach exposure check",
                )
            )
        enriched_entity["external_references"] = external_references
        enriched_objects = [
            enriched_entity if obj["id"] == enriched_entity["id"] else obj
            for obj in stix_objects
        ]

        # Per-breach detail as a markdown Note attached to the observable.
        note = self.converter.build_note(enriched_entity["id"], result)
        enriched_objects += [
            self.converter.author.to_stix2_object(),
            self.tlp.to_stix2_object(),
            note.to_stix2_object(),
        ]

        bundle = self.helper.stix2_create_bundle(enriched_objects)
        self.helper.send_stix2_bundle(bundle, update=True)

        first_year, latest_year = self.converter.years(breaches)
        span = (
            " (first %s, latest %s)" % (first_year, latest_year)
            if first_year and latest_year
            else ""
        )
        return (
            "Found %d breach(es)%s; observable updated and summary note attached."
            % (
                len(breaches),
                span,
            )
        )

    def _process_callback(self, data: dict) -> str:
        try:
            return self._process_message(data)
        except Exception:
            self.helper.connector_logger.error(
                "Error during enrichment", meta={"trace": traceback.format_exc()}
            )
            return "Internal error (see logs)."

    def run(self) -> None:
        self.helper.connector_logger.info("Starting the XposedOrNot connector.")
        self.helper.listen(message_callback=self._process_callback)
