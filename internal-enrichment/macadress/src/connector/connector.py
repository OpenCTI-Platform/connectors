"""macadress.com internal-enrichment connector.

Enriches a ``Mac-Addr`` observable with the IEEE-registered vendor, an inferred
device category, virtualization / special-use classification and MAC
randomization confidence, from the macadress.com API (the same lookup behind the
JSON API, the MCP server and the website).
"""

import stix2
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.utils import MacadressUtils
from macadress_client import MacadressAPIError, MacadressClient
from pycti import (
    STIX_EXT_OCTI_SCO,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
)


class MacadressConnector:
    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper

        macadress = config.macadress
        self.api_base_url = str(macadress.api_base_url)
        self.max_tlp = macadress.max_tlp
        self.default_score = int(macadress.default_score)
        self.create_note = bool(macadress.create_note)
        self.create_vendor_identity = bool(macadress.create_vendor_identity)

        self.client = MacadressClient(
            helper=helper,
            base_url=self.api_base_url,
            api_key=macadress.api_key.get_secret_value(),
        )
        self.author = ConverterToStix.make_author()
        self.converter = ConverterToStix(self.author, self.default_score)

    def _extract_and_check_markings(self, entity: dict) -> None:
        tlp = "TLP:CLEAR"
        for marking_definition in entity.get("objectMarking", []):
            if marking_definition.get("definition_type") == "TLP":
                tlp = marking_definition.get("definition", tlp)

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            self.helper.connector_logger.warning(
                "[MACADRESS] Skipping enrichment: observable TLP exceeds MAX TLP",
                {"observable_tlp": tlp, "max_tlp": self.max_tlp},
            )
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

    def _send_bundle(self, stix_objects: list) -> str:
        # OpenCTI upserts by STIX id on import, so a re-enrichment of the same
        # MAC updates the existing objects instead of duplicating them.
        stix_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_bundle)
        return f"Sending {len(bundles_sent)} STIX bundle(s) for worker import"

    def _is_entity_in_scope(self, entity_type: str) -> bool:
        scopes = [scope.lower() for scope in self.config.connector.scope]
        return entity_type.lower() in scopes

    def process_message(self, data: dict) -> str:
        opencti_entity = data["enrichment_entity"]
        self._extract_and_check_markings(opencti_entity)

        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        observable_value = stix_entity.get("value")
        observable_markings = stix_entity.get("object_marking_refs", [])

        self.helper.connector_logger.info(
            "[MACADRESS] Received enrichment request",
            {
                "entity_type": opencti_entity.get("entity_type"),
                "stix_type": stix_entity.get("type"),
                "value": observable_value,
            },
        )

        if not self._is_entity_in_scope(opencti_entity["entity_type"]):
            if data.get("event_type"):
                raise ValueError(
                    "Failed to process observable, "
                    f"{opencti_entity['entity_type']} is not a supported entity type"
                )
            return self._send_bundle(stix_objects)

        if stix_entity.get("type") != "mac-addr":
            if data.get("event_type"):
                raise ValueError(
                    "Unsupported entity type for macadress.com connector: "
                    f"{stix_entity.get('type')}"
                )
            return self._send_bundle(stix_objects)

        if not isinstance(observable_value, str) or not observable_value.strip():
            self.helper.connector_logger.warning(
                "[MACADRESS] Observable has no value; skipping enrichment",
                {"id": stix_entity.get("id")},
            )
            return self._send_bundle(stix_objects)

        mac = observable_value.strip()
        try:
            result = self.client.lookup(mac)
        except MacadressAPIError as err:
            if err.status_code == 400:
                self.helper.connector_logger.warning(
                    "[MACADRESS] Value is not a valid MAC address; skipping",
                    {"value": mac},
                )
                return self._send_bundle(stix_objects)
            self.helper.connector_logger.error(
                "[MACADRESS] macadress.com lookup failed",
                {"value": mac, "error": str(err)},
            )
            raise

        if not isinstance(result, dict) or not result.get("valid", False):
            self.helper.connector_logger.info(
                "[MACADRESS] macadress.com could not parse the MAC address",
                {"value": mac},
            )
            return self._send_bundle(stix_objects)

        self.helper.connector_logger.info(
            "[MACADRESS] MAC address analysed",
            {"value": mac, "organization": result.get("organization")},
        )

        stix_objects.append(self.author)
        self._update_observable(stix_entity, result, mac)
        stix_objects.extend(
            self._vendor_objects(stix_entity, result, observable_markings)
        )

        if self.create_note:
            stix_objects.append(
                self._summary_note(stix_entity, result, mac, observable_markings)
            )

        return self._send_bundle(stix_objects)

    def _update_observable(self, stix_entity: dict, result: dict, mac: str) -> None:
        description = MacadressUtils.build_description(result)
        if description:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "x_opencti_description",
                description,
            )
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity, STIX_EXT_OCTI_SCO, "score", self.default_score
        )
        for label in MacadressUtils.build_labels(result):
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "labels", label, True
            )
        for reference in MacadressUtils.build_external_references(result, mac):
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "external_references",
                reference,
                True,
            )

    def _vendor_objects(self, stix_entity: dict, result: dict, markings: list) -> list:
        organization = result.get("organization")
        if not (
            self.create_vendor_identity
            and organization
            and result.get("vendor_lookup_reliable", True)
        ):
            return []

        country = result.get("country")
        vendor = self.converter.vendor_identity(organization, country)
        relationship = self.converter.relationship(
            stix_entity["id"],
            "related-to",
            vendor["id"],
            description=(
                f"MAC address is in a block IEEE registered to {organization}"
                + (f" ({country})" if country else "")
            ),
            object_marking_refs=markings,
        )
        return [vendor, relationship]

    def _summary_note(
        self, stix_entity: dict, result: dict, mac: str, markings: list
    ) -> stix2.Note:
        # Stable per-observable id: re-enriching the same MAC updates this note
        # instead of piling up duplicates. Keyed on the MAC, not the rendered
        # body, so wording changes do not mint a new note.
        return stix2.Note(
            id=Note.generate_id(None, f"macadress.com enrichment of {mac}"),
            abstract=f"macadress.com analysis of {mac}",
            content=MacadressUtils.build_summary(mac, result),
            created_by_ref=self.author["id"],
            object_refs=[stix_entity["id"]],
            object_marking_refs=markings,
            custom_properties={"note_types": ["external"]},
        )

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
