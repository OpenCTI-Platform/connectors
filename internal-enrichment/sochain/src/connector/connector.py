"""SoChain internal-enrichment connector.

Enriches a ``Cryptocurrency-Wallet`` observable holding a Bitcoin, Litecoin,
Dogecoin or Zcash (transparent) address with its balance, total received,
transaction counts and first and last activity from the SoChain API, and adds
a note when the address was targeted by address poisoning.
"""

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.utils import SochainUtils, detect_network
from pycti import STIX_EXT_OCTI_SCO, OpenCTIConnectorHelper, OpenCTIStix2
from sochain_client import SochainAPIError, SochainClient

POISONING_LABEL = "address-poisoning"


class SochainConnector:
    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper

        sochain = config.sochain
        self.max_tlp = f"TLP:{config.connector.max_tlp.upper()}"
        self.check_poisoning = bool(sochain.check_poisoning)

        api_key = sochain.api_key.get_secret_value() if sochain.api_key else None
        self.client = SochainClient(
            helper=helper,
            base_url=str(sochain.api_base_url),
            api_key=api_key,
        )
        self.author = ConverterToStix.make_author()
        self.converter = ConverterToStix(self.author)

    def _check_tlp(self, entity: dict) -> None:
        """Raise when any of the observable's TLP markings is above MAX TLP."""
        tlps = [
            marking_definition.get("definition", "TLP:CLEAR")
            for marking_definition in entity.get("objectMarking", [])
            if marking_definition.get("definition_type") == "TLP"
        ] or ["TLP:CLEAR"]
        # Every marking is checked, so their order cannot hide a stricter one.
        if not all(
            OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp) for tlp in tlps
        ):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

    def _send_bundle(self, stix_objects: list) -> str:
        stix_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            stix_bundle, cleanup_inconsistent_bundle=True
        )
        return f"Sending {len(bundles_sent)} STIX bundle(s) for worker import"

    def _skip(self, data: dict, message: str, meta: dict) -> str:
        """Skip the enrichment. A playbook still gets its bundle back, unchanged."""
        self.helper.connector_logger.warning(message, meta)
        if not data.get("event_type"):
            return self._send_bundle(data["stix_objects"])
        return message

    def _is_entity_in_scope(self, data: dict) -> bool:
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data.get("entity_id", "").split("--")[0].lower()
        return entity_type in scopes

    @staticmethod
    def _observable_in_bundle(stix_objects: list, stix_entity: dict) -> dict:
        """Return the observable dict as it lives in the outgoing bundle."""
        for candidate in stix_objects:
            if candidate.get("id") == stix_entity.get("id"):
                return candidate
        stix_objects.append(stix_entity)
        return stix_entity

    def process_message(self, data: dict) -> str:
        opencti_entity = data["enrichment_entity"]
        stix_objects = data["stix_objects"]
        stix_entity = self._observable_in_bundle(stix_objects, data["stix_entity"])
        address = str(stix_entity.get("value") or "").strip()

        if not self._is_entity_in_scope(data):
            return self._skip(
                data,
                "[SOCHAIN] Entity type is not in the connector scope; skipping",
                {"entity_id": data.get("entity_id")},
            )

        try:
            self._check_tlp(opencti_entity)
        except ValueError:
            if data.get("event_type"):
                raise
            # A playbook gets its bundle back, unchanged.
            return self._skip(
                data,
                "[SOCHAIN] Observable TLP is above MAX TLP; skipping",
                {"max_tlp": self.max_tlp},
            )

        network = detect_network(address)
        if network is None:
            return self._skip(
                data,
                "[SOCHAIN] Not a Bitcoin, Litecoin, Dogecoin or Zcash address; skipping",
                {"value": address},
            )

        try:
            summary = self.client.address_summary(network, address)
        except SochainAPIError as err:
            if err.status_code in (400, 404):
                return self._skip(
                    data,
                    "[SOCHAIN] SoChain does not know this address; skipping",
                    {"network": network, "value": address, "error": err.message},
                )
            if not data.get("event_type"):
                return self._skip(
                    data,
                    "[SOCHAIN] Address lookup failed; bundle returned unchanged",
                    {"network": network, "value": address, "error": err.message},
                )
            raise

        findings = []
        if self.check_poisoning:
            try:
                poisoning = self.client.address_poisoning(network, address)
                findings = SochainUtils.poisoning_findings(poisoning)
            except SochainAPIError as err:
                # The summary is still worth sending without this check.
                self.helper.connector_logger.warning(
                    "[SOCHAIN] Address poisoning check failed; continuing without it",
                    {"network": network, "value": address, "error": err.message},
                )

        self.helper.connector_logger.info(
            "[SOCHAIN] Address enriched",
            {
                "network": network,
                "value": address,
                "txs_total": summary.get("txs_total"),
                "poisoning_findings": len(findings),
            },
        )

        stix_objects.append(self.author)
        self._update_observable(stix_entity, network, address, summary, findings)

        if findings:
            stix_objects.append(
                self.converter.poisoning_note(
                    network=network,
                    address=address,
                    content=SochainUtils.build_poisoning_note(
                        network, address, findings
                    ),
                    count=len(findings),
                    observable_id=stix_entity["id"],
                    markings=stix_entity.get("object_marking_refs", []),
                )
            )

        return self._send_bundle(stix_objects)

    def _update_observable(
        self,
        stix_entity: dict,
        network: str,
        address: str,
        summary: dict,
        findings: list,
    ) -> None:
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity,
            STIX_EXT_OCTI_SCO,
            "description",
            SochainUtils.build_description(network, summary),
        )
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity,
            STIX_EXT_OCTI_SCO,
            "external_references",
            SochainUtils.build_external_reference(network, address),
            True,
        )
        if findings:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "labels", POISONING_LABEL, True
            )

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
