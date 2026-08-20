from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from visionheight_client import VisionHeightClient


class VisionHeightConnector:
    """
    OpenCTI internal-enrichment connector for VisionHeight.

    Enriches IPv4-Addr and Domain-Name observables with VisionHeight threat
    intelligence: risk score, threat labels, ASN, geolocation, CVEs, DNS
    resolutions, SSL certificates, WHOIS, and high-risk Indicators (score >= 75).

    To be compatible with OpenCTI's "playbook automation" feature, this connector
    always sends back a STIX bundle containing the original entity (mutated in
    place by the converter) plus any new enrichment objects.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = VisionHeightClient(
            self.helper,
            base_url=str(self.config.visionheight.api_base_url),
            api_key=self.config.visionheight.api_key.get_secret_value(),
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.visionheight.max_tlp_level,
        )

        # Bundle of STIX objects accumulated for the current enrichment job.
        self.stix_objects_list: list = []

    # ------------------------------------------------------------------ #
    # Intelligence collection
    # ------------------------------------------------------------------ #

    def _collect_intelligence(self, stix_entity: dict) -> list:
        """
        Fetch enrichment data from VisionHeight and convert to STIX 2.1 objects.

        Mutates ``stix_entity`` in place (score, labels, external_references)
        and appends new enrichment objects (Identity, AS, Country, CVEs, certs,
        Notes, Indicator) to ``self.stix_objects_list``. Returns the full list
        to be sent in the bundle.
        """
        obs_value = stix_entity["value"]
        obs_type = stix_entity["type"].lower()

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting enrichment",
            {"value": obs_value, "type": obs_type},
        )

        if obs_type == "ipv4-addr":
            data = self.client.get_ip(obs_value)
            if data is None:
                return self.stix_objects_list
            new_objects = self.converter_to_stix.enrich_ip(stix_entity, data)
        elif obs_type == "domain-name":
            data = self.client.get_domain(obs_value)
            if data is None:
                return self.stix_objects_list
            new_objects = self.converter_to_stix.enrich_domain(stix_entity, data)
        else:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Unsupported entity type",
                {"type": obs_type},
            )
            return f"[CONNECTOR] Unsupported entity type: {obs_type}"

        # Always include the VisionHeight Identity (created_by_ref target).
        if self.converter_to_stix.author is not None:
            self.stix_objects_list.append(self.converter_to_stix.author)

        self.stix_objects_list.extend(new_objects)
        return self.stix_objects_list

    # ------------------------------------------------------------------ #
    # Scope and TLP gating
    # ------------------------------------------------------------------ #

    def entity_in_scope(self, data: dict) -> bool:
        """
        Limit playbook triggers to the configured connector scope.
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["entity_id"].split("--")[0].lower()
        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Verify the observable's TLP marking does not exceed the configured cap.
        Raises ValueError if it does.
        """
        tlp = None
        for marking in opencti_entity.get("objectMarking", []):
            if marking["definition_type"] == "TLP":
                tlp = marking["definition"]

        if not self.helper.check_max_tlp(tlp, self.config.visionheight.max_tlp_level):
            raise ValueError(
                "[CONNECTOR] TLP of the observable exceeds the connector's "
                "max_tlp_level; refusing to enrich."
            )

    # ------------------------------------------------------------------ #
    # Message handling
    # ------------------------------------------------------------------ #

    def process_message(self, data: dict) -> str:
        """
        Entry point invoked by the OpenCTI helper for each enrichment job.
        Sees: https://docs.opencti.io/latest/development/connectors/#additional-implementations
        """
        try:
            # When invoked via a playbook, ``stix_objects`` is the bundle being
            # passed through. Initialize it before the TLP check so the inbound
            # bundle is preserved even if enrichment is refused.
            self.stix_objects_list = data.get("stix_objects") or []
            opencti_entity = data["enrichment_entity"]
            self.extract_and_check_markings(opencti_entity)

            stix_entity = data["stix_entity"]

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing observable",
                {"type": stix_entity["type"], "value": stix_entity["value"]},
            )

            if self.entity_in_scope(data):
                stix_objects = self._collect_intelligence(stix_entity)
                if stix_objects:
                    return self._send_bundle(stix_objects)
                return "[CONNECTOR] No information found"

            # Not in scope. If invoked through a playbook (no event_type),
            # pass the original bundle through unchanged.
            if not data.get("event_type"):
                return self._send_bundle(self.stix_objects_list)

            raise ValueError(
                f"Failed to process observable, "
                f"{opencti_entity['entity_type']} is not a supported entity type."
            )

        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected error",
                {"error_message": str(err)},
            )
            return f"[CONNECTOR] Error: {err}"

    # ------------------------------------------------------------------ #
    # Bundle dispatch and main loop
    # ------------------------------------------------------------------ #

    def _send_bundle(self, stix_objects: list) -> str:
        bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"

    def run(self) -> None:
        """
        Listen on the connector's RabbitMQ queue for enrichment jobs.
        """
        self.helper.listen(message_callback=self.process_message)
