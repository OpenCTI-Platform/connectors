import random
import time

import stix2
from connector.settings import ConnectorSettings
from pycti import Indicator, Malware, OpenCTIConnectorHelper, StixCoreRelationship

ENRICHED_DESCRIPTION = "coucou from enrichment"
ENRICHED_LABEL = "enriched"
LINKED_MALWARE_NAME = "supra coucou"
# Delay before sending the bundle, to observe the work while it is in progress
SEND_BUNDLE_DELAY_SECONDS = 15
# Chance that the enrichment bundle is replaced by one the backend rejects at ingestion
INGESTION_ERROR_PROBABILITY = 0.5
# Invalid STIX pattern: the backend refuses the indicator, so the work gets an ingestion error
BROKEN_INDICATOR_PATTERN = "[ipv4-addr:value = "


class CoucouEnrichmentConnector:
    """
    Minimal internal enrichment connector, meant as a reference.

    When triggered on an IPv4 observable, it sends back the received bundle with the observable
    description set to `coucou from enrichment` and the label `enriched` added, plus the malware
    `supra coucou` and a `communicates-with` relationship from that malware to the observable.
    No external API is called.
    To be compatible with the "playbook automation" feature, it always sends back a STIX bundle
    containing the entity to enrich.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

    def _enrich(self, stix_objects: list, entity_id: str) -> list:
        """
        Set the description and add the label on the entity, in place in the received objects.

        Existing labels can be in `labels`, in the OpenCTI extensions (platform STIX, e.g. playbooks)
        or in `x_opencti_labels` (pycti export). Top-level `labels` and `x_opencti_description`
        take precedence over the other locations at import, so the result is written there.
        """
        for stix_object in stix_objects:
            if stix_object["id"] != entity_id:
                continue
            labels = list(
                stix_object.get("labels")
                or self.helper.get_attribute_in_extension("labels", stix_object)
                or stix_object.get("x_opencti_labels")
                or []
            )
            if ENRICHED_LABEL not in labels:
                labels.append(ENRICHED_LABEL)
            stix_object["labels"] = labels
            stix_object["x_opencti_description"] = ENRICHED_DESCRIPTION
        return stix_objects

    @staticmethod
    def _link_to_malware(entity_id: str) -> list:
        """
        Create the malware and a `communicates-with` relationship from it to the entity.
        Ids are deterministic, so re-runs upsert the same objects instead of creating new ones.
        """
        malware = stix2.Malware(
            id=Malware.generate_id(LINKED_MALWARE_NAME),
            name=LINKED_MALWARE_NAME,
            is_family=True,
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "communicates-with", malware.id, entity_id
            ),
            relationship_type="communicates-with",
            source_ref=malware.id,
            target_ref=entity_id,
        )
        return [malware, relationship]

    @staticmethod
    def _broken_indicator() -> dict:
        """
        Build an indicator with an invalid STIX pattern, rejected by the backend at ingestion.
        It is a plain dict because the stix2 library would refuse the pattern before sending.
        """
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": Indicator.generate_id(BROKEN_INDICATOR_PATTERN),
            "name": "coucou broken indicator",
            "pattern": BROKEN_INDICATOR_PATTERN,
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00.000Z",
        }

    def _maybe_replace_with_ingestion_error(self, stix_objects: list) -> list:
        """
        With a INGESTION_ERROR_PROBABILITY chance, replace the objects to send by the broken indicator only,
        so nothing from the enrichment is ingested and the whole bundle fails.
        """
        if random.random() >= INGESTION_ERROR_PROBABILITY:
            return stix_objects
        self.helper.connector_logger.info(
            "[CONNECTOR] Sending a bundle the backend will reject at ingestion"
        )
        return [self._broken_indicator()]

    def entity_in_scope(self, data: dict) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["entity_id"].split("--")[0].lower()
        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Raise if the TLP of the entity is greater than the configured max TLP.
        :param opencti_entity: Dict of observable from OpenCTI
        """
        tlp = None
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        # `check_max_tlp` expects `TLP:`-prefixed upper case values, e.g. `TLP:AMBER+STRICT`
        max_tlp = "TLP:" + self.config.coucou_enrichment.max_tlp_level.upper()
        if not self.helper.check_max_tlp(tlp, max_tlp):
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

    def process_message(self, data: dict) -> str:
        """
        Enrich the entity received from OpenCTI.
        The structure of `data` is described in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            opencti_entity = data["enrichment_entity"]
            self.extract_and_check_markings(opencti_entity)

            stix_objects = data["stix_objects"]
            if self.entity_in_scope(data):
                entity_id = data["stix_entity"]["id"]
                return self._send_bundle(
                    self._maybe_replace_with_ingestion_error(
                        self._enrich(stix_objects, entity_id)
                        + self._link_to_malware(entity_id)
                    )
                )
            if not data.get("event_type"):
                # Not in scope AND bundle passed through playbook: return the original bundle unchanged
                return self._send_bundle(stix_objects)
            raise ValueError(
                f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
            )
        except Exception as err:
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def _send_bundle(self, stix_objects: list) -> str:
        """
        Wait SEND_BUNDLE_DELAY_SECONDS, then send the objects as a STIX bundle for worker import.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Waiting before sending the bundle",
            {"delay_seconds": SEND_BUNDLE_DELAY_SECONDS},
        )
        time.sleep(SEND_BUNDLE_DELAY_SECONDS)
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)
        return f"Sending {len(bundles_sent)} stix bundle(s) for worker import"

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
